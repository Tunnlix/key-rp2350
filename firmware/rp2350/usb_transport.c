#include "usb_transport.h"
#include "tusb.h"
#include "device/dcd.h"
#include "pico/stdlib.h"
#include "hardware/watchdog.h"
#include <string.h>

/* The hardware NAKs OUT while its buffer is occupied. This bounded queue also
 * retains input arriving while a synchronous IN submission services USB. An
 * overflow fails the connection explicitly instead of dropping request bytes. */
#define INPUT_REPORTS 16U
static struct {
    uint8_t reports[INPUT_REPORTS][64];
    size_t first, count;
    bool enabled, mounted, failed, sending, sent, restart;
    volatile bool reset;
} usb;

bool rp2350_usb_init(void) {
    memset(&usb, 0, sizeof(usb));
    usb.enabled = tud_init(0);
    return usb.enabled;
}
void rp2350_usb_close(void) {
    if(usb.enabled) (void)tud_deinit(0);
    memset(&usb, 0, sizeof(usb));
}

void tud_mount_cb(void) { usb.mounted = true; }
void tud_umount_cb(void) { usb.reset = true; usb.mounted = false; }
/* This hook can run in the USB interrupt. Only set a flag; never call the app. */
void tud_event_hook_cb(uint8_t port, uint32_t event, bool in_isr) {
    (void)port; (void)in_isr;
    if(event == DCD_EVENT_BUS_RESET || event == DCD_EVENT_UNPLUGGED) usb.reset = true;
}
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t id,
        hid_report_type_t type, uint8_t *buffer, uint16_t requested) {
    (void)instance; (void)id; (void)type; (void)buffer; (void)requested;
    return 0; /* CTAPHID responses are delivered through interrupt IN. */
}
void tud_hid_set_report_cb(uint8_t instance, uint8_t id,
        hid_report_type_t type, const uint8_t *buffer, uint16_t length) {
    if(instance != 0 || id != 0 || type != HID_REPORT_TYPE_OUTPUT || length != 64) return;
    if(usb.reset || usb.failed) return;
    if(usb.count == INPUT_REPORTS) { usb.failed = true; return; }
    memcpy(usb.reports[(usb.first + usb.count) % INPUT_REPORTS], buffer, 64);
    ++usb.count;
}
void tud_hid_report_complete_cb(uint8_t instance, const uint8_t *report, uint16_t length) {
    (void)report;
    if(instance == 0 && usb.sending && length == 64) usb.sent = true;
}
void tud_hid_report_failed_cb(uint8_t instance, hid_report_type_t type,
        const uint8_t *report, uint16_t length) {
    (void)instance; (void)type; (void)report; (void)length;
    usb.failed = true;
}

bool rp2350_usb_submit(void *context, const uint8_t report[64], uint64_t transfer) {
    (void)context; (void)transfer;
    if(!usb.enabled || usb.failed || usb.reset || !usb.mounted) return false;
    uint32_t started = to_ms_since_boot(get_absolute_time());
    usb.sent = false;
    usb.sending = false;
    for(;;) {
        tud_task_ext(0, false);
        if(usb.failed || usb.reset || !tud_mounted()) return false;
        if(!usb.sending && tud_hid_ready()) {
            usb.sending = tud_hid_report(0, report, 64);
        }
        if(usb.sent) { usb.sending = false; return true; }
        if((uint32_t)(to_ms_since_boot(get_absolute_time()) - started) >= CTAPHID_SEND_TIMEOUT_MS) {
            /* Quiesce hardware before rejecting a borrowed report. There is no
             * later completion referring to a reused coordinator transfer. */
            rp2350_usb_close(); usb.restart = true; usb.reset = true;
            return false;
        }
        watchdog_update();
        tight_loop_contents();
    }
}

static CtaphidDeviceResult reset_session(Rp2350Application *application) {
    bool restart = usb.restart;
    usb.reset = false; usb.first = 0; usb.count = 0;
    usb.sending = false; usb.sent = false;
    if(!rp2350_application_disconnect(application)) return CTAPHID_DEVICE_INVALID_STATE;
    /* A send timeout (including host suspend) has already deinitialized USB,
     * cancelling hardware access and queued replies. Re-enumerate only after
     * the coordinator unwinds and its old session/tokens are discarded. */
    if(restart && !rp2350_usb_init()) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    return CTAPHID_DEVICE_OK;
}

CtaphidDeviceResult rp2350_usb_poll(Rp2350Application *application) {
    if(usb.failed) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    if(usb.restart) return reset_session(application);
    if(!usb.enabled) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    tud_task_ext(0, false);
    if(usb.failed) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    if(usb.reset) {
        CtaphidDeviceResult result = reset_session(application);
        if(result != CTAPHID_DEVICE_OK) return result;
    }
    if(usb.count) {
        CtaphidDeviceResult result = rp2350_application_receive(application, usb.reports[usb.first], 64);
        /* INIT/PING can submit IN synchronously from receive(), too. Once it
         * unwinds, a bus reset discards the old session before its send error
         * can be interpreted as a permanent transport failure. */
        if(usb.reset && !usb.failed) return reset_session(application);
        if(result != CTAPHID_DEVICE_OK && result != CTAPHID_DEVICE_IGNORED) return result;
        usb.first = (usb.first + 1) % INPUT_REPORTS;
        --usb.count;
    }
    CtaphidDeviceResult result = rp2350_application_poll(application);
    /* A reset during synchronous IN cancels that transfer. The coordinator
     * has now released it; discard the old session instead of faulting flash. */
    if(usb.reset && !usb.failed) {
        return reset_session(application);
    }
    return result;
}
