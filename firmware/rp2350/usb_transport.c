#include "usb_transport.h"
#include "tusb.h"
#include "device/dcd.h"
#include "pico/stdlib.h"
#include "hardware/watchdog.h"
#include <string.h>

/* The hardware NAKs OUT while its buffer is occupied. This bounded queue also
 * retains input arriving while a synchronous IN submission services USB. An
 * overflow cancels the session and reconnects instead of dropping request
 * bytes into a still-authorized session. Callbacks only request that restart. */
#define INPUT_REPORTS 16U
static struct {
    uint8_t reports[INPUT_REPORTS][64];
    size_t first, count;
    bool enabled, mounted, failed, sending, sent, restart;
    uint8_t progress_report[64];
    uint32_t progress_channel, progress_ms;
    uint64_t progress_operation;
    bool progress_sending, cancel_seen;
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
    uint32_t channel=((uint32_t)buffer[0]<<24)|((uint32_t)buffer[1]<<16)|((uint32_t)buffer[2]<<8)|buffer[3];
    if(usb.progress_operation && channel==usb.progress_channel &&
        buffer[4]==(0x80U|CTAPHID_COMMAND_CANCEL) && buffer[5]==0 && buffer[6]==0)
        usb.cancel_seen=true;
    if(usb.count == INPUT_REPORTS) { usb.restart = true; usb.reset = true; return; }
    memcpy(usb.reports[(usb.first + usb.count) % INPUT_REPORTS], buffer, 64);
    ++usb.count;
}
void tud_hid_report_complete_cb(uint8_t instance, const uint8_t *report, uint16_t length) {
    (void)report;
    if(instance == 0 && length == 64) {
        if(usb.progress_sending) usb.progress_sending=false;
        else if(usb.sending) usb.sent=true;
    }
}
void tud_hid_report_failed_cb(uint8_t instance, hid_report_type_t type,
        const uint8_t *report, uint16_t length) {
    (void)instance; (void)type; (void)report; (void)length;
    usb.failed = true;
}

bool rp2350_usb_cancel_requested(void *context,uint64_t operation) {
    (void)context;
    return usb.cancel_seen && operation==usb.progress_operation;
}

void rp2350_usb_service(const Rp2350Application *application) {
    if(!usb.enabled || usb.failed || usb.reset || usb.sending || !application || !application->initialized) return;
    const CtaphidDevice *device=&application->device;
    bool active=device->cbor_running && device->phase==CTAPHID_DEVICE_PROCESSING;
    uint32_t now=to_ms_since_boot(get_absolute_time());
    if(active && usb.progress_operation!=device->transaction_id) {
        usb.progress_operation=device->transaction_id;
        usb.progress_channel=device->active_channel_id;
        usb.progress_ms=device->last_keepalive_ms;
        usb.cancel_seen=false;
    }
    tud_task_ext(0,false);
    if(!active || usb.failed || usb.reset || !usb.mounted || usb.progress_sending ||
        (uint32_t)(now-usb.progress_ms)<CTAPHID_KEEPALIVE_INTERVAL_MS || !tud_hid_ready()) return;
    uint8_t *report=usb.progress_report;
    memset(report,0,64);
    for(size_t i=0;i<4;i++) report[i]=(uint8_t)(usb.progress_channel>>(24U-8U*i));
    report[4]=0x80U|CTAPHID_COMMAND_KEEPALIVE;
    report[6]=1; report[7]=CTAPHID_STATUS_PROCESSING;
    usb.progress_sending=tud_hid_report(0,report,64);
    if(usb.progress_sending) usb.progress_ms=now;
}

bool rp2350_usb_submit(void *context, const uint8_t report[64], uint64_t transfer) {
    (void)context; (void)transfer;
    if(!usb.enabled || usb.failed || usb.reset || !usb.mounted) return false;
    uint32_t started = to_ms_since_boot(get_absolute_time());
    usb.sent = false;
    usb.sending = false;
    for(;;) {
        tud_task_ext(0, false);
        if(usb.restart && !usb.failed) {
            /* Overflow can arrive during synchronous IN. Cancel hardware
             * access before returning the borrowed report to its owner. */
            rp2350_usb_close(); usb.restart = true; usb.reset = true;
            return false;
        }
        if(usb.failed || usb.reset || !tud_mounted()) return false;
        if(!usb.sending && !usb.progress_sending && tud_hid_ready()) {
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
    if(restart) rp2350_usb_close();
    usb.reset = false; usb.first = 0; usb.count = 0;
    usb.sending = false; usb.sent = false;
    usb.progress_sending=false; usb.cancel_seen=false;
    usb.progress_operation=0; usb.progress_channel=0;
    if(!rp2350_application_disconnect(application)) return CTAPHID_DEVICE_INVALID_STATE;
    /* Re-enumerate only after hardware is quiescent, the coordinator unwinds
     * and its old session/tokens are discarded. Storage faults stay terminal. */
    if(restart && !rp2350_usb_init()) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    return CTAPHID_DEVICE_OK;
}

CtaphidDeviceResult rp2350_usb_poll(Rp2350Application *application) {
    if(usb.failed) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    if(usb.restart) return reset_session(application);
    if(!usb.enabled) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    tud_task_ext(0, false);
    if(usb.failed) return CTAPHID_DEVICE_TRANSPORT_FAILED;
    if(usb.restart) return reset_session(application);
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
