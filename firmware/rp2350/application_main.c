#include "board_layout.h"
#include "application.h"
#include "board_flash.h"
#include "board_entropy.h"
#include "stack_probe.h"
#include "status_led.h"
#include "usb_transport.h"
#include "ctap_device_version.h"
#include "pico/binary_info.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"

/* Match USB/INIT/GetInfo in offline UF2/ELF inspection too. */
bi_decl(bi_program_version_string(CTAP_DEVICE_VERSION_STRING))

/* Normal Key entry point. Recover existing authenticated storage, then
 * serve USB requests with real GPIO26 presence. Never format storage here. */
static struct {
    Rp2350Application application;
    Rp2350Crypto crypto;
    Rp2350BoardFlash flash;
    Rp2350Entropy entropy;
} app;

#define STARTUP_MARKER UINT32_C(0x41505031)
#define WATCHDOG_TIMEOUT_MS 6000U
#define STACK_USE_LIMIT_BYTES 14336U
#define STACK_CHECK_INTERVAL_MS 50U

static uint64_t presence_operation;
static void update_status_led(AuthStatus status);

static uint32_t now_ms(void *context) {
    (void)context;
    return to_ms_since_boot(get_absolute_time());
}

static bool button_pressed(void *context) {
    (void)context;
    return !gpio_get(RP2350_BUTTON_GPIO);
}

static void flash_progress(void *context) {
    (void)context;
    watchdog_update();
    rp2350_usb_service(&app.application);
    update_status_led(AUTH_OK);
}

static void configure_pins(void) {
    rp2350_status_led_init();
    gpio_init(RP2350_BUTTON_GPIO);
    gpio_set_dir(RP2350_BUTTON_GPIO, GPIO_IN);
    gpio_pull_up(RP2350_BUTTON_GPIO);
}

static void clear_startup_marker(void) {
    watchdog_hw->scratch[0] = 0;
    watchdog_hw->scratch[1] = 0;
}

static void __attribute__((noreturn)) enter_bootloader(void) {
    /* Called only from this owner loop, outside USB callbacks/provider writes.
     * A PC request reaches here after its final IN completion. */
    rp2350_usb_close();
    if(app.application.initialized) rp2350_application_close(&app.application);
    rp2350_crypto_free(&app.crypto);
    auth_secure_zero(&app,sizeof(app));
    clear_startup_marker();
    watchdog_disable();
    rp2350_status_led_close();
    rom_reset_usb_boot(0,0);
}

static void startup_update_gesture(void) {
    Rp2350BootGesture gesture;
    rp2350_boot_gesture_init(&gesture,button_pressed(NULL),now_ms(NULL));
    for(;;) {
        uint32_t now=now_ms(NULL);
        Rp2350BootGestureResult result=rp2350_boot_gesture_sample(&gesture,button_pressed(NULL),now);
        if(result==RP2350_BOOT_NORMAL) return;
        if(result==RP2350_BOOT_ENTER) enter_bootloader();
        rp2350_status_led_poll(result == RP2350_BOOT_RELEASE ?
            RP2350_LED_RECOVERY_RELEASE : RP2350_LED_RECOVERY_HOLD, now);
        sleep_ms(1);
    }
}

static bool submit_report(void *context, const uint8_t report[64], uint64_t transfer) {
    const CtaphidDevice *device = &app.application.device;
    const CtaphidQueuedReport *first = &device->response[0];
    bool success = presence_operation != 0 && device->flight_id == transfer &&
        device->flight.final_response && device->flight.owner == presence_operation &&
        device->response_count != 0 && first->owner == presence_operation &&
        first->bytes[4] == (0x80U | CTAPHID_COMMAND_CBOR) &&
        (first->bytes[5] != 0 || first->bytes[6] != 0) && first->bytes[7] == CTAP_STATUS_OK;
    bool sent = rp2350_usb_submit(context, report, transfer);
    if(sent && success) {
        rp2350_status_led_success(now_ms(NULL));
        presence_operation = 0;
    }
    return sent;
}

static AuthStatus start_application(void) {
    AuthStatus status = rp2350_board_flash_open(&app.flash, 0, RP2350_STORE_FLASH_BYTES);
    if(status != AUTH_OK) return status;
    app.flash.progress = flash_progress;

    if(!rp2350_board_entropy_init(&app.entropy)) return AUTH_CRYPTO_ERROR;
    status = rp2350_crypto_init(&app.crypto, rp2350_entropy_read, &app.entropy);
    if(status != AUTH_OK) return status;

    Rp2350Flash flash = rp2350_flash_guard_interface(&app.flash.guard);
    Rp2350ApplicationIo io = {
        .now_ms = now_ms,
        .pressed = button_pressed,
        .submit = submit_report,
        .usb_transport = true,
        .cancel_requested = rp2350_usb_cancel_requested
    };
    /* Key onboard model: fa024a59-a2a6-41d9-bd40-ed6a78915bca. Stable across firmware revisions. */
    static const uint8_t model_aaguid[16] = {0xfa, 0x02, 0x4a, 0x59, 0xa2, 0xa6, 0x41, 0xd9, 0xbd, 0x40, 0xed, 0x6a, 0x78, 0x91, 0x5b, 0xca};
    status = rp2350_application_init(&app.application, &app.crypto, &flash, &io,
        model_aaguid, 0); /* Actual power-on time; USB reset never renews it. */
    if(status != AUTH_OK) return status;
    Rp2350Flash blobs = rp2350_board_blob_flash(&app.flash);
    status = rp2350_application_configure_blobs(&app.application, &blobs);
    if(status != AUTH_OK) return status;
    return rp2350_usb_init() ? AUTH_OK : AUTH_IO_ERROR;
}

static AuthStatus poll_application(void) {
    if(app.application.backend.pending && app.application.backend.awaiting_presence)
        presence_operation = app.application.backend.operation_id;
    else if(app.application.device.phase == CTAPHID_DEVICE_IDLE ||
        presence_operation != app.application.device.transaction_id)
        presence_operation = 0;
    CtaphidDeviceResult result = rp2350_usb_poll(&app.application);
    if(result != CTAPHID_DEVICE_OK && result != CTAPHID_DEVICE_IGNORED) return AUTH_IO_ERROR;
    return rp2350_application_ready(&app.application) ? AUTH_OK : AUTH_IO_ERROR;
}

static void update_status_led(AuthStatus status) {
    Rp2350LedState state;
    if(status != AUTH_OK) {
        state = RP2350_LED_FAULT;
    } else if(!app.application.initialized) {
        state = RP2350_LED_STARTING;
    } else if(app.application.update.waiting) {
        state = RP2350_LED_UPDATE;
    } else if(app.application.backend.awaiting_presence) {
        state = RP2350_LED_TOUCH;
    } else {
        state = RP2350_LED_IDLE;
    }
    rp2350_status_led_poll(state, now_ms(NULL));
}

int main(void) {
    configure_pins();
    bool interrupted = watchdog_enable_caused_reboot() &&
        watchdog_hw->scratch[0] == STARTUP_MARKER &&
        watchdog_hw->scratch[1] == ~STARTUP_MARKER;
    clear_startup_marker();
    watchdog_disable();
    startup_update_gesture();
    bool stack_observed = rp2350_stack_probe_begin();

    /* Do not repeatedly retry a startup that already timed out. */
    if(!interrupted) {
        watchdog_hw->scratch[0] = STARTUP_MARKER;
        watchdog_hw->scratch[1] = ~STARTUP_MARKER;
        watchdog_enable(WATCHDOG_TIMEOUT_MS, true);
    }
    AuthStatus status = AUTH_IO_ERROR;
    if(!interrupted) status = stack_observed ? start_application() : AUTH_CAPACITY;
    clear_startup_marker();
    bool fault_closed = false;
    uint32_t last_stack_check=now_ms(NULL)-STACK_CHECK_INTERVAL_MS;

    while(true) {
        if(status == AUTH_OK) status = poll_application();
        if(status == AUTH_OK && rp2350_firmware_update_ready(&app.application)) enter_bootloader();
        uint32_t now=now_ms(NULL);
        if(stack_observed && (uint32_t)(now-last_stack_check)>=STACK_CHECK_INTERVAL_MS) {
            last_stack_check=now;
            uint32_t used = rp2350_stack_probe_used();
            if(used > STACK_USE_LIMIT_BYTES) status = AUTH_CAPACITY;
        }
        if(status != AUTH_OK && !fault_closed) {
            rp2350_usb_close();
            if(app.application.initialized) rp2350_application_close(&app.application);
            /* Terminal faults never resume service. Wipe the owned DRBG/arena
             * and previous entropy block, including partial startup failures. */
            rp2350_crypto_free(&app.crypto);
            auth_secure_zero(app.entropy.previous, sizeof(app.entropy.previous));
            fault_closed = true;
        }
        update_status_led(status);
        watchdog_update();
        sleep_ms(1);
    }
}
