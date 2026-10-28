#include "status_led.h"
#include "ctap_device_version.h"
#include "pico/binary_info.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"
#include "hardware/watchdog.h"

bi_decl(bi_program_version_string(CTAP_DEVICE_VERSION_STRING))

/* Exercise a signed RAM boot without binding flash, storage or OTP writers.
 * Return to PICOBOOT so the host can restore the signed application. */
int main(void) {
    watchdog_enable(6000, true);
    rp2350_status_led_init();
    uint32_t started = to_ms_since_boot(get_absolute_time());
    for(;;) {
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if((uint32_t)(now - started) >= 3000U) break;
        rp2350_status_led_poll(RP2350_LED_UPDATE, now - started);
        watchdog_update();
        sleep_ms(1);
    }
    rp2350_status_led_close();
    watchdog_disable();
    rom_reset_usb_boot(0, 1); /* Keep PICOBOOT; disable mass storage. */
}
