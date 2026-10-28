#include "board_layout.h"
#include "firmware_update.h"
#include "presence.h"
#include "status_led.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"

/* Explicit RAM-only escape from a damaged or unwanted partition table.
 * Never erase application slots, credentials, blobs or OTP. */
_Static_assert(RP2350_FIRMWARE_A_OFFSET == 8192U, "Layout reset must erase only 8 KiB");
int main(void) {
    watchdog_enable(6000, true);
    rp2350_status_led_init();
    gpio_init(RP2350_BUTTON_GPIO);
    gpio_set_dir(RP2350_BUTTON_GPIO, GPIO_IN);
    gpio_pull_up(RP2350_BUTTON_GPIO);
    Rp2350UpdateGesture gesture;
    rp2350_update_gesture_init(&gesture, !gpio_get(RP2350_BUTTON_GPIO),
        to_ms_since_boot(get_absolute_time()));
    for(;;) {
        uint32_t now = to_ms_since_boot(get_absolute_time());
        Rp2350UpdateGestureResult result = rp2350_update_gesture_sample(&gesture,
            !gpio_get(RP2350_BUTTON_GPIO), now);
        if(result == RP2350_UPDATE_EXPIRED) break;
        if(result == RP2350_UPDATE_CONFIRMED) {
            uint32_t saved = save_and_disable_interrupts();
            flash_range_erase(0, RP2350_FIRMWARE_A_OFFSET);
            restore_interrupts(saved);
            const volatile uint8_t *metadata = (const volatile uint8_t *)(uintptr_t)
                XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE;
            bool erased = true;
            for(size_t i = 0; i < RP2350_FIRMWARE_A_OFFSET; ++i)
                if(metadata[i] != 0xffU) erased = false;
            rp2350_status_led_poll(erased ? RP2350_LED_IDLE : RP2350_LED_FAULT, now);
            break;
        }
        rp2350_status_led_poll(result == RP2350_UPDATE_RELEASE ?
            RP2350_LED_RECOVERY_RELEASE : RP2350_LED_UPDATE, now);
        watchdog_update();
        sleep_ms(1);
    }
    rp2350_status_led_close();
    watchdog_disable();
    rom_reset_usb_boot(0, 1);
}
