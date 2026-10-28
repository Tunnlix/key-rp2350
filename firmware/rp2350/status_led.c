#include "status_led.h"
#include "pico/status_led.h"
#include "pico/time.h"

static struct {
    bool initialized, rgb, shown, success;
    uint32_t color, success_ms;
    uint64_t last_write_us;
    Rp2350Fault fault;
    uint32_t fault_ms;
} led;

void rp2350_status_led_init(void) {
    led.initialized = status_led_init();
    led.rgb = led.initialized && colored_status_led_supported();
    led.shown = led.success = false;
    led.fault = 0;
    led.last_write_us = time_us_64();
    /* The XIAO user LED remains available even if RGB initialization fails. */
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_put(PICO_DEFAULT_LED_PIN, true);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
}

void rp2350_status_led_success(uint32_t now_ms) {
    led.success = true;
    led.success_ms = now_ms;
}
void rp2350_status_led_fault(Rp2350Fault fault, uint32_t now_ms) {
    if(!led.fault && fault>=RP2350_FAULT_STORAGE && fault<=RP2350_FAULT_USB) {
        led.fault=fault;
        led.fault_ms=now_ms;
    }
}

void rp2350_status_led_poll(Rp2350LedState state, uint32_t now_ms) {
    uint32_t color = 0;
    bool on = false;
    if(led.success && (uint32_t)(now_ms - led.success_ms) >= 250U) led.success = false;
    if(state != RP2350_LED_IDLE) led.success = false;

    switch(state) {
    case RP2350_LED_STARTING:
        on = true;
        color = 0x020100U;
        break;
    case RP2350_LED_FAULT: {
        unsigned flashes=led.fault ? (unsigned)led.fault : (unsigned)RP2350_FAULT_BOOT;
        uint32_t phase=(uint32_t)(now_ms-led.fault_ms)%(flashes*400U+1400U);
        on = phase<flashes*400U && phase%400U<150U;
        color = 0x100000U;
        break;
    }
    case RP2350_LED_UPDATE: {
        uint32_t phase = now_ms % 1500U;
        on = phase < 100U || (phase >= 250U && phase < 350U);
        color = 0x100600U;
        break;
    }
    case RP2350_LED_RECOVERY_HOLD:
        on = now_ms % 1000U < 150U;
        color = 0x100600U;
        break;
    case RP2350_LED_RECOVERY_RELEASE:
        on = now_ms % 200U < 80U;
        color = 0x100600U;
        break;
    case RP2350_LED_TOUCH:
        on = now_ms % 400U < 200U;
        color = 0x000010U;
        break;
    case RP2350_LED_IDLE:
        on = led.success || now_ms % 3000U < 100U;
        color = led.success ? 0x001000U : 0x000002U;
        break;
    }
    if(!on) color = 0;
    /* Keep the existing fault indication even if RGB hardware is damaged. */
    gpio_put(PICO_DEFAULT_LED_PIN, !(on && (!led.rgb || state == RP2350_LED_FAULT)));
    if(!led.rgb || (led.shown && color == led.color)) return;

    uint64_t now_us = time_us_64();
    /* A pixel takes 30 us plus 300 us reset. Spacing writes by 1 ms keeps
     * the SDK's no-alarm path from waiting for the previous pixel. */
    if(now_us - led.last_write_us < 1000U) return;
    if(!colored_status_led_set_on_with_color(color)) {
        led.rgb = false;
        gpio_put(PICO_DEFAULT_LED_PIN, !on);
        return;
    }
    led.shown = true;
    led.color = color;
    led.last_write_us = time_us_64();
}

void rp2350_status_led_close(void) {
    if(led.initialized) status_led_deinit();
    led.initialized = led.rgb = led.success = false;
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_put(PICO_DEFAULT_LED_PIN, true);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
}
