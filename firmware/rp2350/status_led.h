#ifndef RP2350_STATUS_LED_H
#define RP2350_STATUS_LED_H
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    RP2350_LED_STARTING,
    RP2350_LED_IDLE,
    RP2350_LED_TOUCH,
    RP2350_LED_UPDATE,
    RP2350_LED_RECOVERY_HOLD,
    RP2350_LED_RECOVERY_RELEASE,
    RP2350_LED_FAULT
} Rp2350LedState;

void rp2350_status_led_init(void);
void rp2350_status_led_success(uint32_t now_ms);
void rp2350_status_led_poll(Rp2350LedState state, uint32_t now_ms);
void rp2350_status_led_close(void);
#endif
