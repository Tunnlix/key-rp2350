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
typedef enum {
    RP2350_FAULT_STORAGE=1,
    RP2350_FAULT_FLASH,
    RP2350_FAULT_ENTROPY,
    RP2350_FAULT_CRYPTO,
    RP2350_FAULT_STACK,
    RP2350_FAULT_BOOT,
    RP2350_FAULT_USB
} Rp2350Fault;

void rp2350_status_led_init(void);
void rp2350_status_led_success(uint32_t now_ms);
/* Retain the first nonsecret fault code in RAM; never write diagnostics to flash. */
void rp2350_status_led_fault(Rp2350Fault fault, uint32_t now_ms);
void rp2350_status_led_poll(Rp2350LedState state, uint32_t now_ms);
void rp2350_status_led_close(void);
#endif
