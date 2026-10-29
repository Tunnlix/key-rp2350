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
void rp2350_status_led_fault(Rp2350Fault fault, uint8_t detail,
    uint32_t status, uint32_t now_ms);

/* Pure timing function, also exercised by native checks. Entropy diagnostics:
 * red category, amber failure enum, blue (RNG_ISR low nibble + 1). The offset
 * makes a zero status visible. Other faults retain the original pattern.
 * No entropy samples, secrets, counters, USB or persistent storage are used. */
static inline uint32_t rp2350_fault_led_color(Rp2350Fault fault, uint8_t detail,
        uint8_t status, uint32_t elapsed_ms) {
    unsigned flashes=fault>=RP2350_FAULT_STORAGE && fault<=RP2350_FAULT_USB ?
        (unsigned)fault : (unsigned)RP2350_FAULT_BOOT;
    uint32_t red_ms=flashes*400U;
    if(fault!=RP2350_FAULT_ENTROPY || detail<1U || detail>7U) {
        uint32_t phase=elapsed_ms%(red_ms+1400U);
        return phase<red_ms && phase%400U<150U ? 0x100000U : 0U;
    }
    uint32_t amber_ms=detail*400U, blue_ms=((status&15U)+1U)*400U;
    uint32_t phase=elapsed_ms%(red_ms+1000U+amber_ms+1000U+blue_ms+2400U);
    if(phase<red_ms) return phase%400U<150U ? 0x100000U : 0U;
    if(phase<red_ms+1000U) return 0;
    phase-=red_ms+1000U;
    if(phase<amber_ms) return phase%400U<150U ? 0x100600U : 0U;
    if(phase<amber_ms+1000U) return 0;
    phase-=amber_ms+1000U;
    return phase<blue_ms && phase%400U<150U ? 0x001010U : 0U;
}
void rp2350_status_led_poll(Rp2350LedState state, uint32_t now_ms);
void rp2350_status_led_close(void);
#endif
