#ifndef RP2350_LED_WINK_H
#define RP2350_LED_WINK_H
#include <stdbool.h>
#include <stdint.h>

/* Owner-loop animation: no sleep, flash write, touch event or authorization.
 * Repeated requests cannot renew the active burst or bypass the quiet period. */
typedef struct { bool seen, active; uint32_t started_ms; } Rp2350Wink;
static inline void rp2350_wink_begin(Rp2350Wink *wink, uint32_t now_ms) {
    if(wink->seen && (uint32_t)(now_ms-wink->started_ms)<3000U) return;
    wink->seen=wink->active=true;
    wink->started_ms=now_ms;
}
static inline uint32_t rp2350_wink_color(Rp2350Wink *wink, bool idle, uint32_t now_ms) {
    uint32_t elapsed=now_ms-wink->started_ms;
    if(!idle || elapsed>=1200U) wink->active=false;
    return wink->active && elapsed%300U<100U ? UINT32_C(0x100010) : 0U;
}
#endif
