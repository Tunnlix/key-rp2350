#include "stack_probe.h"
#include "hardware/sync.h"
#include <stddef.h>
#if !defined(__ARM_ARCH_8M_MAIN__)
#error "Stack probe requires the reviewed Cortex-M33 build"
#endif
extern uint8_t __StackBottom[],__StackTop[];
static uintptr_t paint_end;
#define STACK_PATTERN UINT32_C(0xa55a39c6)
bool rp2350_stack_probe_begin(void) {
    uint32_t irq_state=save_and_disable_interrupts();
    uintptr_t current;
    __asm__ volatile("mrs %0, msp" : "=r"(current));
    uintptr_t bottom=(uintptr_t)__StackBottom,top=(uintptr_t)__StackTop;
    if (current>top || current<bottom+512U || bottom%4U || top%4U) {
        restore_interrupts(irq_state); return false;
    }
    /* Leave the active stack and 256 bytes of call/interrupt headroom untouched. */
    paint_end=(current-256U)&~(uintptr_t)3;
    for (uintptr_t at=bottom;at<paint_end;at+=4U) *(volatile uint32_t *)at=STACK_PATTERN;
    restore_interrupts(irq_state);
    return true;
}
uint32_t rp2350_stack_probe_used(void) {
    uintptr_t bottom=(uintptr_t)__StackBottom,top=(uintptr_t)__StackTop,at=bottom;
    if (!paint_end) return (uint32_t)(top-bottom);
    while (at<paint_end && *(volatile uint32_t *)at==STACK_PATTERN) at+=4U;
    return (uint32_t)(top-at);
}
