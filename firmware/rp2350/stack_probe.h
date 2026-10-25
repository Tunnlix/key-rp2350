#ifndef RP2350_STACK_PROBE_H
#define RP2350_STACK_PROBE_H
#include <stdbool.h>
#include <stdint.h>
/* Development stack observation. Reports use after begin, not a worst-case bound.
 * The boot loop must run on MSP, with no core 1 or RTOS switching stacks. */
bool rp2350_stack_probe_begin(void);
uint32_t rp2350_stack_probe_used(void);
#endif
