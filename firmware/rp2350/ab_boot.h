#ifndef RP2350_AB_BOOT_H
#define RP2350_AB_BOOT_H
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool valid, pending;
} Rp2350AbBoot;

/* Pending defaults to true on an unreadable boot record: never disable or feed
 * the ROM trial watchdog when the boot mode is uncertain. */
bool rp2350_ab_boot_begin(Rp2350AbBoot *);
/* Call only after read-only startup and USB health checks, with no live CTAP
 * operation. Scratch is borrowed from the idle provider and wiped on return. */
bool rp2350_ab_boot_confirm(Rp2350AbBoot *, void *scratch, size_t bytes);
#endif
