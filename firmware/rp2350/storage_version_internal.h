#ifndef RP2350_STORAGE_VERSION_INTERNAL_H
#define RP2350_STORAGE_VERSION_INTERNAL_H
#include <stdint.h>
typedef struct {
    uint8_t epoch[16];
    uint64_t root_serial,selector_serial,generation,logical_sequence;
} Rp2350StoreVersion;
#endif
