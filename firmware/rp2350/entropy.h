#ifndef RP2350_ENTROPY_H
#define RP2350_ENTROPY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define RP2350_ENTROPY_BLOCK_SIZE 24U
#define RP2350_ENTROPY_TIMEOUT_MS 100U
#define RP2350_ENTROPY_MAX_POLLS 1000000U
#define RP2350_ENTROPY_MAX_REQUEST 256U
/* Driver owns the TRNG exclusively. Status bit 0=valid, bits 1..3=health
 * failures, matching RP2350 RNG_ISR. No retry/reset after a health failure. */
typedef struct {
    void *context;
    bool (*start)(void *);
    uint32_t (*status)(void *);
    uint32_t (*read_word)(void *,size_t);
    void (*stop)(void *);
    uint32_t (*now_ms)(void *);
} Rp2350EntropyIo;
/* Retain the first collection failure without storing entropy samples in
 * diagnostics. STATUS includes hardware errors or adapter configuration errors. */
typedef enum {
    RP2350_ENTROPY_FAULT_NONE,
    RP2350_ENTROPY_FAULT_START,
    RP2350_ENTROPY_FAULT_STATUS,
    RP2350_ENTROPY_FAULT_TIMEOUT,
    RP2350_ENTROPY_FAULT_POLL_LIMIT,
    RP2350_ENTROPY_FAULT_REPEATED,
    RP2350_ENTROPY_FAULT_STUCK
} Rp2350EntropyFault;
typedef struct {
    Rp2350EntropyIo io;
    bool initialized, faulted, have_previous;
    Rp2350EntropyFault failure;
    uint32_t last_status;
    uint8_t previous[RP2350_ENTROPY_BLOCK_SIZE];
} Rp2350Entropy;
bool rp2350_entropy_init(Rp2350Entropy *,const Rp2350EntropyIo *);
int rp2350_entropy_read(void *,unsigned char *,size_t);
#endif
