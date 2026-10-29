#ifndef RP2350_ENTROPY_H
#define RP2350_ENTROPY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define RP2350_ENTROPY_BLOCK_SIZE 24U
#define RP2350_ENTROPY_TIMEOUT_MS 100U
#define RP2350_ENTROPY_MAX_POLLS 1000000U
#define RP2350_ENTROPY_MAX_REQUEST 256U
#define RP2350_ENTROPY_CONFIG_ERROR UINT32_C(0x10000)
#define RP2350_ENTROPY_ERROR_MASK (UINT32_C(0x0e) | RP2350_ENTROPY_CONFIG_ERROR)
#define RP2350_ENTROPY_MAX_CRNGT_RETRIES 3U
/* Driver owns the TRNG exclusively. Status bit 0=valid, bits 1..3=health
 * failures, matching RP2350 RNG_ISR; bit 16 reports adapter configuration
 * changes separately. Only an isolated CRNGT rejection while polling may be
 * cleared, at most three times per read without extending collection deadlines
 * or poll budgets.
 * Other failures remain terminal; no rejected block may be read or delivered. */
typedef struct {
    void *context;
    bool (*start)(void *);
    uint32_t (*status)(void *);
    uint32_t (*read_word)(void *,size_t);
    void (*stop)(void *);
    uint32_t (*now_ms)(void *);
    /* Optional: acknowledge only CRNGT_ERR, retaining enabled hardware checks
     * and the running collection. Never clear another fault or return samples. */
    bool (*clear_crngt)(void *);
} Rp2350EntropyIo;
/* Retain the first collection failure without storing entropy samples in
 * diagnostics. STATUS identifies hardware errors; CONFIG identifies adapter
 * configuration errors without fabricating hardware health-failure flags. */
typedef enum {
    RP2350_ENTROPY_FAULT_NONE,
    RP2350_ENTROPY_FAULT_START,
    RP2350_ENTROPY_FAULT_STATUS,
    RP2350_ENTROPY_FAULT_TIMEOUT,
    RP2350_ENTROPY_FAULT_POLL_LIMIT,
    RP2350_ENTROPY_FAULT_REPEATED,
    RP2350_ENTROPY_FAULT_STUCK,
    RP2350_ENTROPY_FAULT_CONFIG
} Rp2350EntropyFault;
typedef struct {
    Rp2350EntropyIo io;
    bool initialized, faulted, have_previous;
    Rp2350EntropyFault failure;
    uint32_t last_status;
    uint32_t requests,blocks,elapsed_ms; /* Nonsecret, wrapping diagnostic counters. */
    uint32_t crngt_retries;
    uint8_t previous[RP2350_ENTROPY_BLOCK_SIZE];
    uint8_t available; /* Unused suffix of the last health-checked block. */
} Rp2350Entropy;
bool rp2350_entropy_init(Rp2350Entropy *,const Rp2350EntropyIo *);
int rp2350_entropy_read(void *,unsigned char *,size_t);
#endif
