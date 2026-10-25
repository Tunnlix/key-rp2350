#ifndef RP2350_STORAGE_SELECTOR_INTERNAL_H
#define RP2350_STORAGE_SELECTOR_INTERNAL_H
#include "storage_authority_internal.h"
typedef struct {
    Rp2350StoreSelector selector;
    uint32_t arena_base; /* Only meaningful for state 1 SWITCH. */
    bool validated;
    uint8_t used[2],current_mask; /* Authenticated append placement information. */
} Rp2350StoreSelection;
typedef struct {
    uint8_t frame[512],plain[96];
    Rp2350StoreSealWorkspace seal;
    Rp2350StoreSelector records[16]; size_t count;
    uint8_t used[2]; uint64_t last[2];
} Rp2350StoreSelectorWorkspace;
/* Read-only fixed selector sectors at partition offsets 0/0x1000, eight
 * 512-byte slots each. Envelope generation is the validated root serial;
 * envelope sequence equals payload serial. Epoch/reset generation bind root.
 * Each sector is a contiguous append prefix. First retained serial may be an
 * authenticated recycling anchor; following serials are contiguous. Merge
 * overlapping identical anchors, reject conflicts/gaps/torn or hidden tails.
 * SWITCH increments arena generation and alternates arenas. RESET_INTENT is
 * terminal within this root epoch and never authorizes an arena.
 * All buffers/contexts disjoint, static caller-owned workspace, serial calls.
 * Output and workspace clear on every failure; read NOT_FOUND is a fault.
 * Blank selectors under an existing root are BAD_DATA, never provisioning.
 * No writes/recycling, freshness/rollback proof or checkpoint mount occurs.
 * SWITCH only supplies trusted inputs for checkpoint validation; RESET_INTENT
 * requires RESETTING, never credential service. */
AuthStatus rp2350_store_select_internal(Rp2350StoreSelection *,const Rp2350Flash *,
    Rp2350StoreRootAuthority *,Rp2350StoreSelectorWorkspace *);
#endif
