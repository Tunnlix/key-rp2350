#ifndef RP2350_STORAGE_RESET_INTERNAL_H
#define RP2350_STORAGE_RESET_INTERNAL_H
#include "storage_selector_writer_internal.h"
typedef struct { bool verified_blank; } Rp2350StoreResetErasure;
typedef struct {
    Rp2350StoreRootAuthority root;
    Rp2350StoreSelection selection;
    union {
        Rp2350StoreRootWorkspace roots;
        Rp2350StoreSelectorWorkspace selectors;
        uint8_t page[256];
    } io;
} Rp2350StoreResetWorkspace;
/* Development-profile erasure over injected model or verified physical IO.
 * All arguments/contexts disjoint, serialized, workspace in static RAM; freeze
 * all mutations and credential service throughout. The authorization callback
 * must invalidate runtime secrets/state and latch service off (as for intent
 * writing). It runs before any IO; retain the latch on EVERY later failure.
 * Authenticate fresh roots and terminal intent, scan the whole owned partition,
 * erase/read-verify both arenas, both roots, the other selector sector, then an
 * intent-bearing sector last. Final full-partition verification precedes the
 * receipt. No programs, provisioning, provider activation or CTAP Reset success.
 * A cut while erasing roots/selectors may destroy intent verifiability and
 * require a separately authorized physical recovery Reset, never auto-repair.
 * Any error clears output/scratch; successful scratch is also wiped. */
AuthStatus rp2350_store_reset_erase_internal(Rp2350StoreResetErasure *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreResetAuthorize,void *,Rp2350StoreResetWorkspace *);
/* Explicit destructive recovery entry, NOT automatic retry of normal Reset.
 * Callback must consume NEW physical recovery-Reset authorization, independent
 * of cached intent/blank media, and invalidate/latch runtime as above. The
 * callback contract is simulated in native tests, not physically implemented.
 * No root/selector/credential is trusted or mounted; scan all owned bytes before
 * erasing. Erase data, roots, selector 1 then 0; read-verify every sector and the
 * whole partition. Already blank still needs explicit authorization, but no
 * erases. Never fall back to this operation after normal failure. Policy is
 * fixed by caller (development profile 1/backend 0 only), not taken from flash.
 * This receipt authorizes neither provisioning nor completed CTAP Reset. */
AuthStatus rp2350_store_reset_recovery_erase_internal(Rp2350StoreResetErasure *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreResetAuthorize,void *,Rp2350StoreResetWorkspace *);
#endif
