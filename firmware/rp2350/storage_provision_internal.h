#ifndef RP2350_STORAGE_PROVISION_INTERNAL_H
#define RP2350_STORAGE_PROVISION_INTERNAL_H
#include "storage_reset_internal.h"
typedef struct { bool verified; } Rp2350StoreProvisioned;
typedef struct {
    Rp2350StoreRoot root;
    Rp2350StoreSeal seal;
    Rp2350StoreGlobal global;
    AuthPinRecord pin;
    Rp2350StoreManifest manifest;
    Rp2350StoreSelector selector;
    Rp2350StoreLog log;
    Rp2350StoreBootResult recovered;
    Rp2350StoreBootWorkspace boot;
    uint8_t root_wire[512],data[96],compare[96],plain[112],ordered[88];
} Rp2350StoreProvisionWorkspace;
/* Development provisioning over injected IO. Fixed caller profile 1/backend 0;
 * the on-flash root descriptor is UNPROTECTED. No production root backend,
 * persistent encryption-attempt reservation or rollback proof is provided.
 * Callback consumes explicit provisioning authorization and invalidates/latches
 * runtime service before any IO. Blank media/cached erasure receipts never
 * authorize this call. All inputs/contexts disjoint, serialized, workspace in
 * static RAM; freeze all other mutations. Keep service disabled on every exit.
 * Re-read ALL partition bytes before RNG/writes; require entirely erased media.
 * Generate a new root, epoch, handle prefix, store state and device identifier
 * using supplied provider randomness. Never accept caller-selected secrets or
 * fall back to test randomness. RNG freshness/quality remains a provider duty.
 * Write an empty global/PIN/manifest checkpoint in arena A, identical root
 * capsules, then the FIRST SWITCH as final authority. No erase callback used.
 * Revalidate complete boot, canonical empty state and the blank inactive arena
 * before returning a receipt. Serial/reset generation start at 1 WITHIN the
 * fresh epoch; these are not cross-epoch monotonic/anti-rollback counters.
 * Any failure clears output/workspace; a complete new empty image may already
 * be durable. Never resume partial provisioning or automatically erase it:
 * fresh boot/recovery authorization must precede recovery erasure and a new
 * provisioning attempt. A verified receipt is NOT READY or CTAP Reset success:
 * agreement-key renewal and application/provider publication remain separate. */
AuthStatus rp2350_store_provision_internal(Rp2350StoreProvisioned *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,const AuthCrypto *,const AuthSecretCrypto *,
    Rp2350StoreResetAuthorize,void *,Rp2350StoreProvisionWorkspace *);
#endif
