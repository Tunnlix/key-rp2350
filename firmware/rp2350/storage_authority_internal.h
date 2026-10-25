#ifndef RP2350_STORAGE_AUTHORITY_INTERNAL_H
#define RP2350_STORAGE_AUTHORITY_INTERNAL_H
#include "storage_root_internal.h"
#include "flash.h"
/* Provider-private read-only root-pair gate. Policy is fixed by the application,
 * never selected from flash. Profile 1/backend 0 is explicitly disposable;
 * profile 2 requires a specific nonzero backend. No fallback is permitted. */
typedef struct { uint8_t profile,backend; } Rp2350StoreRootPolicy;
/* Resolve only the supplied UNTRUSTED descriptor into derived-key primitives.
 * Must enforce backend policy, remain bounded, have no persistent side effects
 * and retain no resources needing separate release. Borrowed primitive contexts
 * remain owned by the provider. No raw-root export through a core interface.
 * An actual protected backend is not implemented by this callback contract. */
typedef AuthStatus (*Rp2350StoreRootResolve)(void *,const Rp2350StoreRoot *,Rp2350StoreSeal *);
typedef struct {
    Rp2350StoreRoot root;
    Rp2350StoreSeal seal;
    bool validated;
} Rp2350StoreRootAuthority;
typedef struct {
    uint8_t slots[2][4096];
    Rp2350StoreRoot roots[2];
    Rp2350StoreSeal seal;
} Rp2350StoreRootWorkspace;
/* Reads fixed partition-relative slots 0x2000/0x3000, requires byte-identical
 * complete sectors and independently authenticates both copies before output.
 * No highest-serial selection, repair, provisioning, flash writes or OTP.
 * All arguments/workspace/provider contexts must be disjoint and serialized.
 * Caller-owned workspace belongs in static RAM, not the target stack.
 * Every error clears authority and workspace. NOT_FOUND means BOTH root sectors
 * are erased, not that the entire partition is virgin or safe to provision.
 * Pair agreement/authentication does not establish trusted freshness/rollback
 * protection, selector/checkpoint authority or a serving provider. */
AuthStatus rp2350_store_root_pair_open_internal(Rp2350StoreRootAuthority *,const Rp2350Flash *,
    const Rp2350StoreRootPolicy *,Rp2350StoreRootResolve,void *,Rp2350StoreRootWorkspace *);
void rp2350_store_root_authority_clear_internal(Rp2350StoreRootAuthority *);
#endif
