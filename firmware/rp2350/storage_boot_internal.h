#ifndef RP2350_STORAGE_BOOT_INTERNAL_H
#define RP2350_STORAGE_BOOT_INTERNAL_H
#include "storage_selector_internal.h"
#include "storage_replay_internal.h"
/* RECOVERED is a validated storage snapshot, NOT a serving/qualified provider
 * or READY. Separate provider recovery restores/activates keys; this API never does. */
typedef enum {
    RP2350_STORE_LOCKED=0, RP2350_STORE_UNPROVISIONED,
    RP2350_STORE_RESETTING, RP2350_STORE_MAINTENANCE, RP2350_STORE_RECOVERED
} Rp2350StoreBootState;
typedef struct {
    Rp2350StoreRootPolicy policy;
    Rp2350StoreRootResolve resolve; void *root_context;
    Rp2350StoreHash hash; Rp2350StoreKeyInspect key_inspect; void *records_context;
} Rp2350StoreBootConfig;
typedef struct {
    Rp2350StoreBootState state;
    Rp2350StoreRootAuthority root;
    Rp2350StoreSelection selection;
    Rp2350StoreReplayState records;
    uint32_t journal_end; /* Authenticated selected log extent, not cached IO. */
} Rp2350StoreBootResult;
typedef struct {
    Rp2350StoreRootAuthority root;
    Rp2350StoreSelection selection;
    Rp2350StoreRecovery recovery;
    Rp2350StoreLog log;
    union {
        Rp2350StoreRootWorkspace roots;
        Rp2350StoreSelectorWorkspace selectors;
        Rp2350StoreLogWorkspace log;
        uint8_t blank[256];
    } io;
} Rp2350StoreBootWorkspace;
/* All objects/provider contexts disjoint, serial, caller-owned static RAM.
 * Read-only: no provisioning, writes/erase, repair or private-key activation.
 * NOT_FOUND/UNPROVISIONED requires the ENTIRE owned 512 KiB partition erased;
 * it never authorizes automatic provisioning. A read/backend NOT_FOUND cannot
 * become UNPROVISIONED. Any failure wipes result to LOCKED and clears scratch.
 * A valid RESET_INTENT yields RESETTING without reading a data arena. SWITCH
 * validates exactly its selected checkpoint/log; no fallback to the standby.
 * Orphan/retired keys yield MAINTENANCE. Only complete recovery yields RECOVERED.
 * Successful snapshots and maintenance authority remain provider-private and
 * must be explicitly cleared before their owning primitives are torn down. */
AuthStatus rp2350_store_boot_internal(Rp2350StoreBootResult *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreBootWorkspace *);
void rp2350_store_boot_clear_internal(Rp2350StoreBootResult *);
#endif
