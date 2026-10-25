#ifndef RP2350_STORAGE_MUTATION_INTERNAL_H
#define RP2350_STORAGE_MUTATION_INTERNAL_H
#include "storage_boot_internal.h"
typedef struct {
    uint8_t epoch[16];
    uint64_t root_serial,selector_serial,generation,logical_sequence;
} Rp2350StoreVersion;
typedef struct { bool busy,locked; } Rp2350StoreMutationWriter;
typedef struct { Rp2350StoreVersion version; bool verified,maintenance; } Rp2350StoreMutationReceipt;
typedef struct {
    Rp2350StoreBootResult source,after;
    Rp2350StoreReplayState expected;
    Rp2350StoreBootWorkspace boot;
    Rp2350StoreLog log;
    uint8_t plain[RP2350_STORE_PLAIN_MAX],left[RP2350_STORE_METADATA_MAX],right[RP2350_STORE_METADATA_MAX];
} Rp2350StoreMutationWorkspace;
/* Development profile 1 over injected model or verified physical IO. No
 * production attempt reservation. Objects/contexts disjoint, static workspace, serialize all
 * mutations. Open freshly authenticates authority/state and returns a version;
 * MAINTENANCE is not permission to serve credentials. No key activation here.
 * Commit requires that exact version, validates typed transaction semantics
 * BEFORE writing, appends ONLY to the selected arena, then fully boot-recovers
 * and compares canonical expected state before acknowledging the mutation.
 * No erase/compaction/fallback/provisioning. Caller-private key payloads stay
 * outside the portable core. Freeze their buffers through the entire call.
 * Any non-reentrant error locks the writer and clears receipt/scratch; a commit
 * may already be durable. Recover afresh before retrying; never roll back an
 * acknowledged PIN retry/counter transition. Busy calls leave active objects
 * untouched. Open cannot repair torn media. */
AuthStatus rp2350_store_mutation_open_internal(Rp2350StoreMutationWriter *,Rp2350StoreMutationReceipt *,
    const Rp2350Flash *,const Rp2350StoreBootConfig *,Rp2350StoreMutationWorkspace *);
AuthStatus rp2350_store_mutation_commit_internal(Rp2350StoreMutationWriter *,Rp2350StoreMutationReceipt *,
    const Rp2350Flash *,const Rp2350StoreBootConfig *,const Rp2350StoreVersion *,
    const Rp2350StoreTransaction *,Rp2350StoreMutationWorkspace *);
#endif
