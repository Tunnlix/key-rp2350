#ifndef RP2350_STORAGE_REPLAY_INTERNAL_H
#define RP2350_STORAGE_REPLAY_INTERNAL_H
#include "storage_log_internal.h"
#include "storage_index_internal.h"
/* Development checkpoint/mutation replay for an already selected arena/root.
 * This is NOT root/selector authority or a live
 * provider. Only opaque handles are retained here; key payload validation stays
 * inside the provider. No public-key activation or durable writes occur.
 * All objects/buffers must be disjoint, caller-owned and serialized. */
typedef struct { AuthKeyHandle handle; bool retired; uint64_t sequence; uint8_t digest[32]; uint32_t offset; uint16_t class_id; } Rp2350StoreReplayKey;
typedef struct {
    Rp2350StoreGlobal global;
    AuthPinRecord pin;
    Rp2350StoreMetadataIndex metadata[AUTH_RESIDENT_MAX_COUNT];
    Rp2350StoreReplayKey keys[AUTH_RESIDENT_MAX_COUNT+1U];
    size_t metadata_count,key_count;
    uint64_t last_sequence; /* Physical envelope sequence in this generation. */
    uint64_t logical_sequence; /* Prior manifest high-water plus mutations. */
} Rp2350StoreReplayState;
/* Validate a provider-private record and return only its opaque handle.
 * Must not publish keys or mutate a live provider. Wipe private decode scratch. */
typedef AuthStatus (*Rp2350StoreKeyInspect)(void *,const uint8_t *,size_t,AuthKeyHandle *);
typedef struct {
    Rp2350StoreReplayState staged,candidate;
    AuthCredential decoded;
    Rp2350StoreMetadataIndex indexed;
    uint8_t canonical[RP2350_STORE_METADATA_MAX];
    Rp2350StoreHash hash; Rp2350StoreKeyInspect key_inspect; void *context;
    uint64_t generation; uint8_t epoch[16];
    uint64_t reset_generation;
    uint8_t manifest_digest[32],global_digest[32];
    uint8_t checkpoint_digests[24U+(2U*AUTH_RESIDENT_MAX_COUNT+3U)*32U];
    size_t checkpoint_items;
    bool active,faulted,verified,checkpoint_mode,checkpoint_ready,have_global,have_pin;
} Rp2350StoreRecovery;
/* Explicit trusted baseline includes a valid global AND PIN record, even when
 * unset. Blank/NOT_FOUND storage must never be passed as a provisioned baseline.
 * Full checkpoint digest/root selection remains the caller's responsibility. */
AuthStatus rp2350_store_recovery_begin(Rp2350StoreRecovery *,const Rp2350StoreReplayState *,
    uint64_t,const uint8_t[16],Rp2350StoreHash,Rp2350StoreKeyInspect,void *);
/* Expected manifest commit body digest, reset generation, generation and epoch
 * must come from independently authenticated selector/root authority. Do not
 * adopt them from the arena being loaded. No missing-PIN/global defaults. */
AuthStatus rp2350_store_recovery_checkpoint_begin(Rp2350StoreRecovery *,uint64_t,const uint8_t[16],
    uint64_t,const uint8_t[32],Rp2350StoreHash,Rp2350StoreKeyInspect,void *);
/* Signature matches the log replay callback. Any failure wipes staging and
 * latches the recovery context; no previously published state is modified. */
AuthStatus rp2350_store_recovery_apply(void *,const Rp2350StoreIdentity *,const Rp2350StoreTransaction *);
/* Mutation-only development log over a trusted baseline at sequence zero.
 * Or, after checkpoint_begin, a complete checkpoint prefix/manifest followed by
 * mutations, bound to independently supplied expected manifest identity. Wraps
 * log open so even late read failures destroy staging. Sets verified only on
 * full success; blank logs are NOT_FOUND and cannot publish an unset PIN.
 * Call exactly once after begin and before finish. */
AuthStatus rp2350_store_recovery_read_log(Rp2350StoreRecovery *,Rp2350StoreLog *,
    const Rp2350Flash *,Rp2350StoreSeal *,uint32_t,uint32_t,Rp2350StoreLogWorkspace *);
/* Only read_log's full success permits finish. Copies the
 * staged result once, then wipes recovery. Orphan/retired keys set maintenance;
 * this result must not become a serving provider until cleanup is complete.
 * Failure leaves the output and maintenance flag unchanged. */
AuthStatus rp2350_store_recovery_finish(Rp2350StoreRecovery *,Rp2350StoreReplayState *,bool *);
void rp2350_store_recovery_abort(Rp2350StoreRecovery *);
#endif
