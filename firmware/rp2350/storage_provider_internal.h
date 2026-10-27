#ifndef RP2350_STORAGE_PROVIDER_INTERNAL_H
#define RP2350_STORAGE_PROVIDER_INTERNAL_H
#include "storage_mutation_internal.h"
#include "storage_compaction_internal.h"
#include "crypto_restore_internal.h"
#include "nonresident_seal_internal.h"
#include "authenticator/auth_nonresident_provider.h"
typedef struct {
    union {
        Rp2350StoreCheckpointWorkspace recovery;
        Rp2350StoreMutationWorkspace mutation;
        Rp2350StoreCompactionWorkspace compaction;
    } phase;
    uint8_t metadata[RP2350_STORE_METADATA_MAX],global[96],key[136],counter[48];
    uint8_t pending[RP2350_STORE_PLAIN_MAX]; /* Survives phase-union compaction. */
    Rp2350NonresidentSeal nonresident_seal;
    Rp2350NonresidentWorkspace nonresident;
    Rp2350Key nonresident_key;
} Rp2350StoreProviderWorkspace;
typedef struct {
    Rp2350Crypto *crypto;
    Rp2350Flash flash;
    Rp2350StoreBootConfig config;
    Rp2350StoreReplayState cache;
    Rp2350StoreMutationWriter writer;
    Rp2350StoreVersion version;
    Rp2350StoreProviderWorkspace *workspace;
    uint32_t journal_end;
    uint8_t selected_id[RP2350_NONRESIDENT_ID_SIZE],selected_rp[32];
    bool selected_nonresident;
    bool live,busy,staged;
} Rp2350StoreProvider;
/* Development profile 1/backend 0, used by native models and the board app.
 * Physical IO is injected; it does not provide a protected root, persistent
 * encryption-attempt reservation or production credential protection.
 * Caller owns zero-initialized
 * context/static workspace, one candidate crypto owner, disjoint buffers and
 * base primitive contexts; serialize all application calls. Config resolve/hash/
 * inspect must use BASE crypto, never this provider's gated service interfaces.
 * Recover validates roots/selector/full log, performs authenticated compaction
 * maintenance, checks the entire inactive bank and builds a compact authenticated
 * index. Full metadata and private records are loaded by selected frame only
 * when requested. Public keys are recomputed before use (P-256 uses blinding); working
 * keys and scratch are wiped at every callback exit. No repair
 * or provisioning of LOCKED/blank/RESETTING storage. All mutation errors revoke
 * live service and clear keys/cache. Cached metadata is valid only while this is
 * the sole serialized owner; external writes require close + fresh recover.
 * Key allocation commits the private record and handle high-water before output.
 * Reads reauthenticate root/selector authority and the selected frame against
 * the recovered index. Mutations stage typed semantics against that index;
 * append authenticates the existing journal/cursor and verifies the durable
 * new frame before publishing the staged index. Full replay remains mandatory
 * at recovery and after compaction, not for every record read or PIN write.
 * Preflight compacts before journal exhaustion, reserving two maximum frames
 * for a serialized creation. A durable unreferenced staging key prevents
 * compaction until its metadata is committed or the key is retired. Pending
 * transaction bytes survive phase-union maintenance; no uncertain append retry.
 * Index storage still scales with configured capacity; it is not an unbounded
 * external-storage implementation. Persistent record encodings are unchanged.
 * Key destruction scrubs retired/orphan copies via compaction before success;
 * this expensive path is NOT qualified for target callback timing/endurance.
 * Workspace is wiped after callbacks. API inputs/outputs must not alias provider
 * state/scratch. Core gains no format or private-key import/export API. */
AuthStatus rp2350_store_provider_recover_internal(Rp2350StoreProvider *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,Rp2350StoreProviderWorkspace *);
/* Same recovery with key service left locked, for a serialized Reset/startup
 * owner to initialize service/PIN storage and RNG. No requests may be accepted
 * until that owner activates crypto after all initialization succeeds. */
AuthStatus rp2350_store_provider_stage_internal(Rp2350StoreProvider *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,Rp2350StoreProviderWorkspace *);
void rp2350_store_provider_close_internal(Rp2350StoreProvider *);
AuthCrypto rp2350_store_provider_crypto_internal(Rp2350StoreProvider *);
AuthSecretCrypto rp2350_store_provider_secrets_internal(Rp2350StoreProvider *);
AuthStorage rp2350_store_provider_storage_internal(Rp2350StoreProvider *);
AuthPinStorage rp2350_store_provider_pin_internal(Rp2350StoreProvider *);
AuthNonresidentProvider rp2350_store_provider_nonresident_internal(Rp2350StoreProvider *);
#endif
