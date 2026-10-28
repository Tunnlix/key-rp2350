#ifndef RP2350_STORAGE_PROVIDER_INTERNAL_H
#define RP2350_STORAGE_PROVIDER_INTERNAL_H
#include "storage_version_internal.h"
#include "storage_compaction_internal.h"
#include "crypto_restore_internal.h"
#include "nonresident_seal_internal.h"
#include "authenticator/auth_nonresident_provider.h"
typedef struct {
    Rp2350StoreBootResult source;
    Rp2350StoreBootWorkspace boot;
    Rp2350StoreLog log;
} Rp2350StoreCommitWorkspace;
typedef struct {
    union {
        Rp2350StoreCheckpointWorkspace recovery;
        Rp2350StoreCommitWorkspace mutation;
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
    Rp2350StoreVersion version;
    Rp2350StoreProviderWorkspace *workspace;
    uint32_t journal_end;
    AuthStatus failure; /* First terminal provider error; no credential data. */
    uint8_t selected_id[RP2350_NONRESIDENT_ID_SIZE],selected_rp[32];
    bool selected_nonresident;
    bool live,busy,staged,read_only;
} Rp2350StoreProvider;
/* Single serialized writer with caller-owned, disjoint contexts/workspace.
 * Config primitives must use base crypto, never the gated provider callbacks.
 * Recovery validates authority and the complete log, cleans orphan/retired keys
 * and builds a compact index. External writes require close + fresh recovery.
 * Reads authenticate current authority and the indexed frame. Private working
 * keys and used scratch are wiped on callback exit. Mutations validate typed
 * state against the exclusively owned recovered index, then verify the new
 * frame before publishing; external writes invalidate this ownership.
 * Any mutation failure revokes service; never retry an uncertain append.
 * Creation reserves journal space before staging an unreferenced key. Pending
 * transaction bytes survive phase-union compaction. Key destruction completes
 * verified compaction/scrubbing before success. Record encodings are unchanged.
 * This onboard provider uses the security scope described in SECURITY.md. */
AuthStatus rp2350_store_provider_recover_internal(Rp2350StoreProvider *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,Rp2350StoreProviderWorkspace *);
/* Same recovery with key service left locked, for a serialized Reset/startup
 * owner to initialize service/PIN storage and RNG. No requests may be accepted
 * until that owner activates crypto after all initialization succeeds. */
AuthStatus rp2350_store_provider_stage_internal(Rp2350StoreProvider *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,Rp2350StoreProviderWorkspace *);
/* A/B trial only: authenticate selected records without erasing an inactive
 * bank or cleaning retired keys. Mutations stay disabled until maintenance
 * completes after ROM confirms the image and the board unlocks flash writes. */
AuthStatus rp2350_store_provider_trial_internal(Rp2350StoreProvider *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,Rp2350StoreProviderWorkspace *);
AuthStatus rp2350_store_provider_finish_trial_internal(Rp2350StoreProvider *);
void rp2350_store_provider_close_internal(Rp2350StoreProvider *);
AuthCrypto rp2350_store_provider_crypto_internal(Rp2350StoreProvider *);
AuthSecretCrypto rp2350_store_provider_secrets_internal(Rp2350StoreProvider *);
AuthStorage rp2350_store_provider_storage_internal(Rp2350StoreProvider *);
AuthPinStorage rp2350_store_provider_pin_internal(Rp2350StoreProvider *);
AuthNonresidentProvider rp2350_store_provider_nonresident_internal(Rp2350StoreProvider *);
#endif
