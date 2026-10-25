#ifndef RP2350_STORAGE_RESET_FLOW_INTERNAL_H
#define RP2350_STORAGE_RESET_FLOW_INTERNAL_H
#include "storage_provision_internal.h"
#include "storage_provider_internal.h"
#include "crypto.h"
typedef struct {
    bool busy,locked,complete;
    AuthStatus status;
} Rp2350StoreResetFlow;
typedef struct {
    /* Consume a fresh application-approved Reset (core presence/window checks
     * still required). Recovery entry requires NEW physical recovery consent. */
    Rp2350StoreResetAuthorize authorize;
    /* Idempotently clear PIN tokens/permissions, assertions/enumerations,
     * application scratch and ALL cached store/root/private-key copies.
     * Credential crypto is already locked and wiped before this callback. */
    AuthStatus (*invalidate)(void *);
    /* Rebind/reinitialize storage, credential service and inactive PIN token
     * from freshly read empty state. Copy required metadata, retain no borrowed
     * snapshot pointer. Keys/agreement service stays locked until this returns
     * OK. Failure invokes invalidate again. Never publish external responses. */
    AuthStatus (*reinitialize)(void *,const Rp2350StoreReplayState *);
    void *context;
} Rp2350StoreResetHooks;
typedef struct {
    union {
        Rp2350StoreCheckpointWorkspace intent;
        Rp2350StoreResetWorkspace erase;
        Rp2350StoreProvisionWorkspace provision;
        /* Final boot starts only after provisioning has returned and wiped
         * its scratch. The snapshot and receipts remain outside this union. */
        Rp2350StoreBootWorkspace boot;
        /* Normal application provider scratch may share these completed
         * phases. invalidate closes the idle provider before phase IO;
         * reinitialize uses this member only after final boot has returned.
         * No snapshot/receipt/provider context may overlap this union. */
        Rp2350StoreProviderWorkspace provider;
    } phase;
    Rp2350StoreSelection selection;
    Rp2350StoreResetErasure erased;
    Rp2350StoreProvisioned provisioned;
    Rp2350StoreBootResult snapshot;
} Rp2350StoreResetFlowWorkspace;
/* Model profile 1 only; zero-initialize state, static workspace disjoint from
 * state and provider objects. Hook-owned provider scratch may be exactly
 * phase.provider; all other hook-owned storage remains disjoint. Authorization
 * must not depend on scratch, invalidate closes the idle provider before phase
 * IO, and reinitialize may reuse phase.provider after final boot returns. It
 * must consume/copy snapshot values without retaining a pointer. Serialize calls.
 * Caller must gate its main loop on
 * locked/complete AND crypto/PIN/provider health. No physical binding exists.
 * Authorize once -> lock/wipe crypto + invalidate RAM -> durable intent ->
 * verified erasure -> explicit fresh provisioning -> fresh empty boot -> stage
 * new agreement/handle epoch -> reinitialize services -> enable key operations.
 * No phase receipt is authority for the next phase; all readers revalidate.
 * Reentrant calls return BUSY without disturbing the outer operation. After
 * any post-authorization error, wipe keys/RAM again and remain locked. A new
 * epoch may already be durable despite failure; never automatically recover.
 * This is not a final provider binding or proof of physical consent/durability.
 * Preserve core Reset window/presence checks when binding a CTAP callback.
 * Backend PIN reset may subsequently fail; its failure must keep service off.
 * Workspace clears on all non-reentrant exits. */
AuthStatus rp2350_store_reset_flow_internal(Rp2350StoreResetFlow *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,const Rp2350StoreResetHooks *,Rp2350StoreResetFlowWorkspace *);
/* Separate NEW authorized recovery operation. Erases without trusting old
 * authority, then follows the same provisioning/runtime publication checks.
 * Never used as automatic fallback by the normal flow. */
AuthStatus rp2350_store_reset_recovery_flow_internal(Rp2350StoreResetFlow *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350Crypto *,const Rp2350StoreResetHooks *,Rp2350StoreResetFlowWorkspace *);
#endif
