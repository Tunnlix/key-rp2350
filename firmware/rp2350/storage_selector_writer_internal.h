#ifndef RP2350_STORAGE_SELECTOR_WRITER_INTERNAL_H
#define RP2350_STORAGE_SELECTOR_WRITER_INTERNAL_H
#include "storage_checkpoint_writer_internal.h"
/* Disposable-development/model-only. Caller freezes all mutations throughout.
 * Revalidate current boot authority, target checkpoint and canonical live state
 * INCLUDING provider-private key bytes before using a candidate. Append only
 * beside current authority. If full, erase the OTHER safe sector, verify blank,
 * copy/read-validate the current anchor there, then append the new SWITCH.
 * Never erase the sole current selector; never touch roots or data arenas.
 * Success requires complete boot recovery through the new selection.
 * Failure can follow a completed commit: latch the application into recovery;
 * do not retry from cached authority. Incomplete final records retire append
 * space; a separately validated retained authority can re-anchor a damaged
 * stale sector through selector_repair_internal.
 * Static workspace and all inputs/contexts disjoint. Wiped on every exit.
 * Output clears on failure. No physical binding/protected-root support or
 * durable encryption-attempt reservation; not a production writer. */
AuthStatus rp2350_store_selector_commit_internal(Rp2350StoreSelection *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,const Rp2350StoreCheckpointCandidate *,Rp2350StoreCheckpointWorkspace *);
/* Re-anchor a damaged/non-current sector only after full boot validation of
 * the retained selector and its selected arena. Never repair an unusable
 * selected checkpoint or erase the sector retaining current authority. */
AuthStatus rp2350_store_selector_repair_internal(const Rp2350Flash *,const Rp2350StoreBootConfig *,Rp2350StoreCheckpointWorkspace *);
/* The application callback must consume an already approved core Reset
 * (presence/startup window intact), invalidate tokens, enumeration/assertion
 * state and cached keys, and latch credential service off before returning OK.
 * No IO occurs before it returns OK; denial never writes. Keep service off on
 * EVERY later failure and until a separate complete Reset succeeds. This is
 * a caller contract, not a physical authorization implementation.
 * Uses the same model-only limits as SWITCH. Requires recoverable current
 * authority (or an already verified intent); does not repair LOCKED media.
 * Success means durable RESETTING, never completed Reset or permission to serve.
 * No roots/arenas are erased or provisioned. Existing intent is idempotent after
 * fresh authorization/boot verification; failures may follow a durable commit.
 * No interleaved mutation, aliasing or reentry; workspace wiped on every exit. */
typedef AuthStatus (*Rp2350StoreResetAuthorize)(void *context);
AuthStatus rp2350_store_reset_intent_internal(Rp2350StoreSelection *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreResetAuthorize,void *,Rp2350StoreCheckpointWorkspace *);
#endif
