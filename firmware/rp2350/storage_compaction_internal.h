#ifndef RP2350_STORAGE_COMPACTION_INTERNAL_H
#define RP2350_STORAGE_COMPACTION_INTERNAL_H
#include "storage_selector_writer_internal.h"
typedef struct {
    Rp2350StoreSelection selection;
    bool inactive_dirty,active_key_cleanup,clean;
} Rp2350StoreMaintenance;
typedef struct {
    Rp2350StoreCheckpointWorkspace scratch;
    Rp2350StoreCheckpointCandidate candidate;
    Rp2350StoreSelection committed;
    Rp2350StoreMaintenance audit;
} Rp2350StoreCompactionWorkspace;
/* All objects/provider contexts disjoint and serialized. Caller freezes all
 * mutations through audit/compaction/resume. Static caller-owned workspace.
 * Read-only audit: boot RECOVERED is only a snapshot. Before any future READY
 * transition, require this additional gate: no orphan/retired active keys AND
 * the entire inactive arena erased. RESETTING/LOCKED never permits cleanup.
 * No state here activates providers, authorizes provisioning or completes Reset. */
AuthStatus rp2350_store_maintenance_internal(Rp2350StoreMaintenance *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreCompactionWorkspace *);
/* Development/model profile 1 only. Stage -> SWITCH/read-recover -> scrub only
 * the freshly validated inactive arena -> revalidate authority and erased bank.
 * No roots/selectors are erased by the scrub. Old key copies are not considered
 * removed until clean success. No production attempt reservation/physical I/O.
 * Errors clear output/scratch; a new switch may already be durable. Recover
 * before further writes, never fall back or resume from cached receipts. */
AuthStatus rp2350_store_compact_internal(Rp2350StoreMaintenance *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreCompactionWorkspace *);
/* Re-derive current authority from flash. If active keys need cleanup, restart
 * full compaction; otherwise scrub only the inactive arena. An uncommitted
 * standby may be discarded. Already clean storage needs no writes. Torn
 * root/selector/selected data locks; no automatic repair is attempted. */
AuthStatus rp2350_store_compaction_resume_internal(Rp2350StoreMaintenance *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreCompactionWorkspace *);
#endif
