#ifndef RP2350_STORAGE_CHECKPOINT_WRITER_INTERNAL_H
#define RP2350_STORAGE_CHECKPOINT_WRITER_INTERNAL_H
#include "storage_record_reader_internal.h"
/* Development-profile checkpoint staging over caller-supplied flash IO.
 * No production root or persistent encryption-attempt reservation is supplied.
 * Re-read current authority/state and authenticated provider-private records;
 * never export private keys through the portable core or trust cached counters.
 * Caller freezes all mutations for this entire serialized operation. */
typedef struct {
    Rp2350StoreSelector proposed_switch;
    uint64_t root_serial;
    uint32_t arena_base,bytes;
    bool verified;
} Rp2350StoreCheckpointCandidate;
typedef struct {
    Rp2350StoreBootResult source;
    Rp2350StoreBootWorkspace boot;
    Rp2350StoreLog target;
    Rp2350StoreRecordWorkspace reader;
    uint8_t data[RP2350_STORE_METADATA_MAX],compare[RP2350_STORE_METADATA_MAX],plain[3584];
    uint8_t ordered[24U+(2U*AUTH_RESIDENT_MAX_COUNT+2U)*32U];
    size_t items;
} Rp2350StoreCheckpointWorkspace;
/* Requires explicit development profile 1/backend 0 and verified read/program/
 * erase callbacks. All buffers/contexts disjoint, caller-owned static RAM.
 * Authenticates current boot state, validates referenced encoded key records
 * one at a time, then erases/read-verifies ONLY the opposite arena.
 * Writes a folded checkpoint, verifies full replay and compares canonical
 * state before returning a proposed SWITCH. Orphan/retired keys are omitted;
 * their old copies remain and deletion/compaction is NOT complete.
 * No selector/root/active-arena write, authority switch or provisioning occurs.
 * Failure clears candidate and all scratch; the active authority stays intact.
 * A failed target must be erased/rebuilt, never appended/retried in place.
 * A later selector writer must revalidate current authority before using this
 * candidate. Real flash, attempt budgeting, timing/wear and Reset are unqualified. */
AuthStatus rp2350_store_checkpoint_stage_internal(Rp2350StoreCheckpointCandidate *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreCheckpointWorkspace *);
/* Shared private validation for a later selector writer. Workspace source is
 * a freshly recovered active index. compare=false validates selected private
 * records; true checks target record digests against the source and loads each
 * target record independently. Never caches all private payloads. */
AuthStatus rp2350_store_checkpoint_keys_internal(Rp2350StoreCheckpointWorkspace *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,const Rp2350StoreSelection *,bool);
AuthStatus rp2350_store_checkpoint_matches_internal(Rp2350StoreCheckpointWorkspace *,const Rp2350StoreBootConfig *);
#endif
