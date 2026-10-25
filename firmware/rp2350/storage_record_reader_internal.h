#ifndef RP2350_STORAGE_RECORD_READER_INTERNAL_H
#define RP2350_STORAGE_RECORD_READER_INTERNAL_H
#include "storage_boot_internal.h"
typedef struct {
    AuthCredential credential;
    Rp2350StoreMetadataIndex index;
    uint8_t key[136],canonical[RP2350_STORE_METADATA_MAX];
} Rp2350StoreRecordWorkspace;
/* Read one record selected by an authenticated recovered index. Caller first
 * authenticates current authority/full replay and freezes mutations. Verify
 * physical offset, generation, sequence, class, authentication and content digest
 * before publishing scratch. No unverified pointer becomes a record lookup.
 * No raw offset or unauthenticated entry may select credential material.
 * Exactly one of metadata/key is required. All inputs/scratch are disjoint and
 * serialized. Caller wipes successful scratch; errors wipe it before return. */
AuthStatus rp2350_store_record_read_internal(Rp2350StoreRecordWorkspace *,const Rp2350Flash *,
    const Rp2350StoreBootConfig *,Rp2350StoreSeal *,const Rp2350StoreSelection *,
    const Rp2350StoreMetadataIndex *,const Rp2350StoreReplayKey *,Rp2350StoreLogWorkspace *);
#endif
