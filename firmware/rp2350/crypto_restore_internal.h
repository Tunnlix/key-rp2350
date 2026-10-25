#ifndef RP2350_CRYPTO_RESTORE_INTERNAL_H
#define RP2350_CRYPTO_RESTORE_INTERNAL_H
#include "crypto.h"
/* Provider-private authenticated-record restoration, not a core import/export
 * interface. Caller must authenticate all root/selector/checkpoint/mutation
 * state, remove orphan/retired copies and stage its handle prefix/high-water
 * before this batch. Serialized, all buffers/contexts disjoint. Decode scalar
 * and randoms privately, validate handle allocation, recompute the public point
 * with blinded P-256 multiplication, reject duplicate handles. Any error wipes
 * the ENTIRE staged provider (including agreement material); no partial batch
 * can be activated. Success stays key-locked. Activate only after complete
 * metadata/key cross-checks and runtime initialization. Model/development format
 * 1 only; protected providers may use a different private restoration scheme. */
AuthStatus rp2350_crypto_restore_records_internal(Rp2350Crypto *,const uint8_t (*)[136],size_t);
#endif
