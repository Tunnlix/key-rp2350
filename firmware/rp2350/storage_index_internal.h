#ifndef RP2350_STORAGE_INDEX_INTERNAL_H
#define RP2350_STORAGE_INDEX_INTERNAL_H
#include "storage_codec.h"
/* Authenticated replay index, not a serialized format. Full RP/name strings and
 * private records stay in flash. Sequence identifies the original metadata
 * frame (offset/class/sequence are assigned by authenticated replay); counters
 * are folded separately. Digests cover canonical
 * metadata with counter zero, and with mutable user names additionally removed. */
typedef struct {
    uint8_t credential_id[32],rp_id_hash[32],user_id[64];
    AuthKeyHandle key;
    uint8_t content_digest[32],identity_digest[32];
    uint64_t sequence,creation_order;
    uint32_t signature_count;
    uint32_t offset;
    int32_t algorithm;
    uint16_t rp_id_length;
    uint16_t class_id;
    uint8_t user_id_length,cred_protect,user_name_length,user_display_name_length;
    bool discoverable;
} Rp2350StoreMetadataIndex;
AuthStatus rp2350_store_metadata_index_internal(Rp2350StoreMetadataIndex *,AuthCredential *,
    uint64_t,Rp2350StoreHash,void *,uint8_t *,size_t);
bool rp2350_store_metadata_index_equal_internal(const Rp2350StoreMetadataIndex *,const Rp2350StoreMetadataIndex *);
#endif
