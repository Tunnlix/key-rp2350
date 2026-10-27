#ifndef RP2350_BLOB_STORE_H
#define RP2350_BLOB_STORE_H
#include "flash.h"
#include "ctap/ctap_large_blobs.h"
/* Four rotating 8 KiB banks in a dedicated 32 KiB partition. The header page
 * is programmed last. A torn replacement cannot overwrite the current bank.
 * Client encryption protects array contents; these headers add crash/integrity
 * checks, not protection against physical flash rollback. Epoch is the durable
 * credential reset generation together with its random store identity. No cached array or heap allocation. */
typedef struct {
    Rp2350Flash flash;
    uint64_t epoch, sequence;
    uint32_t active_bank;
    size_t length;
    bool initialized, faulted;
    uint8_t page[256], store_id[16];
} Rp2350BlobStore;
AuthStatus rp2350_blob_store_open(Rp2350BlobStore *, const Rp2350Flash *, uint64_t reset_generation, const uint8_t store_id[16]);
CtapLargeBlobStorage rp2350_blob_store_interface(Rp2350BlobStore *);
#endif
