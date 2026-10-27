#ifndef RP2350_FLASH_GUARD_H
#define RP2350_FLASH_GUARD_H
#include "flash.h"
#include "authenticator/auth_secret_crypto.h"
#define RP2350_BLOB_FLASH_OFFSET 0x178000U
#define RP2350_BLOB_FLASH_BYTES 0x8000U
#define RP2350_STORE_FLASH_OFFSET 0x180000U
#define RP2350_STORE_FLASH_BYTES 0x80000U
/* Disposable-development partition adapter. Raw offsets are device-relative;
 * exposed Rp2350Flash offsets are partition-relative. No identity discovery or
 * production permission is implied. Caller must verify hardware before init,
 * supply static SRAM state, serialize access, and keep buffers disjoint from
 * this context. write_bytes=0 opens read-only. Other write windows must be
 * sector-aligned and wholly inside the reserved partition. No automatic erase,
 * retry or repair; a failed physical/readback operation latches the adapter. */
typedef struct {
    Rp2350Flash raw;
    uint32_t base,bytes,write_offset,write_bytes;
    bool initialized,busy,faulted;
    uint8_t staged[256],verify[256];
} Rp2350FlashGuard;
AuthStatus rp2350_flash_guard_init(Rp2350FlashGuard *,const Rp2350Flash *,uint32_t write_offset,uint32_t write_bytes);
/* Only the fixed firmware-reserved blob/store regions may be opened. */
AuthStatus rp2350_flash_guard_init_blobs(Rp2350FlashGuard *,const Rp2350Flash *,bool writes);
Rp2350Flash rp2350_flash_guard_interface(Rp2350FlashGuard *);
#endif
