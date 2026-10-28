#ifndef RP2350_STORAGE_LOG_INTERNAL_H
#define RP2350_STORAGE_LOG_INTERNAL_H
#include "flash.h"
#include "storage_seal_internal.h"
/* Authenticated bounded append/replay mechanism. The caller supplies a TRUSTED
 * selected arena/epoch/generation; this layer is NOT an arena selector, metadata
 * store or production recovery policy. No hardware callback is installed. */
typedef struct {
    uint8_t frame[4096],plain[3584],page[256]; Rp2350StoreSealWorkspace seal;
} Rp2350StoreLogWorkspace;
typedef struct {
    Rp2350Flash flash; Rp2350StoreSeal *crypto;
    uint32_t base,size,end; uint64_t generation,next_sequence;
    uint8_t epoch[16]; bool selectors,initialized,faulted,interrupted;
} Rp2350StoreLog;
typedef AuthStatus (*Rp2350StoreReplay)(void *,const Rp2350StoreIdentity *,const Rp2350StoreTransaction *);
/* Digest is the authenticated commit's body digest, borrowed only for the
 * callback duration. Never expose an unverified frame digest to recovery. */
typedef AuthStatus (*Rp2350StoreFrameReplay)(void *,const Rp2350StoreIdentity *,const Rp2350StoreTransaction *,const uint8_t[32]);
/* Open authenticates each frame before replay into caller-owned staging.
 * Callbacks MUST NOT perform IO or publish state. Discard staging if open or
 * any callback fails, including errors after the last callback. Successful
 * open alone is not READY: cross-record semantics, root and
 * selector/checkpoint authority are enforced by the next coordinator layer.
 * Blank explicit regions may be appended after open; NOT_FOUND never means a
 * provisioned authenticator has an unset PIN. Open requires only read; append
 * without program_page returns UNSUPPORTED. No erase is performed by this log.
 * Workspace is wiped on every exit. */
AuthStatus rp2350_store_log_open_internal(Rp2350StoreLog *,const Rp2350Flash *,Rp2350StoreSeal *,
    uint32_t,uint32_t,uint64_t,const uint8_t[16],Rp2350StoreReplay,void *,Rp2350StoreLogWorkspace *);
AuthStatus rp2350_store_log_open_frames_internal(Rp2350StoreLog *,const Rp2350Flash *,Rp2350StoreSeal *,
    uint32_t,uint32_t,uint64_t,const uint8_t[16],Rp2350StoreFrameReplay,void *,Rp2350StoreLogWorkspace *);
AuthStatus rp2350_store_log_append_internal(Rp2350StoreLog *,uint16_t,const uint8_t *,size_t,Rp2350StoreLogWorkspace *);
/* Live exclusive provider only: recovery authenticated the entire prefix and
 * blank tail, and every subsequent append was verified before publication.
 * Check the new extent is erased rather than rescanning that trusted prefix.
 * External writes invalidate this ownership: close and recover before use.
 * The new transaction and its readback still receive full validation. */
AuthStatus rp2350_store_log_append_verified_internal(Rp2350StoreLog *,uint16_t,const uint8_t *,size_t,Rp2350StoreLogWorkspace *);
/* Checkpoint staging ONLY: caller has opened the completely blank inactive
 * arena and owns this cursor and all writes until staging ends. Accepts only
 * checkpoint/manifest classes 2/3. Verifies the new extent is erased, every
 * programmed page and the authenticated frame; does not rescan the prefix.
 * Caller MUST fully replay/audit the finished bank before publishing a SWITCH.
 * A failed writer cannot be resumed: erase/rebuild through checkpoint staging.
 * Normal mutation/selector writers must use the full-scan append above. */
AuthStatus rp2350_store_log_append_checkpoint_internal(Rp2350StoreLog *,uint16_t,const uint8_t *,size_t,Rp2350StoreLogWorkspace *);
#endif
