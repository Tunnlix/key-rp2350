#ifndef RP2350_STORAGE_SEAL_INTERNAL_H
#define RP2350_STORAGE_SEAL_INTERNAL_H
#include "storage_codec.h"
#include "authenticator/auth_secret_crypto.h"
/* Provider-private development storage crypto. No persistent root backend or
 * private-key import/export is added to the core. One borrowed, initialized
 * candidate crypto provider owns primitives/RNG; all calls remain serialized. */
typedef struct {
    AuthCrypto crypto; AuthSecretCrypto secrets;
    uint8_t enc[32],mac[32],commit[32],root_auth[32],epoch[16];
    bool initialized,faulted;
} Rp2350StoreSeal;
typedef struct { uint8_t mac_input[4096]; } Rp2350StoreSealWorkspace;
/* offset is runtime-only provenance assigned after authenticated log replay;
 * it is not an extra field in the persistent envelope. */
typedef struct { uint16_t class_id; uint64_t sequence,generation; uint8_t epoch[16]; uint32_t offset; } Rp2350StoreIdentity;
/* Root is supplied only by the owning provider/test fixture. It is not retained
 * after deriving separated keys. All buffers, contexts and workspace disjoint. */
AuthStatus rp2350_store_seal_init_internal(Rp2350StoreSeal *,const AuthCrypto *,const AuthSecretCrypto *,const uint8_t[32],const uint8_t[16]);
void rp2350_store_seal_free_internal(Rp2350StoreSeal *);
AuthStatus rp2350_store_frame_extent(size_t,size_t *);
AuthStatus rp2350_store_frame_inspect(const uint8_t *,size_t,Rp2350StoreIdentity *,size_t *,size_t *);
AuthStatus rp2350_store_seal_internal(Rp2350StoreSeal *,const Rp2350StoreIdentity *,uint32_t,
    const uint8_t *,size_t,uint8_t *,size_t,size_t *,Rp2350StoreSealWorkspace *);
/* Expected identity/physical offset are trusted caller inputs, NOT adopted from
 * the envelope. All errors clear plaintext/length; auth/decode errors latch a
 * fault. No decryption before both tags and commit/body binding are verified. */
AuthStatus rp2350_store_open_internal(Rp2350StoreSeal *,const Rp2350StoreIdentity *,uint32_t,
    const uint8_t *,size_t,uint8_t *,size_t,size_t *,Rp2350StoreSealWorkspace *);
/* Recheck envelope/commit integrity without decrypting a previously replayed
 * frame. Does not validate plaintext padding or transaction semantics. */
AuthStatus rp2350_store_verify_internal(Rp2350StoreSeal *,const Rp2350StoreIdentity *,uint32_t,
    const uint8_t *,size_t,size_t *,Rp2350StoreSealWorkspace *);
#endif
