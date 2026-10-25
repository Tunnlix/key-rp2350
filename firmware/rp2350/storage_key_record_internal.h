#ifndef RP2350_STORAGE_KEY_RECORD_INTERNAL_H
#define RP2350_STORAGE_KEY_RECORD_INTERNAL_H
#include "crypto.h"
/* PROVIDER PRIVATE. Only authenticated storage owned by the software provider
 * may call these codecs. No new AuthCrypto import/export capability. The
 * restore caller must recompute/check the public point before making a key live.
 * Buffers may not overlap. Failed decode clears the complete destination key. */
AuthStatus rp2350_key_record_encode_internal(const Rp2350Key *,uint8_t[136]);
AuthStatus rp2350_key_record_decode_internal(const uint8_t *,size_t,Rp2350Key *);
#endif
