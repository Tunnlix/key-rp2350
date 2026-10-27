#include "storage_key_record_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static bool scalar_valid(const uint8_t scalar[32]) {
    static const uint8_t order[32]={
        0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
    /* Fixed-length subtraction; no early exit based on scalar prefix. */
    unsigned borrow=0;
    for(size_t i=32;i>0;i--) {
        unsigned difference=(unsigned)scalar[i-1]-(unsigned)order[i-1]-borrow;
        borrow=(difference>>8)&1U;
    }
    return store_nonzero(scalar,32) && borrow!=0;
}
AuthStatus rp2350_key_record_encode_internal(const Rp2350Key *key,uint8_t out[136]) {
    if(!key || !out) return AUTH_INVALID_ARGUMENT;
    if(!auth_key_handle_valid(&key->handle) || !auth_algorithm_valid(key->algorithm) ||
        (key->algorithm==AUTH_COSE_ALG_ES256 && !scalar_valid(key->scalar))) return AUTH_BAD_DATA;
    memset(out,0,136); store_put16(out,1); store_put32(out+4,key->algorithm==AUTH_COSE_ALG_ES256 ? 1U : 2U);
    memcpy(out+8,key->handle.bytes,32); memcpy(out+40,key->scalar,32); memcpy(out+72,key->randoms,64);
    return AUTH_OK;
}
AuthStatus rp2350_key_record_decode_internal(const uint8_t *in,size_t n,Rp2350Key *key) {
    if(!key) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(key,sizeof(*key)); if(!in) return AUTH_INVALID_ARGUMENT;
    if(n!=136 || store_u16(in)!=1 || store_u16(in+2) || (store_u32(in+4)!=1 && store_u32(in+4)!=2) ||
        !store_nonzero(in+8,32) || (store_u32(in+4)==1 && !scalar_valid(in+40))) return AUTH_BAD_DATA;
    key->algorithm=store_u32(in+4)==1 ? AUTH_COSE_ALG_ES256 : AUTH_COSE_ALG_EDDSA;
    memcpy(key->handle.bytes,in+8,32); memcpy(key->scalar,in+40,32); memcpy(key->randoms,in+72,64);
    /* Deliberately not used/live: caller must derive and validate public key. */
    return AUTH_OK;
}
