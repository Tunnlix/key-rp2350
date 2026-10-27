#include "crypto.h"
#include "crypto_restore_internal.h"
#include "storage_key_record_internal.h"
#include "ctaes.h"
#include "monocypher-ed25519.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/sha256.h"
#include <stdalign.h>
#include <string.h>
static alignas(max_align_t) uint8_t crypto_pool[RP2350_CRYPTO_POOL_SIZE];
static Rp2350Crypto *owner;
static bool ready(const Rp2350Crypto *p) { return p && owner==p && p->initialized && !p->faulted; }
static int rng(void *ctx, unsigned char *out, size_t n) {
    Rp2350Crypto *p=ctx;
    if (!ready(p)) {
        auth_secure_zero(out,n);
        return MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED;
    }
    int rc=mbedtls_hmac_drbg_random(&p->drbg,out,n);
    if (rc) { auth_secure_zero(out,n); p->faulted=true; }
    return rc;
}
static AuthStatus random_bytes(void *ctx,uint8_t *out,size_t n) {
    if (!out || n==0 || n>MBEDTLS_HMAC_DRBG_MAX_REQUEST) return AUTH_INVALID_ARGUMENT;
    return rng(ctx,out,n)==0 ? AUTH_OK : AUTH_CRYPTO_ERROR;
}
static AuthStatus hash(void *ctx,const uint8_t *in,size_t n,uint8_t out[32]) {
    (void)ctx;
    if (!out || (!in && n)) return AUTH_INVALID_ARGUMENT;
    if (mbedtls_sha256(in,n,out,0)) { auth_secure_zero(out,32); return AUTH_CRYPTO_ERROR; }
    return AUTH_OK;
}
static AuthStatus mac(void *ctx,const uint8_t *key,size_t kn,const uint8_t *in,size_t n,uint8_t out[32]) {
    if (!out || !key || !kn || (!in && n)) return AUTH_INVALID_ARGUMENT;
    if (!ready(ctx)) { auth_secure_zero(out,32); return AUTH_CRYPTO_ERROR; }
    int rc=mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),key,kn,in,n,out);
    if (rc) auth_secure_zero(out,32);
    return rc ? AUTH_CRYPTO_ERROR : AUTH_OK;
}
static AuthStatus aes(void *ctx,bool encrypt,const uint8_t key[32],const uint8_t iv[16],
        const uint8_t *in,size_t n,uint8_t *out) {
    if (!key || !iv || !in || !out || (n!=16 && n!=32 && n!=64)) return AUTH_INVALID_ARGUMENT;
    if (!ready(ctx)) { auth_secure_zero(out,n); return AUTH_CRYPTO_ERROR; }
    /* Own and wipe CBC intermediates: upstream's CBC helper keeps unwiped
     * plaintext/chaining scratch. Its AES block primitive remains unchanged.
     * Save ciphertext before writing for exact in-place decryption. */
    AES256_ctx c;
    uint8_t chain[16],block[16],next[16]={0};
    AES256_init(&c,key); memcpy(chain,iv,sizeof(chain));
    for (size_t offset=0;offset<n;offset+=16U) {
        if (encrypt) {
            for (size_t j=0;j<16U;j++) block[j]=in[offset+j]^chain[j];
            AES256_encrypt(&c,1,out+offset,block);
            memcpy(chain,out+offset,sizeof(chain));
        } else {
            memcpy(next,in+offset,sizeof(next));
            AES256_decrypt(&c,1,block,in+offset);
            for (size_t j=0;j<16U;j++) out[offset+j]=block[j]^chain[j];
            memcpy(chain,next,sizeof(chain));
        }
    }
    auth_secure_zero(&c,sizeof(c));
    auth_secure_zero(chain,sizeof(chain)); auth_secure_zero(block,sizeof(block));
    auth_secure_zero(next,sizeof(next));
    return AUTH_OK;
}
static int keypair(Rp2350Crypto *p,uint8_t scalar[32],uint8_t public_key[65]) {
    mbedtls_ecp_keypair k; size_t len=0;
    mbedtls_ecp_keypair_init(&k);
    int rc=mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&k,rng,p);
    if (!rc) rc=mbedtls_mpi_write_binary(&k.MBEDTLS_PRIVATE(d),scalar,32);
    if (!rc) rc=mbedtls_ecp_point_write_binary(&k.MBEDTLS_PRIVATE(grp),&k.MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED,&len,public_key,65);
    mbedtls_ecp_keypair_free(&k);
    if (rc || len!=65) { auth_secure_zero(scalar,32); auth_secure_zero(public_key,65); return -1; }
    return 0;
}
static Rp2350Key *find(Rp2350Crypto *p,const AuthKeyHandle *h) {
    if (!ready(p) || p->keys_locked || !h || !auth_key_handle_valid(h)) return NULL;
    for (size_t i=0;i<RP2350_KEY_SLOTS;i++)
        if (p->keys[i].used && memcmp(&p->keys[i].handle,h,sizeof(*h))==0) return &p->keys[i];
    return NULL;
}
static void ed25519_public(const uint8_t seed[32], uint8_t pub[65]) {
    uint8_t copy[32], secret[64];
    memcpy(copy,seed,32); memset(pub,0,65);
    crypto_ed25519_key_pair(secret,pub,copy); /* Wipes its seed input. */
    auth_secure_zero(secret,sizeof(secret)); auth_secure_zero(copy,sizeof(copy));
}
static AuthStatus generate_algorithm(void *ctx,int32_t algorithm,AuthKeyHandle *h,uint8_t pub[65]) {
    Rp2350Crypto *p=ctx;
    if (!h || !pub) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(h,sizeof(*h)); auth_secure_zero(pub,65);
    if (!ready(p) || p->keys_locked || p->next_handle==UINT64_MAX) return AUTH_CRYPTO_ERROR;
    Rp2350Key *k=NULL;
    for (size_t i=0;i<RP2350_KEY_SLOTS;i++) if (!p->keys[i].used) { k=&p->keys[i]; break; }
    if (!k) return AUTH_CAPACITY;
    k->algorithm=algorithm;
    int rc=algorithm==AUTH_COSE_ALG_ES256 ? keypair(p,k->scalar,k->public_key) : rng(p,k->scalar,32);
    if (!rc && algorithm==AUTH_COSE_ALG_EDDSA) ed25519_public(k->scalar,k->public_key);
    if (rc || rng(p,(uint8_t *)k->randoms,sizeof(k->randoms))) {
        auth_secure_zero(k,sizeof(*k)); return AUTH_CRYPTO_ERROR;
    }
    ++p->next_handle;
    memcpy(k->handle.bytes,p->epoch,sizeof(p->epoch));
    for (size_t i=0;i<8;i++) k->handle.bytes[24+i]=(uint8_t)(p->next_handle>>(56U-8U*i));
    k->used=true; *h=k->handle; memcpy(pub,k->public_key,65);
    return AUTH_OK;
}
static AuthStatus generate(void *ctx,AuthKeyHandle *h,uint8_t pub[65]) {
    return generate_algorithm(ctx,AUTH_COSE_ALG_ES256,h,pub);
}
static AuthStatus generate_ed25519(void *ctx,AuthKeyHandle *h,uint8_t pub[65]) {
    return generate_algorithm(ctx,AUTH_COSE_ALG_EDDSA,h,pub);
}
static AuthStatus sign_ed25519(void *ctx,const AuthKeyHandle *h,const uint8_t *message,size_t length,uint8_t out[64]) {
    if ((!message && length) || !out) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(out,64);
    Rp2350Key *k=find(ctx,h);
    if (!k) return AUTH_NOT_FOUND;
    if (k->algorithm!=AUTH_COSE_ALG_EDDSA) return AUTH_UNSUPPORTED;
    /* Monocypher's private-key representation is seed || public key. */
    uint8_t secret[64]; memcpy(secret,k->scalar,32); memcpy(secret+32,k->public_key,32);
    crypto_ed25519_sign(out,secret,message,length);
    auth_secure_zero(secret,sizeof(secret)); return AUTH_OK;
}
static AuthStatus public_key(void *ctx,const AuthKeyHandle *h,uint8_t out[65]) {
    if (!out) return AUTH_INVALID_ARGUMENT;
    Rp2350Key *k=find(ctx,h);
    if (!k) { auth_secure_zero(out,65); return AUTH_NOT_FOUND; }
    memcpy(out,k->public_key,65); return AUTH_OK;
}
static AuthStatus destroy(void *ctx,const AuthKeyHandle *h) {
    Rp2350Crypto *p=ctx;
    /* Cleanup remains possible after an RNG failure. */
    if (!p || owner!=p || !p->initialized || !h) return AUTH_INVALID_ARGUMENT;
    for (size_t i=0;i<RP2350_KEY_SLOTS;i++) if (p->keys[i].used &&
            memcmp(h,&p->keys[i].handle,sizeof(*h))==0) {
        auth_secure_zero(&p->keys[i],sizeof(p->keys[i])); return AUTH_OK;
    }
    return AUTH_NOT_FOUND;
}
static AuthStatus sign_digest(void *ctx,const AuthKeyHandle *h,const uint8_t digest[32],uint8_t out[72],size_t *n) {
    if (!digest || !out || !n) return AUTH_INVALID_ARGUMENT;
    *n=0; auth_secure_zero(out,72);
    Rp2350Key *k=find(ctx,h);
    if (!k) return AUTH_NOT_FOUND;
    if (k->algorithm!=AUTH_COSE_ALG_ES256) return AUTH_UNSUPPORTED;
    mbedtls_ecdsa_context c; uint8_t der[MBEDTLS_ECDSA_MAX_LEN]; size_t len=0;
    mbedtls_ecdsa_init(&c);
    int rc=mbedtls_ecp_group_load(&c.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc=mbedtls_mpi_read_binary(&c.MBEDTLS_PRIVATE(d),k->scalar,32);
    if (!rc) rc=mbedtls_ecdsa_write_signature(&c,MBEDTLS_MD_SHA256,digest,32,der,sizeof(der),&len,rng,ctx);
    if (!rc && len<=72) { memcpy(out,der,len); *n=len; } else rc=-1;
    mbedtls_ecdsa_free(&c); auth_secure_zero(der,sizeof(der));
    return rc ? AUTH_CRYPTO_ERROR : AUTH_OK;
}
static AuthStatus agreement(void *ctx,uint8_t out[65]) {
    if (!out) return AUTH_INVALID_ARGUMENT;
    Rp2350Crypto *p=ctx;
    if (!ready(p) || p->keys_locked) { auth_secure_zero(out,65); return AUTH_CRYPTO_ERROR; }
    memcpy(out,p->agreement_public,65); return AUTH_OK;
}
static AuthStatus shared(void *ctx,const uint8_t peer[65],uint8_t out[32]) {
    Rp2350Crypto *p=ctx;
    if (!peer || !out) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(out,32);
    if (!ready(p) || p->keys_locked) return AUTH_CRYPTO_ERROR;
    mbedtls_ecp_group g; mbedtls_ecp_point q; mbedtls_mpi d,z;
    mbedtls_ecp_group_init(&g); mbedtls_ecp_point_init(&q); mbedtls_mpi_init(&d); mbedtls_mpi_init(&z);
    int rc=mbedtls_ecp_group_load(&g,MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc=mbedtls_ecp_point_read_binary(&g,&q,peer,65);
    if (!rc) rc=mbedtls_ecp_check_pubkey(&g,&q);
    bool bad_peer=rc!=0;
    if (!rc) rc=mbedtls_mpi_read_binary(&d,p->agreement_scalar,32);
    if (!rc) rc=mbedtls_ecdh_compute_shared(&g,&z,&q,&d,rng,p);
    if (!rc) rc=mbedtls_mpi_write_binary(&z,out,32);
    mbedtls_mpi_free(&z); mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&g);
    if (rc) auth_secure_zero(out,32);
    return rc ? (bad_peer ? AUTH_BAD_DATA : AUTH_CRYPTO_ERROR) : AUTH_OK;
}
static AuthStatus supported(void *ctx,const AuthKeyHandle *h,bool *out) {
    if (!out) return AUTH_INVALID_ARGUMENT;
    *out=false;
    if (!find(ctx,h)) return AUTH_NOT_FOUND;
    *out=true; return AUTH_OK;
}
static AuthStatus credential_mac(void *ctx,const AuthKeyHandle *h,bool uv,const uint8_t salt[32],uint8_t out[32]) {
    if (!salt || !out) return AUTH_INVALID_ARGUMENT;
    Rp2350Key *k=find(ctx,h);
    if (!k) { auth_secure_zero(out,32); return AUTH_NOT_FOUND; }
    return mac(ctx,k->randoms[uv ? 1 : 0],32,salt,32,out);
}
static AuthStatus regenerate(void *ctx) {
    Rp2350Crypto *p=ctx;
    if (!ready(p) || p->keys_locked) return AUTH_CRYPTO_ERROR;
    /* Failure invalidates old agreement key; never fall back to an old key. */
    auth_secure_zero(p->agreement_scalar,32); auth_secure_zero(p->agreement_public,65);
    if (keypair(p,p->agreement_scalar,p->agreement_public)) { p->faulted=true; return AUTH_CRYPTO_ERROR; }
    return AUTH_OK;
}
void rp2350_crypto_invalidate_internal(Rp2350Crypto *p) {
    if(!p || owner!=p || !p->initialized) return;
    p->keys_locked=true;
    auth_secure_zero(p->keys,sizeof(p->keys));
    auth_secure_zero(p->agreement_scalar,sizeof(p->agreement_scalar));
    auth_secure_zero(p->agreement_public,sizeof(p->agreement_public));
    auth_secure_zero(p->epoch,sizeof(p->epoch)); p->next_handle=0;
}
AuthStatus rp2350_crypto_stage_epoch_internal(Rp2350Crypto *p,const uint8_t prefix[24],uint64_t high) {
    if(!p || !prefix) return AUTH_INVALID_ARGUMENT;
    if(!ready(p) || !p->keys_locked) return AUTH_BUSY;
    bool nonzero=false; for(size_t i=0;i<24;i++) nonzero|=prefix[i]!=0;
    if(!nonzero) return AUTH_BAD_DATA;
    rp2350_crypto_invalidate_internal(p);
    if(keypair(p,p->agreement_scalar,p->agreement_public)) { p->faulted=true; return AUTH_CRYPTO_ERROR; }
    memcpy(p->epoch,prefix,24); p->next_handle=high; return AUTH_OK;
}
AuthStatus rp2350_crypto_activate_internal(Rp2350Crypto *p) {
    if(!ready(p) || !p->keys_locked || p->agreement_public[0]!=4) return AUTH_BUSY;
    bool nonzero=false; for(size_t i=0;i<24;i++) nonzero|=p->epoch[i]!=0;
    if(!nonzero) return AUTH_BAD_DATA;
    p->keys_locked=false; return AUTH_OK;
}
AuthStatus rp2350_crypto_restore_records_internal(Rp2350Crypto *p,const uint8_t (*records)[136],size_t count) {
    if(!p) return AUTH_INVALID_ARGUMENT;
    if(!ready(p) || !p->keys_locked) return AUTH_BUSY;
    AuthStatus status=AUTH_BAD_DATA;
    if(!records && count) { status=AUTH_INVALID_ARGUMENT; goto failed; }
    if(count>RP2350_KEY_SLOTS || p->agreement_public[0]!=4) goto failed;
    for(size_t i=0;i<RP2350_KEY_SLOTS;i++) if(p->keys[i].used) goto failed;
    for(size_t i=0;i<count;i++) {
        Rp2350Key *k=&p->keys[i];
        status=rp2350_key_record_decode_internal(records[i],136,k); if(status!=AUTH_OK) goto failed;
        uint64_t number=0; for(size_t j=24;j<32;j++) number=(number<<8)|k->handle.bytes[j];
        if(!number || number>p->next_handle || memcmp(k->handle.bytes,p->epoch,24)) { status=AUTH_BAD_DATA; goto failed; }
        for(size_t j=0;j<i;j++) if(!memcmp(k->handle.bytes,p->keys[j].handle.bytes,32)) { status=AUTH_BAD_DATA; goto failed; }
        if (k->algorithm==AUTH_COSE_ALG_EDDSA) {
            ed25519_public(k->scalar,k->public_key); k->used=true; continue;
        }
        mbedtls_ecp_group group; mbedtls_ecp_point point; mbedtls_mpi scalar; size_t n=0;
        mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&point); mbedtls_mpi_init(&scalar);
        int rc=mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1);
        if(!rc) rc=mbedtls_mpi_read_binary(&scalar,k->scalar,32);
        if(!rc) rc=mbedtls_ecp_mul(&group,&point,&scalar,&group.G,rng,p);
        if(!rc) rc=mbedtls_ecp_check_pubkey(&group,&point);
        if(!rc) rc=mbedtls_ecp_point_write_binary(&group,&point,MBEDTLS_ECP_PF_UNCOMPRESSED,&n,k->public_key,65);
        mbedtls_mpi_free(&scalar); mbedtls_ecp_point_free(&point); mbedtls_ecp_group_free(&group);
        if(rc || n!=65) { status=AUTH_CRYPTO_ERROR; goto failed; }
        k->used=true;
    }
    return AUTH_OK;
failed:
    rp2350_crypto_invalidate_internal(p); return status;
}
void rp2350_crypto_clear_credentials_internal(Rp2350Crypto *p) {
    if(p && owner==p && p->initialized) auth_secure_zero(p->keys,sizeof(p->keys));
}
AuthStatus rp2350_crypto_load_record_internal(Rp2350Crypto *p,const uint8_t record[136]) {
    if(!p || !record) return AUTH_INVALID_ARGUMENT;
    if(!ready(p) || p->keys_locked) return AUTH_BUSY;
    rp2350_crypto_clear_credentials_internal(p);
    p->keys_locked=true;
    AuthStatus status=rp2350_crypto_restore_records_internal(p,(const uint8_t (*)[136])record,1);
    if(status==AUTH_OK) p->keys_locked=false;
    return status;
}
AuthStatus rp2350_crypto_init(Rp2350Crypto *p,int (*entropy)(void *,unsigned char *,size_t),void *ctx) {
    if (!p || !entropy) return AUTH_INVALID_ARGUMENT;
    if (owner) return AUTH_BUSY;
    memset(p,0,sizeof(*p)); owner=p;
    mbedtls_memory_buffer_alloc_init(crypto_pool,sizeof(crypto_pool));
    mbedtls_hmac_drbg_init(&p->drbg);
    static const uint8_t domain[]="ctap-rp2350-volatile-v1";
    int rc=mbedtls_hmac_drbg_seed(&p->drbg,mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),entropy,ctx,domain,sizeof(domain)-1);
    if (rc) { rp2350_crypto_free(p); return AUTH_CRYPTO_ERROR; }
    mbedtls_hmac_drbg_set_prediction_resistance(&p->drbg,MBEDTLS_HMAC_DRBG_PR_ON);
    p->initialized=true;
    if (rng(p,p->epoch,sizeof(p->epoch)) || regenerate(p)!=AUTH_OK) {
        rp2350_crypto_free(p); return AUTH_CRYPTO_ERROR;
    }
    return AUTH_OK;
}
void rp2350_crypto_free(Rp2350Crypto *p) {
    if (!p || owner!=p) return;
    mbedtls_hmac_drbg_free(&p->drbg); mbedtls_memory_buffer_alloc_free();
    auth_secure_zero(crypto_pool,sizeof(crypto_pool)); auth_secure_zero(p,sizeof(*p)); owner=NULL;
}
AuthCrypto rp2350_crypto_interface(Rp2350Crypto *p) {
    return (AuthCrypto){p,random_bytes,hash,generate,public_key,sign_digest,destroy,generate_ed25519,sign_ed25519};
}
AuthSecretCrypto rp2350_secret_interface(Rp2350Crypto *p) {
    return (AuthSecretCrypto){p,agreement,shared,mac,aes,supported,credential_mac,regenerate};
}
