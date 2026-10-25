#include "nonresident_seal_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>

_Static_assert(RP2350_NONRESIDENT_ID_SIZE<=AUTH_CREDENTIAL_ID_MAX_SIZE,"wire ID bound");
/* Header[32] || random IV[16] || CBC ciphertext[176] || HMAC-SHA256[32].
 * Plaintext: existing private record[136] || RP hash[32] || policy/reserved[8]. */
void rp2350_nonresident_seal_close_internal(Rp2350NonresidentSeal *s) {
    if(s && !s->busy) auth_secure_zero(s,sizeof(*s));
}
AuthStatus rp2350_nonresident_seal_init_internal(Rp2350NonresidentSeal *s,
        const AuthCrypto *crypto,const AuthSecretCrypto *secrets,const uint8_t root[32],const uint8_t epoch[16]) {
    if(!s) return AUTH_INVALID_ARGUMENT;
    if(s->busy) return AUTH_BUSY;
    auth_secure_zero(s,sizeof(*s));
    if(!crypto || !crypto->random || !secrets || !secrets->hmac_sha256 || !secrets->aes256_cbc ||
        !root || !epoch || !store_nonzero(root,32) || !store_nonzero(epoch,16)) return AUTH_INVALID_ARGUMENT;
    s->busy=true; s->crypto=*crypto; s->secrets=*secrets; memcpy(s->epoch,epoch,16);
    uint8_t prk[32]={0},info[48]={0};
    /* RFC 5869 extract and one-block expand, with separate labels. */
    AuthStatus status=secrets->hmac_sha256(secrets->context,epoch,16,root,32,prk);
    static const char *const labels[]={"tunnixkey/nonresident-v1/enc","tunnixkey/nonresident-v1/mac"};
    uint8_t *keys[]={s->enc,s->mac};
    for(size_t i=0;i<2 && status==AUTH_OK;i++) {
        size_t length=strlen(labels[i]); memcpy(info,labels[i],length); info[length]=1;
        status=secrets->hmac_sha256(secrets->context,prk,32,info,length+1,keys[i]);
    }
    auth_secure_zero(prk,sizeof(prk)); auth_secure_zero(info,sizeof(info));
    s->busy=false;
    if(status!=AUTH_OK) rp2350_nonresident_seal_close_internal(s);
    else s->initialized=true;
    return status;
}
static AuthStatus finish(Rp2350NonresidentSeal *s,Rp2350NonresidentWorkspace *w,AuthStatus status) {
    auth_secure_zero(w,sizeof(*w)); s->busy=false;
    if(status!=AUTH_OK && status!=AUTH_NOT_FOUND && status!=AUTH_CAPACITY)
        rp2350_nonresident_seal_close_internal(s);
    return status;
}
static AuthStatus crypt(Rp2350NonresidentSeal *s,Rp2350NonresidentWorkspace *w,bool encrypt) {
    memcpy(w->chain,w->wire+32,16);
    for(size_t at=0;at<176;) {
        size_t remaining=176-at,take=remaining>=64 ? 64 : remaining>=32 ? 32 : 16;
        uint8_t *in=encrypt ? w->plain+at : w->wire+48+at;
        uint8_t *out=encrypt ? w->wire+48+at : w->plain+at;
        if(!encrypt) memcpy(w->next,in+take-16,16);
        AuthStatus status=s->secrets.aes256_cbc(s->secrets.context,encrypt,s->enc,w->chain,in,take,out);
        if(status!=AUTH_OK) return status;
        memcpy(w->chain,encrypt ? out+take-16 : w->next,16); at+=take;
    }
    return AUTH_OK;
}
AuthStatus rp2350_nonresident_seal_create_internal(Rp2350NonresidentSeal *s,
        const Rp2350Key *key,const uint8_t rp[32],uint8_t policy,
        Rp2350NonresidentReserve reserve,void *context,uint8_t out[256],Rp2350NonresidentWorkspace *w) {
    if(s && s->busy) return AUTH_BUSY;
    if(out) auth_secure_zero(out,256);
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!s || !key || !rp || !out || !w || !reserve || policy<1 || policy>3) return AUTH_INVALID_ARGUMENT;
    if(!s->initialized) return AUTH_CRYPTO_ERROR;
    s->busy=true;
    AuthStatus status=rp2350_key_record_encode_internal(key,w->plain);
    if(status!=AUTH_OK) return finish(s,w,status);
    memcpy(w->plain+136,rp,32); w->plain[168]=policy;
    uint64_t serial=0; status=reserve(context,&serial);
    if(status==AUTH_OK && (!serial || serial>=RP2350_NONRESIDENT_ISSUANCE_LIMIT)) status=AUTH_CAPACITY;
    if(status==AUTH_OK) {
        memcpy(w->wire,"TKNR",4); store_put16(w->wire+4,1); store_put16(w->wire+6,176);
        memcpy(w->wire+8,s->epoch,16); store_put64(w->wire+24,serial);
        status=s->crypto.random(s->crypto.context,w->wire+32,16);
    }
    if(status==AUTH_OK) status=crypt(s,w,true);
    if(status==AUTH_OK) status=s->secrets.hmac_sha256(s->secrets.context,s->mac,32,w->wire,224,w->wire+224);
    if(status==AUTH_OK) memcpy(out,w->wire,256);
    return finish(s,w,status);
}
AuthStatus rp2350_nonresident_seal_open_internal(Rp2350NonresidentSeal *s,
        const uint8_t *id,size_t length,const uint8_t rp[32],Rp2350Key *key,uint8_t *policy,
        Rp2350NonresidentWorkspace *w) {
    if(s && s->busy) return AUTH_BUSY;
    if(key) auth_secure_zero(key,sizeof(*key));
    if(policy) *policy=0;
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!s || !id || !rp || !key || !policy || !w) return AUTH_INVALID_ARGUMENT;
    if(!s->initialized) return AUTH_CRYPTO_ERROR;
    s->busy=true;
    if(length!=256 || memcmp(id,"TKNR",4) || store_u16(id+4)!=1 || store_u16(id+6)!=176 ||
        !store_equal(id+8,s->epoch,16) || !store_u64(id+24) ||
        store_u64(id+24)>=RP2350_NONRESIDENT_ISSUANCE_LIMIT) return finish(s,w,AUTH_NOT_FOUND);
    memcpy(w->wire,id,256);
    AuthStatus status=s->secrets.hmac_sha256(s->secrets.context,s->mac,32,w->wire,224,w->tag);
    if(status==AUTH_OK && !store_equal(w->tag,w->wire+224,32)) status=AUTH_NOT_FOUND;
    if(status==AUTH_OK) status=crypt(s,w,false);
    if(status==AUTH_OK && (!store_equal(w->plain+136,rp,32) || w->plain[168]<1 || w->plain[168]>3 ||
        !store_zero(w->plain+169,7))) status=AUTH_NOT_FOUND;
    if(status==AUTH_OK) {
        status=rp2350_key_record_decode_internal(w->plain,136,key);
        if(status==AUTH_BAD_DATA) status=AUTH_NOT_FOUND;
    }
    if(status==AUTH_OK) *policy=w->plain[168];
    return finish(s,w,status);
}
