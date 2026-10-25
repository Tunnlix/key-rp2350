#include "storage_seal_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static const uint8_t uuid[16]={0x43,0x54,0x41,0x50,0x53,0x54,0x4f,0x52,0x45,0x2d,0x56,0x32,0,0,0,1};
static size_t round16(size_t n) { return (n+15U)&~(size_t)15U; }
static size_t commit_offset(size_t cipher) { return (64U+cipher+32U+255U)&~(size_t)255U; }
static bool identity_valid(const Rp2350StoreIdentity *id) {
    return id && id->class_id>=1 && id->class_id<=4 && id->sequence && id->generation && store_nonzero(id->epoch,16);
}
static bool location_valid(uint32_t offset,size_t n) {
    return !(offset%256U) && offset<=RP2350_STORE_PARTITION_SIZE && n<=RP2350_STORE_PARTITION_SIZE-offset;
}
AuthStatus rp2350_store_frame_extent(size_t plain,size_t *n) {
    if(!n) return AUTH_INVALID_ARGUMENT;
    *n=0; if(plain<8 || plain>RP2350_STORE_PLAIN_MAX) return AUTH_BAD_DATA;
    *n=commit_offset(round16(plain))+256U; return AUTH_OK;
}
AuthStatus rp2350_store_frame_inspect(const uint8_t *header,size_t n,Rp2350StoreIdentity *id,size_t *plain,size_t *extent) {
    if(id) *id=(Rp2350StoreIdentity){0};
    if(plain) *plain=0;
    if(extent) *extent=0;
    if(!header || !id || !plain || !extent) return AUTH_INVALID_ARGUMENT;
    if(n<64 || memcmp(header,"CTR2",4) || store_u16(header+4)!=2) return AUTH_BAD_DATA;
    size_t length=store_u32(header+8),size=0;
    if(rp2350_store_frame_extent(length,&size)!=AUTH_OK || store_u32(header+12)!=round16(length)) return AUTH_BAD_DATA;
    Rp2350StoreIdentity parsed={.class_id=store_u16(header+6),.sequence=store_u64(header+16),.generation=store_u64(header+24)};
    memcpy(parsed.epoch,header+32,16); if(!identity_valid(&parsed)) return AUTH_BAD_DATA;
    *id=parsed; *plain=length; *extent=size; return AUTH_OK;
}
AuthStatus rp2350_store_seal_init_internal(Rp2350StoreSeal *s,const AuthCrypto *c,const AuthSecretCrypto *p,
        const uint8_t root[32],const uint8_t epoch[16]) {
    if(!s) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(s,sizeof(*s));
    if(!c || !p || !root || !epoch || !c->random || !c->sha256 || !p->hmac_sha256 || !p->aes256_cbc ||
        !store_nonzero(epoch,16)) return AUTH_INVALID_ARGUMENT;
    s->crypto=*c; s->secrets=*p; memcpy(s->epoch,epoch,16);
    uint8_t prk[32]={0},info[32]={0};
    AuthStatus status=p->hmac_sha256(p->context,epoch,16,root,32,prk);
    static const char *const labels[]={"ctap-store-v2/enc","ctap-store-v2/mac","ctap-store-v2/commit","ctap-store-v2/root-auth"};
    uint8_t *keys[]={s->enc,s->mac,s->commit,s->root_auth};
    for(size_t i=0;i<4 && status==AUTH_OK;i++) {
        size_t length=strlen(labels[i]); memcpy(info,labels[i],length); info[length]=1;
        status=p->hmac_sha256(p->context,prk,32,info,length+1U,keys[i]);
    }
    auth_secure_zero(prk,sizeof(prk)); auth_secure_zero(info,sizeof(info));
    if(status!=AUTH_OK) { auth_secure_zero(s,sizeof(*s)); return status; }
    s->initialized=true; return AUTH_OK;
}
void rp2350_store_seal_free_internal(Rp2350StoreSeal *s) { if(s) auth_secure_zero(s,sizeof(*s)); }
static AuthStatus tag(Rp2350StoreSeal *s,bool commit,uint16_t class_id,uint32_t offset,
        const uint8_t *data,size_t n,uint8_t out[32],Rp2350StoreSealWorkspace *w) {
    const char *domain=class_id==4 ? (commit ? "ctap-store-v2/selector-commit" : "ctap-store-v2/selector") :
        (commit ? "ctap-store-v2/commit-page" : "ctap-store-v2/data");
    size_t length=strlen(domain),prefix=length+16U+4U;
    if(n>sizeof(w->mac_input)-prefix) return AUTH_BAD_DATA;
    memcpy(w->mac_input,domain,length); memcpy(w->mac_input+length,uuid,16);
    store_put32(w->mac_input+length+16U,offset); memcpy(w->mac_input+prefix,data,n);
    return s->secrets.hmac_sha256(s->secrets.context,commit ? s->commit : s->mac,32,w->mac_input,prefix+n,out);
}
static AuthStatus crypt(Rp2350StoreSeal *s,bool encrypt,const uint8_t iv[16],uint8_t *data,size_t n) {
    uint8_t chain[16],next[16]={0}; memcpy(chain,iv,16); AuthStatus status=AUTH_OK;
    for(size_t offset=0;offset<n && status==AUTH_OK;) {
        size_t remain=n-offset,take=remain>=64 ? 64 : remain>=32 ? 32 : 16;
        if(!encrypt) memcpy(next,data+offset+take-16U,16);
        status=s->secrets.aes256_cbc(s->secrets.context,encrypt,s->enc,chain,data+offset,take,data+offset);
        if(status==AUTH_OK) memcpy(chain,encrypt ? data+offset+take-16U : next,16);
        offset+=take;
    }
    auth_secure_zero(chain,sizeof(chain)); auth_secure_zero(next,sizeof(next)); return status;
}
AuthStatus rp2350_store_seal_internal(Rp2350StoreSeal *s,const Rp2350StoreIdentity *id,uint32_t offset,
        const uint8_t *plain,size_t n,uint8_t *out,size_t capacity,size_t *length,Rp2350StoreSealWorkspace *w) {
    if(length) *length=0;
    if(!s || !identity_valid(id) || !plain || !out || !length || !w || capacity>RP2350_STORE_FRAME_MAX) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(w,sizeof(*w));
    size_t extent=0;
    if(!s->initialized || s->faulted) return AUTH_CRYPTO_ERROR;
    if(rp2350_store_frame_extent(n,&extent)!=AUTH_OK || !location_valid(offset,extent) || !store_equal(id->epoch,s->epoch,16)) return AUTH_BAD_DATA;
    if(capacity<extent) return AUTH_CAPACITY;
    size_t cipher=round16(n),commit=extent-256U; AuthStatus status;
    memset(out,0xff,extent); memcpy(out,"CTR2",4); store_put16(out+4,2); store_put16(out+6,id->class_id);
    store_put32(out+8,(uint32_t)n); store_put32(out+12,(uint32_t)cipher); store_put64(out+16,id->sequence);
    store_put64(out+24,id->generation); memcpy(out+32,id->epoch,16);
    status=s->crypto.random(s->crypto.context,out+48,16);
    if(status!=AUTH_OK) goto failed;
    memcpy(out+64,plain,n); memset(out+64+n,0,cipher-n);
    status=crypt(s,true,out+48,out+64,cipher); if(status!=AUTH_OK) goto failed;
    status=tag(s,false,id->class_id,offset,out,64+cipher,out+64+cipher,w); if(status!=AUTH_OK) goto failed;
    uint8_t *cp=out+commit;
    memcpy(cp,"CTC2",4); store_put16(cp+4,2); store_put16(cp+6,id->class_id); store_put64(cp+8,id->sequence);
    store_put64(cp+16,id->generation); memcpy(cp+24,id->epoch,16);
    status=s->crypto.sha256(s->crypto.context,out,64+cipher+32U,cp+40); if(status!=AUTH_OK) goto failed;
    status=tag(s,true,id->class_id,offset,cp,72,cp+72,w); if(status!=AUTH_OK) goto failed;
    auth_secure_zero(w,sizeof(*w)); *length=extent; return AUTH_OK;
failed:
    s->faulted=true; auth_secure_zero(out,extent); auth_secure_zero(w,sizeof(*w)); return status;
}
AuthStatus rp2350_store_open_internal(Rp2350StoreSeal *s,const Rp2350StoreIdentity *expected,uint32_t offset,
        const uint8_t *frame,size_t n,uint8_t *out,size_t capacity,size_t *length,Rp2350StoreSealWorkspace *w) {
    if(length) *length=0;
    if(!out || capacity>RP2350_STORE_PLAIN_MAX) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(out,capacity);
    if(!s || !identity_valid(expected) || !frame || !length || !w) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(w,sizeof(*w));
    if(!s->initialized || s->faulted) return AUTH_CRYPTO_ERROR;
    AuthStatus status=AUTH_BAD_DATA; size_t plain=0,extent=0; Rp2350StoreIdentity actual;
    uint8_t mac[32]={0},digest[32]={0};
    if(rp2350_store_frame_inspect(frame,n,&actual,&plain,&extent)!=AUTH_OK || extent!=n ||
        !location_valid(offset,n) || actual.class_id!=expected->class_id || actual.sequence!=expected->sequence ||
        actual.generation!=expected->generation || !store_equal(actual.epoch,expected->epoch,16) ||
        !store_equal(actual.epoch,s->epoch,16)) goto failed;
    if(capacity<plain) return AUTH_CAPACITY;
    size_t cipher=round16(plain),commit=extent-256U; const uint8_t *cp=frame+commit;
    if(memcmp(cp,"CTC2",4) || store_u16(cp+4)!=2 || store_u16(cp+6)!=actual.class_id ||
        store_u64(cp+8)!=actual.sequence || store_u64(cp+16)!=actual.generation || !store_equal(cp+24,actual.epoch,16)) goto failed;
    for(size_t i=64+cipher+32U;i<commit;i++) if(frame[i]!=0xff) goto failed;
    for(size_t i=104;i<256;i++) if(cp[i]!=0xff) goto failed;
    status=tag(s,false,actual.class_id,offset,frame,64+cipher,mac,w); if(status!=AUTH_OK) goto failed;
    if(!store_equal(mac,frame+64+cipher,32)) { status=AUTH_BAD_DATA; goto failed; }
    status=tag(s,true,actual.class_id,offset,cp,72,mac,w); if(status!=AUTH_OK) goto failed;
    if(!store_equal(mac,cp+72,32)) { status=AUTH_BAD_DATA; goto failed; }
    status=s->crypto.sha256(s->crypto.context,frame,64+cipher+32U,digest); if(status!=AUTH_OK) goto failed;
    if(!store_equal(digest,cp+40,32)) { status=AUTH_BAD_DATA; goto failed; }
    /* Caller may have room for plaintext but not its final padding block. Use
     * authenticated ciphertext copied to private workspace for decryption. */
    memcpy(w->mac_input,frame+64,cipher);
    status=crypt(s,false,frame+48,w->mac_input,cipher); if(status!=AUTH_OK) goto failed;
    if(!store_zero(w->mac_input+plain,cipher-plain)) { status=AUTH_BAD_DATA; goto failed; }
    memcpy(out,w->mac_input,plain); *length=plain;
    auth_secure_zero(mac,sizeof(mac)); auth_secure_zero(digest,sizeof(digest)); auth_secure_zero(w,sizeof(*w)); return AUTH_OK;
failed:
    s->faulted=true; auth_secure_zero(out,capacity); auth_secure_zero(mac,sizeof(mac));
    auth_secure_zero(digest,sizeof(digest)); auth_secure_zero(w,sizeof(*w)); return status;
}
