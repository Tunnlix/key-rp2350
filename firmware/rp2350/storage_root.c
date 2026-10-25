#include "storage_root_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static const uint8_t uuid[16]={0x43,0x54,0x41,0x50,0x53,0x54,0x4f,0x52,0x45,0x2d,0x56,0x32,0,0,0,1};
static bool valid(const Rp2350StoreRoot *r) {
    if(!r->serial || !r->reset_generation || !store_nonzero(r->epoch,16) || !r->descriptor_length || r->descriptor_length>128) return false;
    if(!store_zero(r->descriptor+r->descriptor_length,128U-r->descriptor_length)) return false;
    return (r->profile==1 && !r->backend && r->descriptor_length==32) || (r->profile==2 && r->backend!=0);
}
AuthStatus rp2350_store_root_inspect_internal(const uint8_t *in,size_t n,uint8_t profile,Rp2350StoreRoot *r) {
    if(!r) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(r,sizeof(*r)); if(!in) return AUTH_INVALID_ARGUMENT;
    if((n!=512 && n!=4096) || memcmp(in,"CRR2",4) || store_u16(in+4)!=2 || in[6]!=profile ||
        store_u16(in+10) || store_u32(in+12)) return AUTH_BAD_DATA;
    Rp2350StoreRoot candidate={.profile=in[6],.backend=in[7],.descriptor_length=store_u16(in+8),
        .serial=store_u64(in+160),.reset_generation=store_u64(in+168)};
    memcpy(candidate.epoch,in+16,16); memcpy(candidate.descriptor,in+32,128);
    if(!valid(&candidate)) { auth_secure_zero(&candidate,sizeof(candidate)); return AUTH_BAD_DATA; }
    for(size_t i=208;i<256;i++) if(in[i]!=0xff) { auth_secure_zero(&candidate,sizeof(candidate)); return AUTH_BAD_DATA; }
    for(size_t i=512;i<n;i++) if(in[i]!=0xff) { auth_secure_zero(&candidate,sizeof(candidate)); return AUTH_BAD_DATA; }
    *r=candidate; auth_secure_zero(&candidate,sizeof(candidate)); return AUTH_OK;
}
static AuthStatus root_mac(Rp2350StoreSeal *s,bool commit,const uint8_t *in,uint8_t out[32]) {
    const char *label=commit ? "ctap-store-v2/root-commit" : "ctap-store-v2/root-body";
    uint8_t input[224]; size_t l=strlen(label),n=commit ? 64U : 176U;
    memcpy(input,label,l); memcpy(input+l,uuid,16); memcpy(input+l+16,in,n);
    AuthStatus status=s->secrets.hmac_sha256(s->secrets.context,s->root_auth,32,input,l+16+n,out);
    auth_secure_zero(input,sizeof(input)); return status;
}
static AuthStatus development_root_matches(Rp2350StoreSeal *s,const Rp2350StoreRoot *r) {
    if(r->profile!=1) return AUTH_OK; /* Protected descriptors are backend-resolved. */
    uint8_t prk[32]={0},key[32]={0};
    static const uint8_t info[]="ctap-store-v2/root-auth\001";
    AuthStatus status=s->secrets.hmac_sha256(s->secrets.context,r->epoch,16,r->descriptor,32,prk);
    if(status==AUTH_OK) status=s->secrets.hmac_sha256(s->secrets.context,prk,32,info,sizeof(info)-1U,key);
    if(status==AUTH_OK && !store_equal(key,s->root_auth,32)) status=AUTH_BAD_DATA;
    auth_secure_zero(prk,32); auth_secure_zero(key,32); return status;
}
AuthStatus rp2350_store_root_encode_internal(Rp2350StoreSeal *s,const Rp2350StoreRoot *r,uint8_t out[512]) {
    if(!s || !r || !out) return AUTH_INVALID_ARGUMENT;
    if(!s->initialized || s->faulted) return AUTH_CRYPTO_ERROR;
    if(!valid(r) || !store_equal(s->epoch,r->epoch,16)) return AUTH_BAD_DATA;
    AuthStatus status=development_root_matches(s,r); if(status!=AUTH_OK) return status;
    memset(out,0xff,512); memcpy(out,"CRR2",4); store_put16(out+4,2); out[6]=r->profile; out[7]=r->backend;
    store_put16(out+8,r->descriptor_length); store_put16(out+10,0); store_put32(out+12,0); memcpy(out+16,r->epoch,16);
    memcpy(out+32,r->descriptor,128); store_put64(out+160,r->serial); store_put64(out+168,r->reset_generation);
    status=root_mac(s,false,out,out+176); if(status!=AUTH_OK) goto failed;
    uint8_t *cp=out+256; memcpy(cp,"CRC2",4); store_put16(cp+4,2); cp[6]=r->profile; cp[7]=r->backend;
    store_put64(cp+8,r->serial); memcpy(cp+16,r->epoch,16);
    status=s->crypto.sha256(s->crypto.context,out,256,cp+32); if(status!=AUTH_OK) goto failed;
    status=root_mac(s,true,cp,cp+64); if(status!=AUTH_OK) goto failed;
    return AUTH_OK;
failed:
    s->faulted=true; auth_secure_zero(out,512); return status;
}
AuthStatus rp2350_store_root_open_internal(Rp2350StoreSeal *s,const uint8_t *in,size_t n,uint8_t profile,Rp2350StoreRoot *r) {
    if(!r) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(r,sizeof(*r)); if(!s || !in) return AUTH_INVALID_ARGUMENT;
    if(!s->initialized || s->faulted) return AUTH_CRYPTO_ERROR;
    Rp2350StoreRoot candidate; uint8_t mac[32]={0},digest[32]={0}; AuthStatus status=AUTH_BAD_DATA;
    if(rp2350_store_root_inspect_internal(in,n,profile,&candidate)!=AUTH_OK) goto failed;
    status=development_root_matches(s,&candidate); if(status!=AUTH_OK) goto failed;
    status=AUTH_BAD_DATA;
    const uint8_t *cp=in+256;
    if(!store_equal(candidate.epoch,s->epoch,16) || memcmp(cp,"CRC2",4) || store_u16(cp+4)!=2 ||
        cp[6]!=candidate.profile || cp[7]!=candidate.backend || store_u64(cp+8)!=candidate.serial ||
        !store_equal(cp+16,candidate.epoch,16)) goto failed;
    for(size_t i=96;i<256;i++) if(cp[i]!=0xff) goto failed;
    status=root_mac(s,false,in,mac); if(status!=AUTH_OK) goto failed;
    if(!store_equal(mac,in+176,32)) { status=AUTH_BAD_DATA; goto failed; }
    status=root_mac(s,true,cp,mac); if(status!=AUTH_OK) goto failed;
    if(!store_equal(mac,cp+64,32)) { status=AUTH_BAD_DATA; goto failed; }
    status=s->crypto.sha256(s->crypto.context,in,256,digest); if(status!=AUTH_OK) goto failed;
    if(!store_equal(digest,cp+32,32)) { status=AUTH_BAD_DATA; goto failed; }
    *r=candidate; auth_secure_zero(&candidate,sizeof(candidate)); auth_secure_zero(mac,32); auth_secure_zero(digest,32); return AUTH_OK;
failed:
    s->faulted=true; auth_secure_zero(&candidate,sizeof(candidate)); auth_secure_zero(mac,32); auth_secure_zero(digest,32); return status;
}
