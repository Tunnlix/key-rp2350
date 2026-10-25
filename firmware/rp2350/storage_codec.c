#include "storage_codec.h"
#include "storage_bytes_internal.h"
#include "authenticator/auth_secret_crypto.h"
#include <string.h>
static bool supported(void) { return CTAP_MESSAGE_CAPACITY<=2048 && CTAP_RESIDENT_CAPACITY<=32; }
static AuthStatus metadata_valid(const AuthCredential *c,Rp2350StoreHash hash,void *ctx) {
    if (!supported()) return AUTH_UNSUPPORTED;
    if (!auth_credential_valid(c) || (c->discoverable && (!c->rp_id_length || !c->creation_order))) return AUTH_BAD_DATA;
    if (c->rp_id_length) {
        if (!hash) return AUTH_INVALID_ARGUMENT;
        uint8_t digest[32];
        AuthStatus status=hash(ctx,c->rp_id,c->rp_id_length,digest);
        bool matches=status==AUTH_OK && store_equal(digest,c->rp_id_hash,32);
        auth_secure_zero(digest,sizeof(digest));
        if (status!=AUTH_OK) return status;
        if (!matches) return AUTH_BAD_DATA;
    }
    return AUTH_OK;
}
AuthStatus rp2350_store_metadata_encode(const AuthCredential *c,Rp2350StoreHash hash,void *ctx,
        uint8_t *out,size_t capacity,size_t *length) {
    if (length) *length=0;
    if (!c || !out || !length) return AUTH_INVALID_ARGUMENT;
    AuthStatus status=metadata_valid(c,hash,ctx); if(status!=AUTH_OK) return status;
    size_t sizes[]={c->user_id_length,c->rp_id_length,c->rp_name_length,c->user_name_length,c->user_display_name_length};
    size_t total=128; for(size_t i=0;i<5;i++) total+=sizes[i];
    if(capacity<total) return AUTH_CAPACITY;
    memset(out,0,128); store_put16(out,1); out[2]=c->discoverable ? 1U : 0U; out[3]=c->cred_protect;
    store_put32(out+4,UINT32_C(0xfffffff9)); store_put32(out+8,c->signature_count);
    for(size_t i=0;i<5;i++) store_put16(out+12+2*i,(uint16_t)sizes[i]);
    store_put64(out+24,c->creation_order); memcpy(out+32,c->credential_id,32);
    memcpy(out+64,c->rp_id_hash,32); memcpy(out+96,c->key.bytes,32);
    const uint8_t *fields[]={c->user_id,c->rp_id,c->rp_name,c->user_name,c->user_display_name};
    size_t offset=128; for(size_t i=0;i<5;i++) { memcpy(out+offset,fields[i],sizes[i]); offset+=sizes[i]; }
    *length=total; return AUTH_OK;
}
AuthStatus rp2350_store_metadata_decode(const uint8_t *in,size_t n,Rp2350StoreHash hash,void *ctx,AuthCredential *c) {
    if (!c) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(c,sizeof(*c));
    if (!in) return AUTH_INVALID_ARGUMENT;
    if(!supported()) return AUTH_UNSUPPORTED;
    if(n<128 || n>RP2350_STORE_METADATA_MAX || store_u16(in)!=1 || in[2]>1 ||
        store_u16(in+22) || store_u32(in+4)!=UINT32_C(0xfffffff9)) return AUTH_BAD_DATA;
    size_t limits[]={64,AUTH_RP_ID_MAX_SIZE,64,64,64}, sizes[5],total=128;
    for(size_t i=0;i<5;i++) { sizes[i]=store_u16(in+12+2*i); if(sizes[i]>limits[i]) return AUTH_BAD_DATA; total+=sizes[i]; }
    if(total!=n) return AUTH_BAD_DATA;
    c->discoverable=in[2]!=0; c->cred_protect=in[3]; c->algorithm=AUTH_COSE_ALG_ES256;
    c->signature_count=store_u32(in+8); c->creation_order=store_u64(in+24);
    c->user_id_length=(uint8_t)sizes[0]; c->rp_id_length=(uint16_t)sizes[1];
    c->rp_name_length=(uint8_t)sizes[2]; c->user_name_length=(uint8_t)sizes[3]; c->user_display_name_length=(uint8_t)sizes[4];
    memcpy(c->credential_id,in+32,32); memcpy(c->rp_id_hash,in+64,32); memcpy(c->key.bytes,in+96,32);
    uint8_t *fields[]={c->user_id,c->rp_id,c->rp_name,c->user_name,c->user_display_name};
    size_t offset=128; for(size_t i=0;i<5;i++) { memcpy(fields[i],in+offset,sizes[i]); offset+=sizes[i]; }
    AuthStatus status=metadata_valid(c,hash,ctx);
    if(status!=AUTH_OK) auth_secure_zero(c,sizeof(*c));
    return status;
}
AuthStatus rp2350_store_pin_encode(const AuthPinRecord *p,uint8_t out[24]) {
    if(!p || !out) return AUTH_INVALID_ARGUMENT;
    if(!auth_pin_record_valid(p)) return AUTH_BAD_DATA;
    memset(out,0,24); store_put16(out,1); out[2]=p->set ? 1U : 0U; out[3]=p->code_points; out[4]=p->retries;
    memcpy(out+8,p->hash,16); return AUTH_OK;
}
AuthStatus rp2350_store_pin_decode(const uint8_t *in,size_t n,AuthPinRecord *p) {
    if(!p) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(p,sizeof(*p));
    if(!in) return AUTH_INVALID_ARGUMENT;
    if(n!=24 || store_u16(in)!=1 || in[2]>1 || !store_zero(in+5,3)) return AUTH_BAD_DATA;
    p->set=in[2]!=0; p->code_points=in[3]; p->retries=in[4]; memcpy(p->hash,in+8,16);
    if(!auth_pin_record_valid(p)) { auth_secure_zero(p,sizeof(*p)); return AUTH_BAD_DATA; }
    return AUTH_OK;
}
static bool global_valid(const Rp2350StoreGlobal *g) {
    return g->attempt_high<UINT64_C(16777216) && g->nonresident_issued<UINT32_C(16777216) &&
        g->reset_generation && store_nonzero(g->handle_prefix,24);
}
AuthStatus rp2350_store_global_encode(const Rp2350StoreGlobal *g,uint8_t out[96]) {
    if(!g || !out) return AUTH_INVALID_ARGUMENT;
    if(!global_valid(g)) return AUTH_BAD_DATA;
    memset(out,0,96); store_put16(out,2); store_put64(out+8,g->handle_high); store_put64(out+16,g->attempt_high);
    memcpy(out+24,g->store_state,16); memcpy(out+40,g->handle_prefix,24); store_put64(out+64,g->reset_generation);
    memcpy(out+72,g->device_id,16); store_put32(out+88,g->nonresident_issued);
    store_put32(out+92,g->nonresident_counter); return AUTH_OK;
}
AuthStatus rp2350_store_global_decode(const uint8_t *in,size_t n,Rp2350StoreGlobal *g) {
    if(!g) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(g,sizeof(*g)); if(!in) return AUTH_INVALID_ARGUMENT;
    if(n!=96 || store_u16(in)!=2 || !store_zero(in+2,6)) return AUTH_BAD_DATA;
    g->handle_high=store_u64(in+8); g->attempt_high=store_u64(in+16); g->reset_generation=store_u64(in+64);
    memcpy(g->store_state,in+24,16); memcpy(g->handle_prefix,in+40,24); memcpy(g->device_id,in+72,16);
    g->nonresident_issued=store_u32(in+88); g->nonresident_counter=store_u32(in+92);
    if(!global_valid(g)) { auth_secure_zero(g,sizeof(*g)); return AUTH_BAD_DATA; } return AUTH_OK;
}
static bool counter_valid(const Rp2350StoreCounter *c) {
    return c->expected!=UINT32_MAX && c->next==c->expected+1U && store_nonzero(c->id,32);
}
AuthStatus rp2350_store_counter_encode(const Rp2350StoreCounter *c,uint8_t out[48]) {
    if(!c || !out) return AUTH_INVALID_ARGUMENT;
    if(!counter_valid(c)) return AUTH_BAD_DATA;
    memset(out,0,48); store_put16(out,1); store_put32(out+4,c->expected); store_put32(out+8,c->next);
    memcpy(out+12,c->id,32); return AUTH_OK;
}
AuthStatus rp2350_store_counter_decode(const uint8_t *in,size_t n,Rp2350StoreCounter *c) {
    if(!c) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(c,sizeof(*c)); if(!in) return AUTH_INVALID_ARGUMENT;
    if(n!=48 || store_u16(in)!=1 || store_u16(in+2) || store_u32(in+44)) return AUTH_BAD_DATA;
    c->expected=store_u32(in+4); c->next=store_u32(in+8); memcpy(c->id,in+12,32);
    if(!counter_valid(c)) { auth_secure_zero(c,sizeof(*c)); return AUTH_BAD_DATA; } return AUTH_OK;
}
static bool manifest_valid(const Rp2350StoreManifest *m) {
    return supported() && m->metadata_count<=AUTH_RESIDENT_MAX_COUNT && m->key_count<=AUTH_RESIDENT_MAX_COUNT+1U &&
        m->key_count>=m->metadata_count;
}
AuthStatus rp2350_store_manifest_encode(const Rp2350StoreManifest *m,uint8_t out[96]) {
    if(!m || !out) return AUTH_INVALID_ARGUMENT;
    if(!manifest_valid(m)) return AUTH_BAD_DATA;
    memset(out,0,96); store_put16(out,1); store_put16(out+2,m->metadata_count); store_put16(out+4,m->key_count);
    store_put64(out+8,m->last_sequence); memcpy(out+16,m->global_digest,32); memcpy(out+48,m->ordered_digest,32); return AUTH_OK;
}
AuthStatus rp2350_store_manifest_decode(const uint8_t *in,size_t n,Rp2350StoreManifest *m) {
    if(!m) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(m,sizeof(*m)); if(!in) return AUTH_INVALID_ARGUMENT;
    if(n!=96 || store_u16(in)!=1 || store_u16(in+6) || !store_zero(in+80,16)) return AUTH_BAD_DATA;
    m->metadata_count=store_u16(in+2); m->key_count=store_u16(in+4); m->last_sequence=store_u64(in+8);
    memcpy(m->global_digest,in+16,32); memcpy(m->ordered_digest,in+48,32);
    if(!manifest_valid(m)) { auth_secure_zero(m,sizeof(*m)); return AUTH_BAD_DATA; } return AUTH_OK;
}
static bool selector_valid(const Rp2350StoreSelector *s) {
    if(!s->serial || !s->reset_generation || !store_nonzero(s->epoch,16)) return false;
    if(s->state==1) return s->arena<2 && s->generation!=0;
    return s->state==2 && s->arena==0xff && !s->generation && store_zero(s->manifest_digest,32);
}
AuthStatus rp2350_store_selector_encode(const Rp2350StoreSelector *s,uint8_t out[80]) {
    if(!s || !out) return AUTH_INVALID_ARGUMENT;
    if(!selector_valid(s)) return AUTH_BAD_DATA;
    memset(out,0,80); store_put16(out,1); out[2]=s->state; out[3]=s->arena; store_put64(out+8,s->serial);
    store_put64(out+16,s->generation); memcpy(out+24,s->epoch,16); memcpy(out+40,s->manifest_digest,32);
    store_put64(out+72,s->reset_generation); return AUTH_OK;
}
AuthStatus rp2350_store_selector_decode(const uint8_t *in,size_t n,Rp2350StoreSelector *s) {
    if(!s) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(s,sizeof(*s)); if(!in) return AUTH_INVALID_ARGUMENT;
    if(n!=80 || store_u16(in)!=1 || store_u32(in+4)) return AUTH_BAD_DATA;
    s->state=in[2]; s->arena=in[3]; s->serial=store_u64(in+8); s->generation=store_u64(in+16);
    memcpy(s->epoch,in+24,16); memcpy(s->manifest_digest,in+40,32); s->reset_generation=store_u64(in+72);
    if(!selector_valid(s)) { auth_secure_zero(s,sizeof(*s)); return AUTH_BAD_DATA; } return AUTH_OK;
}
static bool transaction_valid(const Rp2350StoreTransaction *t) {
    if(!t || !t->count || t->count>4 || !t->class_id || t->class_id>4) return false;
    if(t->class_id!=1 && t->count!=1) return false;
    for(size_t i=0;i<t->count;i++) {
        uint16_t kind=t->entries[i].kind;
        if(!t->entries[i].data || !t->entries[i].length || t->entries[i].length>RP2350_STORE_PLAIN_MAX) return false;
        if(!kind || kind>9 || (t->class_id==1 && kind>7) ||
            (t->class_id==2 && kind!=1 && kind!=2 && kind!=4 && kind!=7) ||
            (t->class_id==3 && kind!=8) || (t->class_id==4 && kind!=9)) return false;
        for(size_t j=0;j<i;j++) if(t->entries[j].kind==kind) return false;
    }
    return true;
}
AuthStatus rp2350_store_transaction_encode(const Rp2350StoreTransaction *t,uint8_t *out,size_t capacity,size_t *length) {
    if(length) *length=0;
    if(!out || !length || !t) return AUTH_INVALID_ARGUMENT;
    if(!transaction_valid(t)) return AUTH_BAD_DATA;
    size_t total=8;
    for(size_t i=0;i<t->count;i++) {
        if(total>RP2350_STORE_PLAIN_MAX-8U || t->entries[i].length>RP2350_STORE_PLAIN_MAX-total-8U) return AUTH_CAPACITY;
        total+=8+t->entries[i].length;
    }
    if(capacity<total) return AUTH_CAPACITY;
    memset(out,0,8); store_put16(out,1); store_put16(out+2,t->count);
    size_t offset=8;
    for(size_t i=0;i<t->count;i++) {
        store_put16(out+offset,t->entries[i].kind); store_put16(out+offset+2,1);
        store_put32(out+offset+4,(uint32_t)t->entries[i].length);
        memcpy(out+offset+8,t->entries[i].data,t->entries[i].length); offset+=8+t->entries[i].length;
    }
    *length=total; return AUTH_OK;
}
AuthStatus rp2350_store_transaction_decode(uint16_t class_id,const uint8_t *in,size_t n,Rp2350StoreTransaction *t) {
    if(!t) return AUTH_INVALID_ARGUMENT;
    *t=(Rp2350StoreTransaction){0}; if(!in) return AUTH_INVALID_ARGUMENT;
    if(n<8 || n>RP2350_STORE_PLAIN_MAX || store_u16(in)!=1 || store_u32(in+4)) return AUTH_BAD_DATA;
    t->class_id=class_id; t->count=store_u16(in+2);
    if(!t->count || t->count>4) goto bad;
    size_t offset=8;
    for(size_t i=0;i<t->count;i++) {
        if(n-offset<8 || store_u16(in+offset+2)!=1) goto bad;
        size_t length=store_u32(in+offset+4);
        if(!length || length>n-offset-8U) goto bad;
        t->entries[i]=(Rp2350StoreEntry){store_u16(in+offset),in+offset+8,length};
        offset+=8+length;
    }
    if(offset!=n || !transaction_valid(t)) goto bad;
    return AUTH_OK;
bad:
    *t=(Rp2350StoreTransaction){0}; return AUTH_BAD_DATA;
}
