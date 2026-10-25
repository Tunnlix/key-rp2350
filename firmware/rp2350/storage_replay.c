#include "storage_replay_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>

AuthStatus rp2350_store_metadata_index_internal(Rp2350StoreMetadataIndex *out,AuthCredential *c,
        uint64_t sequence,Rp2350StoreHash hash,void *ctx,uint8_t *wire,size_t capacity) {
    if(!out || !c || !hash || !wire) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(out,sizeof(*out));
    if(!auth_credential_valid(c)) return AUTH_BAD_DATA;
    uint32_t counter=c->signature_count; size_t length=0;
    uint8_t names[2][AUTH_ENTITY_NAME_MAX_SIZE];
    uint8_t name_length=c->user_name_length,display_length=c->user_display_name_length;
    memcpy(names[0],c->user_name,sizeof(names[0])); memcpy(names[1],c->user_display_name,sizeof(names[1]));
    c->signature_count=0;
    AuthStatus status=rp2350_store_metadata_encode(c,hash,ctx,wire,capacity,&length);
    if(status==AUTH_OK) status=hash(ctx,wire,length,out->content_digest);
    auth_secure_zero(c->user_name,sizeof(c->user_name)); auth_secure_zero(c->user_display_name,sizeof(c->user_display_name));
    c->user_name_length=0; c->user_display_name_length=0;
    if(status==AUTH_OK) status=rp2350_store_metadata_encode(c,hash,ctx,wire,capacity,&length);
    if(status==AUTH_OK) status=hash(ctx,wire,length,out->identity_digest);
    c->signature_count=counter; c->user_name_length=name_length; c->user_display_name_length=display_length;
    memcpy(c->user_name,names[0],sizeof(names[0])); memcpy(c->user_display_name,names[1],sizeof(names[1]));
    auth_secure_zero(names,sizeof(names)); auth_secure_zero(wire,capacity);
    if(status!=AUTH_OK) { auth_secure_zero(out,sizeof(*out)); return status; }
    memcpy(out->credential_id,c->credential_id,32); memcpy(out->rp_id_hash,c->rp_id_hash,32);
    memcpy(out->user_id,c->user_id,c->user_id_length); out->key=c->key;
    out->sequence=sequence; out->creation_order=c->creation_order; out->signature_count=counter;
    out->algorithm=c->algorithm; out->rp_id_length=c->rp_id_length;
    out->user_id_length=c->user_id_length; out->cred_protect=c->cred_protect; out->discoverable=c->discoverable;
    out->user_name_length=c->user_name_length; out->user_display_name_length=c->user_display_name_length;
    return AUTH_OK;
}
bool rp2350_store_metadata_index_equal_internal(const Rp2350StoreMetadataIndex *a,const Rp2350StoreMetadataIndex *b) {
    return a->signature_count==b->signature_count && a->creation_order==b->creation_order &&
        a->algorithm==b->algorithm && a->rp_id_length==b->rp_id_length && a->user_id_length==b->user_id_length &&
        a->cred_protect==b->cred_protect && a->discoverable==b->discoverable &&
        a->user_name_length==b->user_name_length && a->user_display_name_length==b->user_display_name_length &&
        store_equal(a->credential_id,b->credential_id,32) && store_equal(a->key.bytes,b->key.bytes,32) &&
        store_equal(a->rp_id_hash,b->rp_id_hash,32) && store_equal(a->user_id,b->user_id,64) &&
        store_equal(a->content_digest,b->content_digest,32) && store_equal(a->identity_digest,b->identity_digest,32);
}

static uint64_t handle_number(const AuthKeyHandle *h) {
    uint64_t n=0; for(size_t i=24;i<32;i++) n=(n<<8)|h->bytes[i]; return n;
}
static size_t key_index(const Rp2350StoreReplayState *s,const AuthKeyHandle *h) {
    for(size_t i=0;i<s->key_count;i++) if(store_equal(s->keys[i].handle.bytes,h->bytes,32)) return i;
    return s->key_count;
}
static size_t metadata_index(const Rp2350StoreReplayState *s,const uint8_t id[32]) {
    for(size_t i=0;i<s->metadata_count;i++) if(store_equal(s->metadata[i].credential_id,id,32)) return i;
    return s->metadata_count;
}
static bool referenced(const Rp2350StoreReplayState *s,const AuthKeyHandle *h) {
    for(size_t i=0;i<s->metadata_count;i++) if(store_equal(s->metadata[i].key.bytes,h->bytes,32)) return true;
    return false;
}
static AuthStatus state_valid(const Rp2350StoreReplayState *s,Rp2350StoreHash hash,void *ctx) {
    (void)hash; (void)ctx;
    uint8_t global[96];
    if(s->metadata_count>AUTH_RESIDENT_MAX_COUNT || s->key_count>AUTH_RESIDENT_MAX_COUNT+1U ||
        rp2350_store_global_encode(&s->global,global)!=AUTH_OK || !auth_pin_record_valid(&s->pin)) return AUTH_BAD_DATA;
    for(size_t i=0;i<s->key_count;i++) {
        const AuthKeyHandle *h=&s->keys[i].handle;
        if(!store_equal(h->bytes,s->global.handle_prefix,24) || !handle_number(h) ||
            handle_number(h)>s->global.handle_high) return AUTH_BAD_DATA;
        for(size_t j=0;j<i;j++) if(store_equal(h->bytes,s->keys[j].handle.bytes,32)) return AUTH_BAD_DATA;
    }
    for(size_t i=0;i<s->metadata_count;i++) {
        const Rp2350StoreMetadataIndex *c=&s->metadata[i];
        size_t k=key_index(s,&c->key);
        if(!auth_key_handle_valid(&c->key) || c->algorithm!=-7 || c->cred_protect<1 || c->cred_protect>3 ||
            c->user_id_length>AUTH_USER_ID_MAX_SIZE || c->rp_id_length>AUTH_RP_ID_MAX_SIZE ||
            c->user_name_length>AUTH_ENTITY_NAME_MAX_SIZE || c->user_display_name_length>AUTH_ENTITY_NAME_MAX_SIZE ||
            !store_nonzero(c->credential_id,32) || k==s->key_count || s->keys[k].retired ||
            (c->discoverable && (!c->rp_id_length || !c->creation_order))) return AUTH_BAD_DATA;
        /* Full text/RP-hash consistency was checked while decoding the
         * authenticated record. Baselines here are trusted recovered indexes. */
        for(size_t j=0;j<i;j++) {
            const Rp2350StoreMetadataIndex *other=&s->metadata[j];
            if(store_equal(c->credential_id,other->credential_id,32) ||
                store_equal(c->key.bytes,other->key.bytes,32)) return AUTH_BAD_DATA;
            if(c->discoverable && other->discoverable &&
                (c->creation_order==other->creation_order ||
                (store_equal(c->rp_id_hash,other->rp_id_hash,32) && c->user_id_length==other->user_id_length &&
                store_equal(c->user_id,other->user_id,c->user_id_length)))) return AUTH_BAD_DATA;
        }
    }
    return AUTH_OK;
}
static AuthStatus fail(Rp2350StoreRecovery *r,AuthStatus status) {
    auth_secure_zero(r,sizeof(*r)); r->faulted=true; return status;
}
void rp2350_store_recovery_abort(Rp2350StoreRecovery *r) { if(r) auth_secure_zero(r,sizeof(*r)); }
AuthStatus rp2350_store_recovery_begin(Rp2350StoreRecovery *r,const Rp2350StoreReplayState *seed,
        uint64_t generation,const uint8_t epoch[16],Rp2350StoreHash hash,Rp2350StoreKeyInspect inspect,void *ctx) {
    if(!r) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(r,sizeof(*r));
    if(!seed || !epoch || !generation || !store_nonzero(epoch,16) || !hash || !inspect) return fail(r,AUTH_INVALID_ARGUMENT);
    if(CTAP_MESSAGE_CAPACITY>2048 || AUTH_RESIDENT_MAX_COUNT>32) return fail(r,AUTH_UNSUPPORTED);
    AuthStatus status=state_valid(seed,hash,ctx); if(status!=AUTH_OK) return fail(r,status);
    r->staged=*seed; r->hash=hash; r->key_inspect=inspect; r->context=ctx;
    r->generation=generation; memcpy(r->epoch,epoch,16); r->active=true; return AUTH_OK;
}
AuthStatus rp2350_store_recovery_checkpoint_begin(Rp2350StoreRecovery *r,uint64_t generation,
        const uint8_t epoch[16],uint64_t reset_generation,const uint8_t manifest_digest[32],
        Rp2350StoreHash hash,Rp2350StoreKeyInspect inspect,void *ctx) {
    if(!r) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(r,sizeof(*r));
    if(!generation || !epoch || !store_nonzero(epoch,16) || !reset_generation || !manifest_digest || !hash || !inspect)
        return fail(r,AUTH_INVALID_ARGUMENT);
    if(CTAP_MESSAGE_CAPACITY>2048 || AUTH_RESIDENT_MAX_COUNT>32) return fail(r,AUTH_UNSUPPORTED);
    r->hash=hash; r->key_inspect=inspect; r->context=ctx; r->generation=generation; r->reset_generation=reset_generation;
    memcpy(r->epoch,epoch,16); memcpy(r->manifest_digest,manifest_digest,32);
    memcpy(r->checkpoint_digests,"ctap-store-v2/checkpoint",24);
    r->active=true; r->checkpoint_mode=true; return AUTH_OK;
}
static bool global_identity(const Rp2350StoreGlobal *a,const Rp2350StoreGlobal *b) {
    return a->reset_generation==b->reset_generation && store_equal(a->handle_prefix,b->handle_prefix,24) &&
        store_equal(a->device_id,b->device_id,16) && b->attempt_high>=a->attempt_high;
}
static bool global_advance(const Rp2350StoreGlobal *a,const Rp2350StoreGlobal *b,bool standalone,bool key_create) {
    bool same_issued=a->nonresident_issued==b->nonresident_issued;
    bool same_counter=a->nonresident_counter==b->nonresident_counter;
    if(!standalone) return same_issued && same_counter && (key_create || a->handle_high==b->handle_high);
    if(!store_equal(a->store_state,b->store_state,16)) return false;
    bool same_attempt=a->attempt_high==b->attempt_high;
    bool same_handle=a->handle_high==b->handle_high;
    /* Three distinct atomic transitions: storage attempt reservation, sealed
     * issuance + its opaque handle allocation, or the shared signature counter.
     * No mixed transition, decrement, skipped issuance or wrapped counter. */
    if(same_issued && same_counter && same_handle) return b->attempt_high>a->attempt_high;
    if(!same_attempt) return false;
    if(same_counter && a->nonresident_issued<UINT32_C(16777215) && a->handle_high!=UINT64_MAX &&
        b->nonresident_issued==a->nonresident_issued+1U && b->handle_high==a->handle_high+1U) return true;
    return same_issued && same_handle && a->nonresident_counter!=UINT32_MAX &&
        b->nonresident_counter==a->nonresident_counter+1U;
}
static bool same_credential_except_names(const Rp2350StoreMetadataIndex *a,const Rp2350StoreMetadataIndex *b) {
    return a->signature_count==b->signature_count && store_equal(a->identity_digest,b->identity_digest,32);
}
AuthStatus rp2350_store_recovery_apply(void *ctx,const Rp2350StoreIdentity *id,const Rp2350StoreTransaction *tx) {
    Rp2350StoreRecovery *r=ctx;
    if(!r) return AUTH_INVALID_ARGUMENT;
    if(!r->active || r->faulted) return AUTH_IO_ERROR;
    if(r->verified) return fail(r,AUTH_BAD_DATA);
    if(r->checkpoint_mode && !r->checkpoint_ready) return fail(r,AUTH_BAD_DATA);
    if(!id || !tx) return fail(r,AUTH_INVALID_ARGUMENT);
    if(id->class_id!=1 || tx->class_id!=1 || !tx->count || tx->count>4 ||
        id->generation!=r->generation || !store_equal(id->epoch,r->epoch,16) ||
        r->staged.last_sequence==UINT64_MAX || r->staged.logical_sequence==UINT64_MAX ||
        id->sequence!=r->staged.last_sequence+1U) return fail(r,AUTH_BAD_DATA);
    const Rp2350StoreEntry *entry[8]={0}; unsigned mask=0; size_t total=8;
    for(size_t i=0;i<tx->count;i++) {
        const Rp2350StoreEntry *e=&tx->entries[i];
        if(!e->kind || e->kind>7 || entry[e->kind] || !e->data || !e->length ||
            total>RP2350_STORE_PLAIN_MAX-8U || e->length>RP2350_STORE_PLAIN_MAX-total-8U) return fail(r,AUTH_BAD_DATA);
        total+=8U+e->length;
        entry[e->kind]=e; mask|=1U<<e->kind;
    }
    /* Exact callback combinations; order inside an atomic transaction is irrelevant. */
    const unsigned global=1U<<1,upsert=1U<<2,del=1U<<3,create=1U<<4,retire=1U<<5,counter=1U<<6,pin=1U<<7;
    if(mask!=global && mask!=(global|create) && mask!=(global|upsert) &&
        mask!=(global|upsert|del|retire) && mask!=(del|retire) &&
        mask!=(global|del|retire) && mask!=retire && mask!=counter && mask!=pin) return fail(r,AUTH_BAD_DATA);
    r->candidate=r->staged; Rp2350StoreReplayState *s=&r->candidate;
    AuthStatus status=AUTH_BAD_DATA;
    if(entry[1]) {
        status=rp2350_store_global_decode(entry[1]->data,entry[1]->length,&s->global);
        if(status!=AUTH_OK) return fail(r,status);
        if(!global_identity(&r->staged.global,&s->global)) return fail(r,AUTH_BAD_DATA);
        if(!global_advance(&r->staged.global,&s->global,mask==global,(mask&create)!=0)) return fail(r,AUTH_BAD_DATA);
    }
    if(entry[4]) {
        AuthKeyHandle h={0};
        status=r->key_inspect(r->context,entry[4]->data,entry[4]->length,&h);
        if(status!=AUTH_OK) { auth_secure_zero(&h,sizeof(h)); return fail(r,status); }
        if(s->key_count==AUTH_RESIDENT_MAX_COUNT+1U || r->staged.global.handle_high==UINT64_MAX ||
            s->global.handle_high!=r->staged.global.handle_high+1U ||
            !store_equal(h.bytes,s->global.handle_prefix,24) || handle_number(&h)!=s->global.handle_high ||
            !store_equal(s->global.store_state,r->staged.global.store_state,16) || key_index(s,&h)!=s->key_count)
            return fail(r,AUTH_BAD_DATA);
        Rp2350StoreReplayKey *key=&s->keys[s->key_count++];
        *key=(Rp2350StoreReplayKey){.handle=h,.sequence=id->sequence,.offset=id->offset,.class_id=id->class_id};
        status=r->hash(r->context,entry[4]->data,entry[4]->length,key->digest);
        if(status!=AUTH_OK) return fail(r,status);
    }
    AuthKeyHandle deleted_key={0}; bool deleted_resident=false;
    if(entry[3]) {
        if(entry[3]->length!=32) return fail(r,AUTH_BAD_DATA);
        size_t i=metadata_index(s,entry[3]->data); if(i==s->metadata_count) return fail(r,AUTH_BAD_DATA);
        deleted_key=s->metadata[i].key;
        deleted_resident=s->metadata[i].discoverable;
        if(deleted_resident && !entry[1]) return fail(r,AUTH_BAD_DATA);
        for(size_t j=i+1;j<s->metadata_count;j++) s->metadata[j-1]=s->metadata[j];
        auth_secure_zero(&s->metadata[--s->metadata_count],sizeof(s->metadata[0]));
    }
    if(entry[2]) {
        status=rp2350_store_metadata_decode(entry[2]->data,entry[2]->length,r->hash,r->context,&r->decoded);
        if(status!=AUTH_OK) return fail(r,status);
        status=rp2350_store_metadata_index_internal(&r->indexed,&r->decoded,id->sequence,r->hash,r->context,
            r->canonical,sizeof(r->canonical));
        if(status!=AUTH_OK) return fail(r,status);
        r->indexed.offset=id->offset; r->indexed.class_id=id->class_id;
        if(entry[3]) {
            size_t old_index=metadata_index(&r->staged,entry[3]->data);
            const Rp2350StoreMetadataIndex *old=&r->staged.metadata[old_index];
            if(!old->discoverable || !r->decoded.discoverable ||
                !store_equal(old->rp_id_hash,r->decoded.rp_id_hash,32) ||
                old->user_id_length!=r->decoded.user_id_length ||
                !store_equal(old->user_id,r->decoded.user_id,old->user_id_length) ||
                store_equal(old->key.bytes,r->decoded.key.bytes,32)) return fail(r,AUTH_BAD_DATA);
        }
        size_t i=metadata_index(s,r->decoded.credential_id);
        if(i<s->metadata_count) {
            if(entry[3] || !r->decoded.discoverable || !same_credential_except_names(&s->metadata[i],&r->indexed))
                return fail(r,AUTH_BAD_DATA);
        } else {
            if(s->metadata_count==AUTH_RESIDENT_MAX_COUNT ||
                r->decoded.signature_count || (entry[3] && store_equal(entry[3]->data,r->decoded.credential_id,32)))
                return fail(r,AUTH_BAD_DATA);
            if(r->decoded.discoverable) for(size_t j=0;j<r->staged.metadata_count;j++)
                if(r->decoded.creation_order<=r->staged.metadata[j].creation_order) return fail(r,AUTH_BAD_DATA);
            i=s->metadata_count++;
        }
        s->metadata[i]=r->indexed;
    }
    if(entry[1] && (mask&(upsert|del))) {
        bool resident=deleted_resident;
        if(entry[2]) resident=resident || r->decoded.discoverable;
        bool same=store_equal(s->global.store_state,r->staged.global.store_state,16);
        if((resident && same) || (!resident && !same)) return fail(r,AUTH_BAD_DATA);
    }
    if(entry[5]) {
        if(entry[5]->length!=32) return fail(r,AUTH_BAD_DATA);
        AuthKeyHandle h; memcpy(h.bytes,entry[5]->data,32); size_t k=key_index(s,&h);
        if(k==s->key_count || referenced(s,&h) || (entry[3] && !store_equal(h.bytes,deleted_key.bytes,32))) return fail(r,AUTH_BAD_DATA);
        s->keys[k].retired=true;
    }
    if(entry[6]) {
        Rp2350StoreCounter c;
        status=rp2350_store_counter_decode(entry[6]->data,entry[6]->length,&c); if(status!=AUTH_OK) return fail(r,status);
        size_t i=metadata_index(s,c.id);
        if(i==s->metadata_count || s->metadata[i].signature_count!=c.expected) return fail(r,AUTH_BAD_DATA);
        s->metadata[i].signature_count=c.next;
    }
    if(entry[7]) {
        status=rp2350_store_pin_decode(entry[7]->data,entry[7]->length,&s->pin); if(status!=AUTH_OK) return fail(r,status);
    }
    status=state_valid(s,r->hash,r->context); if(status!=AUTH_OK) return fail(r,status);
    s->last_sequence=id->sequence; s->logical_sequence++; r->staged=*s;
    auth_secure_zero(&r->candidate,sizeof(r->candidate)); auth_secure_zero(&r->decoded,sizeof(r->decoded));
    auth_secure_zero(&r->indexed,sizeof(r->indexed));
    return AUTH_OK;
}
static AuthStatus checkpoint_frame(void *ctx,const Rp2350StoreIdentity *id,
        const Rp2350StoreTransaction *tx,const uint8_t digest[32]) {
    Rp2350StoreRecovery *r=ctx;
    if(!r->active || r->faulted) return AUTH_IO_ERROR;
    if(r->checkpoint_ready) return rp2350_store_recovery_apply(ctx,id,tx);
    if(id->generation!=r->generation || !store_equal(id->epoch,r->epoch,16) ||
        id->sequence!=r->checkpoint_items+1U || tx->class_id!=id->class_id || tx->count!=1)
        return fail(r,AUTH_BAD_DATA);
    const Rp2350StoreEntry *e=&tx->entries[0];
    Rp2350StoreReplayState *s=&r->candidate; AuthStatus status=AUTH_BAD_DATA;
    if(id->class_id==3) {
        Rp2350StoreManifest m; uint8_t ordered[32]={0};
        if(e->kind!=8 || !r->have_global || !r->have_pin || !store_equal(digest,r->manifest_digest,32))
            return fail(r,AUTH_BAD_DATA);
        status=rp2350_store_manifest_decode(e->data,e->length,&m);
        if(status!=AUTH_OK) return fail(r,status);
        if(m.metadata_count!=s->metadata_count || m.key_count!=s->key_count ||
            !store_equal(m.global_digest,r->global_digest,32) || s->global.reset_generation!=r->reset_generation)
            return fail(r,AUTH_BAD_DATA);
        status=r->hash(r->context,r->checkpoint_digests,24U+r->checkpoint_items*32U,ordered);
        bool equal=status==AUTH_OK && store_equal(ordered,m.ordered_digest,32);
        auth_secure_zero(ordered,sizeof(ordered));
        if(status!=AUTH_OK) return fail(r,status);
        if(!equal) return fail(r,AUTH_BAD_DATA);
        status=state_valid(s,r->hash,r->context); if(status!=AUTH_OK) return fail(r,status);
        s->last_sequence=id->sequence; s->logical_sequence=m.last_sequence; r->staged=*s;
        auth_secure_zero(&r->candidate,sizeof(r->candidate)); auth_secure_zero(&r->decoded,sizeof(r->decoded));
        auth_secure_zero(r->checkpoint_digests,sizeof(r->checkpoint_digests));
        auth_secure_zero(r->global_digest,sizeof(r->global_digest));
        r->checkpoint_ready=true; return AUTH_OK;
    }
    if(id->class_id!=2 || r->checkpoint_items>=2U*AUTH_RESIDENT_MAX_COUNT+3U) return fail(r,AUTH_BAD_DATA);
    if(e->kind==1 && !r->have_global) {
        status=rp2350_store_global_decode(e->data,e->length,&s->global);
        if(status==AUTH_OK) status=r->hash(r->context,e->data,e->length,r->global_digest);
        r->have_global=true;
    } else if(e->kind==7 && !r->have_pin) {
        status=rp2350_store_pin_decode(e->data,e->length,&s->pin); r->have_pin=true;
    } else if(e->kind==2 && s->metadata_count<AUTH_RESIDENT_MAX_COUNT) {
        status=rp2350_store_metadata_decode(e->data,e->length,r->hash,r->context,&r->decoded);
        if(status==AUTH_OK) status=rp2350_store_metadata_index_internal(&s->metadata[s->metadata_count],&r->decoded,
            id->sequence,r->hash,r->context,r->canonical,sizeof(r->canonical));
        if(status==AUTH_OK) s->metadata_count++;
        if(status==AUTH_OK) { s->metadata[s->metadata_count-1U].offset=id->offset; s->metadata[s->metadata_count-1U].class_id=id->class_id; }
        auth_secure_zero(&r->decoded,sizeof(r->decoded));
    } else if(e->kind==4 && s->key_count<AUTH_RESIDENT_MAX_COUNT+1U) {
        AuthKeyHandle h={0}; status=r->key_inspect(r->context,e->data,e->length,&h);
        if(status==AUTH_OK) {
            if(!auth_key_handle_valid(&h) || key_index(s,&h)!=s->key_count) status=AUTH_BAD_DATA;
            else {
                Rp2350StoreReplayKey *key=&s->keys[s->key_count++];
                *key=(Rp2350StoreReplayKey){.handle=h,.sequence=id->sequence,.offset=id->offset,.class_id=id->class_id};
                status=r->hash(r->context,e->data,e->length,key->digest);
            }
        }
        auth_secure_zero(&h,sizeof(h));
    }
    if(status!=AUTH_OK) return fail(r,status);
    memcpy(r->checkpoint_digests+24U+r->checkpoint_items*32U,digest,32); r->checkpoint_items++;
    return AUTH_OK;
}
AuthStatus rp2350_store_recovery_read_log(Rp2350StoreRecovery *r,Rp2350StoreLog *log,
        const Rp2350Flash *flash,Rp2350StoreSeal *seal,uint32_t base,uint32_t size,Rp2350StoreLogWorkspace *w) {
    if(!r) return AUTH_INVALID_ARGUMENT;
    if(!r->active || r->faulted) return AUTH_IO_ERROR;
    if(r->verified || r->staged.last_sequence || !log || !w) return fail(r,AUTH_INVALID_ARGUMENT);
    AuthStatus status;
    if(r->checkpoint_mode) status=rp2350_store_log_open_frames_internal(log,flash,seal,base,size,r->generation,r->epoch,
        checkpoint_frame,r,w);
    else status=rp2350_store_log_open_internal(log,flash,seal,base,size,r->generation,r->epoch,
        rp2350_store_recovery_apply,r,w);
    if(status!=AUTH_OK) return fail(r,status);
    if(r->checkpoint_mode && !r->checkpoint_ready) return fail(r,AUTH_BAD_DATA);
    r->verified=true; return AUTH_OK;
}
AuthStatus rp2350_store_recovery_finish(Rp2350StoreRecovery *r,Rp2350StoreReplayState *out,bool *maintenance) {
    if(!r || !out || !maintenance) return AUTH_INVALID_ARGUMENT;
    if(!r->active || r->faulted || !r->verified) return AUTH_IO_ERROR;
    AuthStatus status=state_valid(&r->staged,r->hash,r->context); if(status!=AUTH_OK) return fail(r,status);
    bool pending=false;
    for(size_t i=0;i<r->staged.key_count;i++) if(r->staged.keys[i].retired ||
        !referenced(&r->staged,&r->staged.keys[i].handle)) pending=true;
    *out=r->staged; *maintenance=pending; rp2350_store_recovery_abort(r); return AUTH_OK;
}
