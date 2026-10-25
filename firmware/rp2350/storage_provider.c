#include "storage_provider_internal.h"
#include "storage_key_record_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static AuthStatus load_nonresident_key(Rp2350StoreProvider *,const AuthKeyHandle *);
static void release_nonresident(void *ctx) {
    Rp2350StoreProvider *p=ctx;
    if(!p || p->busy) return;
    auth_secure_zero(p->selected_id,sizeof(p->selected_id)); auth_secure_zero(p->selected_rp,sizeof(p->selected_rp));
    p->selected_nonresident=false; rp2350_crypto_clear_credentials_internal(p->crypto);
}
static Rp2350StoreVersion version(const Rp2350StoreBootResult *s) {
    Rp2350StoreVersion v={.root_serial=s->root.root.serial,.selector_serial=s->selection.selector.serial,
        .generation=s->selection.selector.generation,.logical_sequence=s->records.logical_sequence};
    memcpy(v.epoch,s->root.root.epoch,16); return v;
}
static bool same_version(const Rp2350StoreVersion *a,const Rp2350StoreVersion *b) {
    return a->root_serial==b->root_serial && a->selector_serial==b->selector_serial && a->generation==b->generation &&
        a->logical_sequence==b->logical_sequence && store_equal(a->epoch,b->epoch,16);
}
static void fault(Rp2350StoreProvider *p) {
    p->live=false; p->staged=false; p->writer.locked=true;
    rp2350_crypto_invalidate_internal(p->crypto);
    auth_secure_zero(&p->cache,sizeof(p->cache)); auth_secure_zero(&p->version,sizeof(p->version));
    p->journal_end=0;
    auth_secure_zero(p->selected_id,sizeof(p->selected_id)); auth_secure_zero(p->selected_rp,sizeof(p->selected_rp));
    p->selected_nonresident=false;
}
void rp2350_store_provider_close_internal(Rp2350StoreProvider *p) {
    if(!p || p->busy) return;
    fault(p); if(p->workspace) auth_secure_zero(p->workspace,sizeof(*p->workspace));
}
static bool begin(Rp2350StoreProvider *p) {
    if(!p || !p->live || p->busy || !p->crypto) return false;
    if(p->crypto->faulted || (p->crypto->keys_locked && !p->staged)) { fault(p); auth_secure_zero(p->workspace,sizeof(*p->workspace)); return false; }
    if(!p->crypto->keys_locked) p->staged=false;
    p->busy=true; return true;
}
static AuthStatus finish(Rp2350StoreProvider *p,AuthStatus status,bool mutation) {
    if(mutation && status!=AUTH_OK) fault(p);
    rp2350_crypto_clear_credentials_internal(p->crypto);
    auth_secure_zero(p->workspace,sizeof(*p->workspace)); p->busy=false; return status;
}
static AuthStatus refresh(Rp2350StoreProvider *p,bool exact) {
    Rp2350StoreCheckpointWorkspace *w=&p->workspace->phase.recovery;
    AuthStatus status=rp2350_store_boot_internal(&w->source,&p->flash,&p->config,&w->boot); if(status!=AUTH_OK) return status;
    if(w->source.state!=RP2350_STORE_RECOVERED && w->source.state!=RP2350_STORE_MAINTENANCE) return AUTH_BUSY;
    Rp2350StoreVersion v=version(&w->source);
    if(exact && !same_version(&v,&p->version)) return AUTH_BAD_DATA;
    p->cache=w->source.records; p->version=v; p->journal_end=w->source.journal_end; return AUTH_OK;
}
static bool pending_key(const Rp2350StoreProvider *p) {
    for(size_t k=0;k<p->cache.key_count;k++) {
        if(p->cache.keys[k].retired) continue;
        bool referenced=false;
        for(size_t i=0;i<p->cache.metadata_count;i++)
            if(store_equal(p->cache.keys[k].handle.bytes,p->cache.metadata[i].key.bytes,32)) { referenced=true; break; }
        if(!referenced) return true;
    }
    return false;
}
/* Reserve two maximum frames before beginning a normal multi-step operation.
 * Once a generated key is durable but not referenced, compaction would remove
 * it as an orphan. That brief serialized creation phase uses the reserve and
 * must finish/retire its key before maintenance is allowed again. */
static AuthStatus space_for_commit(Rp2350StoreProvider *p,size_t extent) {
    const uint32_t reserve=2U*RP2350_STORE_FRAME_MAX;
    if(p->journal_end>RP2350_STORE_ARENA_SIZE) return AUTH_BAD_DATA;
    uint32_t available=RP2350_STORE_ARENA_SIZE-p->journal_end;
    if(available<extent+reserve && !pending_key(p)) {
        Rp2350StoreMaintenance receipt;
        AuthStatus status=rp2350_store_compact_internal(&receipt,&p->flash,&p->config,&p->workspace->phase.compaction);
        if(status==AUTH_OK && !receipt.clean) status=AUTH_BAD_DATA;
        auth_secure_zero(&receipt,sizeof(receipt));
        if(status==AUTH_OK) status=refresh(p,false);
        if(status!=AUTH_OK) return status;
        if(p->journal_end>RP2350_STORE_ARENA_SIZE) return AUTH_BAD_DATA;
        available=RP2350_STORE_ARENA_SIZE-p->journal_end;
        if(available<extent+reserve) return AUTH_CAPACITY;
    }
    return available<extent ? AUTH_CAPACITY : AUTH_OK;
}
static AuthStatus commit(Rp2350StoreProvider *p,const Rp2350StoreTransaction *tx) {
    /* Freeze payloads before maintenance: callers may refer into the cache and
     * phase workspaces share memory. Never retry after an uncertain append. */
    size_t length=0,extent=0;
    AuthStatus status=rp2350_store_transaction_encode(tx,p->workspace->pending,sizeof(p->workspace->pending),&length);
    if(status==AUTH_OK) status=rp2350_store_frame_extent(length,&extent);
    if(status==AUTH_OK) status=space_for_commit(p,extent);
    Rp2350StoreTransaction pending;
    if(status==AUTH_OK) status=rp2350_store_transaction_decode(1,p->workspace->pending,length,&pending);
    if(status!=AUTH_OK) return status;
    Rp2350StoreMutationReceipt receipt;
    status=rp2350_store_mutation_commit_internal(&p->writer,&receipt,&p->flash,&p->config,&p->version,&pending,&p->workspace->phase.mutation);
    if(status==AUTH_OK) {
        p->version=receipt.version; status=refresh(p,true);
    }
    auth_secure_zero(&receipt,sizeof(receipt)); return status;
}
static AuthStatus maintenance(Rp2350StoreProvider *p) {
    Rp2350StoreMaintenance receipt;
    AuthStatus status=rp2350_store_compaction_resume_internal(&receipt,&p->flash,&p->config,&p->workspace->phase.compaction);
    if(status==AUTH_OK && !receipt.clean) status=AUTH_BAD_DATA;
    auth_secure_zero(&receipt,sizeof(receipt)); return status;
}
static AuthStatus recover(Rp2350StoreProvider *p,const Rp2350Flash *flash,const Rp2350StoreBootConfig *config,
        Rp2350Crypto *crypto,Rp2350StoreProviderWorkspace *w,bool activate) {
    if(p && (p->busy || p->live)) return AUTH_BUSY;
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!p || !flash || !flash->read || !config || !crypto || !w) return AUTH_INVALID_ARGUMENT;
    if(!flash->program_page || !flash->erase_sector || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    *p=(Rp2350StoreProvider){.crypto=crypto,.flash=*flash,.config=*config,.workspace=w,.busy=true};
    rp2350_crypto_invalidate_internal(crypto);
    AuthStatus status=maintenance(p); if(status!=AUTH_OK) goto done;
    status=refresh(p,false); if(status!=AUTH_OK) goto done;
    Rp2350StoreCheckpointWorkspace *capture=&w->phase.recovery;
    if(capture->source.state!=RP2350_STORE_RECOVERED) { status=AUTH_BUSY; goto done; }
    status=rp2350_store_checkpoint_keys_internal(capture,&p->flash,&p->config,&capture->source.selection,false); if(status!=AUTH_OK) goto done;
    status=rp2350_crypto_stage_epoch_internal(crypto,p->cache.global.handle_prefix,p->cache.global.handle_high); if(status!=AUTH_OK) goto done;
    if(activate) { status=rp2350_crypto_activate_internal(crypto); if(status!=AUTH_OK) goto done; }
    p->writer.locked=false; p->live=true; p->staged=!activate;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    return finish(p,status,true);
}
AuthStatus rp2350_store_provider_recover_internal(Rp2350StoreProvider *p,const Rp2350Flash *f,const Rp2350StoreBootConfig *c,
        Rp2350Crypto *crypto,Rp2350StoreProviderWorkspace *w) { return recover(p,f,c,crypto,w,true); }
AuthStatus rp2350_store_provider_stage_internal(Rp2350StoreProvider *p,const Rp2350Flash *f,const Rp2350StoreBootConfig *c,
        Rp2350Crypto *crypto,Rp2350StoreProviderWorkspace *w) { return recover(p,f,c,crypto,w,false); }
static size_t index_of(const Rp2350StoreProvider *p,const uint8_t id[32]) {
    for(size_t i=0;i<p->cache.metadata_count;i++) if(store_equal(id,p->cache.metadata[i].credential_id,32)) return i;
    return p->cache.metadata_count;
}
static AuthStatus load_metadata(Rp2350StoreProvider *p,size_t index,AuthCredential *out) {
    AuthStatus status=refresh(p,true);
    if(status!=AUTH_OK) return status;
    if(index>=p->cache.metadata_count) return AUTH_BAD_DATA;
    Rp2350StoreCheckpointWorkspace *w=&p->workspace->phase.recovery;
    status=rp2350_store_record_read_internal(&w->reader,&p->flash,&p->config,&w->source.root.seal,
        &w->source.selection,&p->cache.metadata[index],NULL,&w->boot.io.log);
    if(status==AUTH_OK) *out=w->reader.credential;
    return status;
}
static AuthStatus load_key(Rp2350StoreProvider *p,const AuthKeyHandle *handle) {
    if(!handle || !auth_key_handle_valid(handle)) return AUTH_INVALID_ARGUMENT;
    size_t k=0; while(k<p->cache.key_count && !store_equal(p->cache.keys[k].handle.bytes,handle->bytes,32)) k++;
    if(k==p->cache.key_count) return load_nonresident_key(p,handle);
    if(p->cache.keys[k].retired) return AUTH_NOT_FOUND;
    AuthStatus status=refresh(p,true);
    if(status!=AUTH_OK) return status;
    if(k>=p->cache.key_count || !store_equal(p->cache.keys[k].handle.bytes,handle->bytes,32) || p->cache.keys[k].retired) return AUTH_BAD_DATA;
    Rp2350StoreCheckpointWorkspace *w=&p->workspace->phase.recovery;
    status=rp2350_store_record_read_internal(&w->reader,&p->flash,&p->config,&w->source.root.seal,
        &w->source.selection,NULL,&p->cache.keys[k],&w->boot.io.log);
    if(status==AUTH_OK) status=rp2350_crypto_load_record_internal(p->crypto,w->reader.key);
    return status;
}
static AuthStatus read_record(void *ctx,const uint8_t id[32],AuthCredential *out) {
    Rp2350StoreProvider *p=ctx; if(!id || !out) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    size_t i=index_of(p,id); AuthStatus status=i==p->cache.metadata_count ? AUTH_NOT_FOUND : AUTH_OK;
    if(status==AUTH_OK) status=load_metadata(p,i,out);
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus enumerate(void *ctx,size_t i,AuthCredential *out) {
    Rp2350StoreProvider *p=ctx; if(!out) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    AuthStatus status=i>=p->cache.metadata_count ? AUTH_NOT_FOUND : AUTH_OK;
    if(status==AUTH_OK) status=load_metadata(p,i,out);
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus find_rp(void *ctx,const uint8_t rp[32],bool resident,size_t n,AuthCredential *out) {
    Rp2350StoreProvider *p=ctx; if(!rp || !out) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    AuthStatus status=AUTH_NOT_FOUND;
    for(size_t i=0;i<p->cache.metadata_count;i++) if((!resident || p->cache.metadata[i].discoverable) &&
        store_equal(rp,p->cache.metadata[i].rp_id_hash,32) && n--==0) { status=load_metadata(p,i,out); break; }
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus count(void *ctx,size_t *out) {
    Rp2350StoreProvider *p=ctx; if(!out) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    *out=p->cache.metadata_count; return finish(p,AUTH_OK,false);
}
static AuthStatus put(void *ctx,const uint8_t *old,const AuthCredential *in,const uint8_t *state) {
    Rp2350StoreProvider *p=ctx; if(!in) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    if(old && index_of(p,old)==p->cache.metadata_count) return finish(p,AUTH_NOT_FOUND,false);
    Rp2350StoreGlobal global=p->cache.global; if(state) memcpy(global.store_state,state,16);
    AuthStatus status=rp2350_store_global_encode(&global,p->workspace->global); size_t n=0;
    if(status==AUTH_OK) status=rp2350_store_metadata_encode(in,p->config.hash,p->config.records_context,
        p->workspace->metadata,sizeof(p->workspace->metadata),&n);
    if(status==AUTH_OK) {
        Rp2350StoreTransaction tx={.class_id=1,.count=2,.entries={{1,p->workspace->global,96},{2,p->workspace->metadata,(uint16_t)n}}};
        if(old) {
            const Rp2350StoreMetadataIndex *prior=&p->cache.metadata[index_of(p,old)];
            tx.count=4; tx.entries[2]=(Rp2350StoreEntry){3,old,32}; tx.entries[3]=(Rp2350StoreEntry){5,prior->key.bytes,32};
        }
        status=commit(p,&tx);
    }
    auth_secure_zero(&global,sizeof(global)); return finish(p,status,true);
}
static AuthStatus insert(void *ctx,const AuthCredential *in) {
    Rp2350StoreProvider *p=ctx;
    if(p && p->live && !p->busy && in && index_of(p,in->credential_id)<p->cache.metadata_count) return AUTH_ALREADY_EXISTS;
    return put(ctx,NULL,in,NULL);
}
static AuthStatus update(void *ctx,const AuthCredential *in,const uint8_t state[16]) {
    Rp2350StoreProvider *p=ctx; if(!in || !state) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    bool found=index_of(p,in->credential_id)<p->cache.metadata_count;
    (void)finish(p,AUTH_OK,false);
    return found ? put(ctx,NULL,in,state) : AUTH_NOT_FOUND;
}
static AuthStatus erase(void *ctx,const uint8_t id[32],const uint8_t *state) {
    Rp2350StoreProvider *p=ctx; if(!id) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    size_t i=index_of(p,id); if(i==p->cache.metadata_count) return finish(p,AUTH_NOT_FOUND,false);
    const Rp2350StoreMetadataIndex *prior=&p->cache.metadata[i];
    Rp2350StoreTransaction tx={.class_id=1,.count=2,.entries={{3,id,32},{5,prior->key.bytes,32}}};
    Rp2350StoreGlobal global=p->cache.global; AuthStatus status=AUTH_OK;
    if(state) { memcpy(global.store_state,state,16); status=rp2350_store_global_encode(&global,p->workspace->global);
        tx.entries[2]=(Rp2350StoreEntry){1,p->workspace->global,96}; tx.count=3; }
    if(status==AUTH_OK) status=commit(p,&tx);
    auth_secure_zero(&global,sizeof(global)); return finish(p,status,true);
}
static AuthStatus erase_plain(void *ctx,const uint8_t id[32]) { return erase(ctx,id,NULL); }
static AuthStatus counter(void *ctx,const uint8_t id[32],uint32_t expected,uint32_t next) {
    Rp2350StoreProvider *p=ctx; if(!id) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    Rp2350StoreCounter c={.expected=expected,.next=next}; memcpy(c.id,id,32);
    AuthStatus status=rp2350_store_counter_encode(&c,p->workspace->counter);
    Rp2350StoreTransaction tx={.class_id=1,.count=1,.entries={{6,p->workspace->counter,48}}};
    if(status==AUTH_OK) status=commit(p,&tx);
    return finish(p,status,true);
}
static AuthStatus pin_read(void *ctx,AuthPinRecord *out) {
    Rp2350StoreProvider *p=ctx; if(!out) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    *out=p->cache.pin; return finish(p,AUTH_OK,false);
}
static AuthStatus pin_write(void *ctx,const AuthPinRecord *in) {
    Rp2350StoreProvider *p=ctx; if(!in) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    AuthStatus status=rp2350_store_pin_encode(in,p->workspace->global);
    Rp2350StoreTransaction tx={.class_id=1,.count=1,.entries={{7,p->workspace->global,24}}};
    if(status==AUTH_OK) status=commit(p,&tx);
    return finish(p,status,true);
}
static AuthStatus random_bytes(void *ctx,uint8_t *out,size_t n) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,n); return AUTH_IO_ERROR; }
    AuthCrypto c=rp2350_crypto_interface(p->crypto); return finish(p,c.random(c.context,out,n),true);
}
static AuthStatus hash(void *ctx,const uint8_t *in,size_t n,uint8_t out[32]) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,32); return AUTH_IO_ERROR; }
    AuthCrypto c=rp2350_crypto_interface(p->crypto); return finish(p,c.sha256(c.context,in,n,out),true);
}
static AuthStatus generate(void *ctx,AuthKeyHandle *out,uint8_t pub[65]) {
    Rp2350StoreProvider *p=ctx; if(!out || !pub) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(out,sizeof(*out)); auth_secure_zero(pub,65); if(!begin(p)) return AUTH_IO_ERROR;
    AuthCrypto c=rp2350_crypto_interface(p->crypto); AuthKeyHandle handle={0}; uint8_t public_key[65]={0};
    AuthStatus status=c.generate_p256(c.context,&handle,public_key);
    if(status==AUTH_OK) {
        Rp2350Key *key=NULL;
        for(size_t i=0;i<RP2350_KEY_SLOTS;i++) if(p->crypto->keys[i].used && store_equal(handle.bytes,p->crypto->keys[i].handle.bytes,32)) key=&p->crypto->keys[i];
        if(!key) status=AUTH_BAD_DATA;
        else status=rp2350_key_record_encode_internal(key,p->workspace->key);
    }
    Rp2350StoreGlobal global=p->cache.global;
    if(status==AUTH_OK) { if(global.handle_high==UINT64_MAX) status=AUTH_CAPACITY; else global.handle_high++;
        if(status==AUTH_OK) status=rp2350_store_global_encode(&global,p->workspace->global); }
    Rp2350StoreTransaction tx={.class_id=1,.count=2,.entries={{1,p->workspace->global,96},{4,p->workspace->key,136}}};
    if(status==AUTH_OK) status=commit(p,&tx);
    if(status==AUTH_OK) { *out=handle; memcpy(pub,public_key,65); }
    auth_secure_zero(&handle,sizeof(handle)); auth_secure_zero(public_key,sizeof(public_key)); auth_secure_zero(&global,sizeof(global));
    return finish(p,status,true);
}
static AuthStatus public_key(void *ctx,const AuthKeyHandle *h,uint8_t out[65]) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,65); return AUTH_IO_ERROR; }
    AuthStatus status=load_key(p,h);
    if(status==AUTH_OK) { AuthCrypto c=rp2350_crypto_interface(p->crypto); status=c.public_key(c.context,h,out); }
    if(status!=AUTH_OK && out) auth_secure_zero(out,65);
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus sign(void *ctx,const AuthKeyHandle *h,const uint8_t d[32],uint8_t out[72],size_t *n) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,72); if(n) *n=0; return AUTH_IO_ERROR; }
    AuthStatus status=load_key(p,h);
    if(status==AUTH_OK) { AuthCrypto c=rp2350_crypto_interface(p->crypto); status=c.sign_p256_digest(c.context,h,d,out,n); }
    if(status!=AUTH_OK) { if(out) auth_secure_zero(out,72); if(n) *n=0; }
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus destroy(void *ctx,const AuthKeyHandle *h) {
    Rp2350StoreProvider *p=ctx; if(!h) return AUTH_INVALID_ARGUMENT; if(!begin(p)) return AUTH_IO_ERROR;
    for(size_t i=0;i<p->cache.metadata_count;i++) if(store_equal(h->bytes,p->cache.metadata[i].key.bytes,32)) return finish(p,AUTH_BUSY,false);
    size_t i=0; while(i<p->cache.key_count && !store_equal(h->bytes,p->cache.keys[i].handle.bytes,32)) i++;
    if(i==p->cache.key_count) return finish(p,AUTH_NOT_FOUND,false);
    AuthStatus status=AUTH_OK;
    if(!p->cache.keys[i].retired) {
        Rp2350StoreTransaction tx={.class_id=1,.count=1,.entries={{5,h->bytes,32}}}; status=commit(p,&tx);
    }
    if(status==AUTH_OK) status=maintenance(p);
    if(status==AUTH_OK) status=refresh(p,false);
    if(status==AUTH_OK) { AuthCrypto c=rp2350_crypto_interface(p->crypto); status=c.destroy_key(c.context,h); if(status==AUTH_NOT_FOUND) status=AUTH_OK; }
    return finish(p,status,true);
}
static AuthStatus agreement(void *ctx,uint8_t out[65]) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,65); return AUTH_IO_ERROR; }
    AuthSecretCrypto s=rp2350_secret_interface(p->crypto); return finish(p,s.key_agreement(s.context,out),true);
}
static AuthStatus shared(void *ctx,const uint8_t peer[65],uint8_t out[32]) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,32); return AUTH_IO_ERROR; }
    AuthSecretCrypto s=rp2350_secret_interface(p->crypto); AuthStatus status=s.ecdh(s.context,peer,out); return finish(p,status,status!=AUTH_BAD_DATA);
}
static AuthStatus mac(void *ctx,const uint8_t *key,size_t kn,const uint8_t *in,size_t n,uint8_t out[32]) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,32); return AUTH_IO_ERROR; }
    AuthSecretCrypto s=rp2350_secret_interface(p->crypto); return finish(p,s.hmac_sha256(s.context,key,kn,in,n,out),true);
}
static AuthStatus aes(void *ctx,bool encrypt,const uint8_t key[32],const uint8_t iv[16],const uint8_t *in,size_t n,uint8_t *out) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,n); return AUTH_IO_ERROR; }
    AuthSecretCrypto s=rp2350_secret_interface(p->crypto); return finish(p,s.aes256_cbc(s.context,encrypt,key,iv,in,n,out),true);
}
static AuthStatus supported(void *ctx,const AuthKeyHandle *h,bool *out) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) *out=false; return AUTH_IO_ERROR; }
    if(!out) return finish(p,AUTH_INVALID_ARGUMENT,false);
    *out=false; AuthStatus status=load_key(p,h);
    if(status==AUTH_OK) *out=true;
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus credential_mac(void *ctx,const AuthKeyHandle *h,bool uv,const uint8_t salt[32],uint8_t out[32]) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) { if(out) auth_secure_zero(out,32); return AUTH_IO_ERROR; }
    AuthStatus status=load_key(p,h);
    if(status==AUTH_OK) { AuthSecretCrypto s=rp2350_secret_interface(p->crypto); status=s.credential_hmac(s.context,h,uv,salt,out); }
    if(status!=AUTH_OK && out) auth_secure_zero(out,32);
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus regenerate(void *ctx) {
    Rp2350StoreProvider *p=ctx; if(!begin(p)) return AUTH_IO_ERROR;
    AuthSecretCrypto s=rp2350_secret_interface(p->crypto); return finish(p,s.regenerate(s.context),true);
}
AuthCrypto rp2350_store_provider_crypto_internal(Rp2350StoreProvider *p) { return (AuthCrypto){p,random_bytes,hash,generate,public_key,sign,destroy}; }
AuthSecretCrypto rp2350_store_provider_secrets_internal(Rp2350StoreProvider *p) { return (AuthSecretCrypto){p,agreement,shared,mac,aes,supported,credential_mac,regenerate}; }
AuthStorage rp2350_store_provider_storage_internal(Rp2350StoreProvider *p) {
    return (AuthStorage){p,AUTH_RESIDENT_MAX_COUNT,read_record,insert,erase_plain,find_rp,count,counter,enumerate,put,erase,update};
}
AuthPinStorage rp2350_store_provider_pin_internal(Rp2350StoreProvider *p) { return (AuthPinStorage){p,pin_read,pin_write}; }

static uint64_t handle_number(const AuthKeyHandle *h) {
    uint64_t value=0; for(size_t i=24;i<32;i++) value=(value<<8)|h->bytes[i]; return value;
}
static AuthStatus init_nonresident(Rp2350StoreProvider *p) {
    const Rp2350StoreRoot *root=&p->workspace->phase.recovery.source.root.root;
    if(root->profile!=1 || root->backend || root->descriptor_length!=32) return AUTH_UNSUPPORTED;
    AuthCrypto c=rp2350_crypto_interface(p->crypto); AuthSecretCrypto s=rp2350_secret_interface(p->crypto);
    return rp2350_nonresident_seal_init_internal(&p->workspace->nonresident_seal,&c,&s,root->descriptor,root->epoch);
}
/* Caller owns begin/finish. Freshly authenticate root/global state before
 * decoding, and never resolve a future or non-durable handle/issuance serial. */
static AuthStatus decode_nonresident(Rp2350StoreProvider *p,const uint8_t *id,size_t length,const uint8_t rp[32],uint8_t *policy) {
    if(length!=RP2350_NONRESIDENT_ID_SIZE) return AUTH_NOT_FOUND;
    AuthStatus status=refresh(p,true);
    if(status==AUTH_OK) status=init_nonresident(p);
    if(status==AUTH_OK) status=rp2350_nonresident_seal_open_internal(&p->workspace->nonresident_seal,
        id,length,rp,&p->workspace->nonresident_key,policy,&p->workspace->nonresident);
    if(status==AUTH_OK) {
        const AuthKeyHandle *h=&p->workspace->nonresident_key.handle;
        uint64_t number=handle_number(h);
        if(!store_equal(h->bytes,p->cache.global.handle_prefix,24) || !number || number>p->cache.global.handle_high ||
            store_u64(id+24)>p->cache.global.nonresident_issued) status=AUTH_NOT_FOUND;
    }
    return status;
}
static AuthStatus nonresident_metadata(Rp2350StoreProvider *p,const uint8_t *id,size_t length,
        const uint8_t rp[32],uint8_t policy,AuthCredential *out) {
    auth_secure_zero(out,sizeof(*out));
    AuthCrypto c=rp2350_crypto_interface(p->crypto);
    AuthStatus status=c.sha256(c.context,id,length,out->credential_id);
    if(status==AUTH_OK) {
        out->key=p->workspace->nonresident_key.handle; memcpy(out->rp_id_hash,rp,32);
        out->algorithm=AUTH_COSE_ALG_ES256; out->cred_protect=policy;
        out->signature_count=p->cache.global.nonresident_counter;
        if(!auth_credential_valid(out)) status=AUTH_BAD_DATA;
    }
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    return status;
}
static AuthStatus read_nonresident(void *ctx,const uint8_t *id,size_t length,const uint8_t rp[32],AuthCredential *out) {
    Rp2350StoreProvider *p=ctx;
    if(!p || !id || !rp || !out) return AUTH_INVALID_ARGUMENT;
    release_nonresident(p);
    if(!begin(p)) return AUTH_IO_ERROR;
    uint8_t policy=0; AuthStatus status=decode_nonresident(p,id,length,rp,&policy);
    if(status==AUTH_OK) status=nonresident_metadata(p,id,length,rp,policy,out);
    if(status==AUTH_OK) {
        memcpy(p->selected_id,id,length); memcpy(p->selected_rp,rp,32); p->selected_nonresident=true;
    }
    return finish(p,status,status!=AUTH_NOT_FOUND);
}
static AuthStatus load_nonresident_key(Rp2350StoreProvider *p,const AuthKeyHandle *h) {
    if(!p->selected_nonresident) return AUTH_NOT_FOUND;
    uint8_t policy=0;
    AuthStatus status=decode_nonresident(p,p->selected_id,sizeof(p->selected_id),p->selected_rp,&policy);
    if(status==AUTH_OK && !store_equal(h->bytes,p->workspace->nonresident_key.handle.bytes,32)) status=AUTH_NOT_FOUND;
    if(status==AUTH_OK) status=rp2350_key_record_encode_internal(&p->workspace->nonresident_key,p->workspace->key);
    if(status==AUTH_OK) status=rp2350_crypto_load_record_internal(p->crypto,p->workspace->key);
    return status;
}
static AuthStatus reserve_nonresident(void *ctx,uint64_t *serial) {
    Rp2350StoreProvider *p=ctx;
    Rp2350StoreGlobal g=p->cache.global;
    const AuthKeyHandle *h=&p->workspace->nonresident_key.handle;
    if(g.nonresident_issued>=UINT32_C(16777215) || g.handle_high==UINT64_MAX) return AUTH_CAPACITY;
    if(!store_equal(h->bytes,g.handle_prefix,24) || handle_number(h)!=g.handle_high+1U ||
        p->crypto->next_handle!=g.handle_high+1U) return AUTH_BAD_DATA;
    g.nonresident_issued++; g.handle_high++;
    AuthStatus status=rp2350_store_global_encode(&g,p->workspace->global);
    Rp2350StoreTransaction tx={.class_id=1,.count=1,.entries={{1,p->workspace->global,96}}};
    if(status==AUTH_OK) status=commit(p,&tx);
    if(status==AUTH_OK) *serial=p->cache.global.nonresident_issued;
    auth_secure_zero(&g,sizeof(g)); return status;
}
static AuthStatus create_nonresident(void *ctx,const uint8_t rp[32],uint8_t policy,
        AuthCredential *out,uint8_t id[AUTH_CREDENTIAL_ID_MAX_SIZE],size_t *length,uint8_t pub[65]) {
    Rp2350StoreProvider *p=ctx;
    if(!p || !rp || !out || !id || !length || !pub || policy<1 || policy>3) return AUTH_INVALID_ARGUMENT;
    if(p->busy) return AUTH_BUSY;
    auth_secure_zero(out,sizeof(*out)); auth_secure_zero(id,AUTH_CREDENTIAL_ID_MAX_SIZE); auth_secure_zero(pub,65); *length=0;
    release_nonresident(p);
    if(!begin(p)) return AUTH_IO_ERROR;
    AuthStatus status=refresh(p,true);
    if(status==AUTH_OK && (p->cache.global.nonresident_issued>=UINT32_C(16777215) ||
        p->cache.global.nonresident_counter==UINT32_MAX || p->cache.global.handle_high==UINT64_MAX))
        return finish(p,AUTH_CAPACITY,false);
    if(status==AUTH_OK) status=init_nonresident(p);
    AuthCrypto c=rp2350_crypto_interface(p->crypto); AuthKeyHandle handle={0}; uint8_t generated[65]={0};
    if(status==AUTH_OK) status=c.generate_p256(c.context,&handle,generated);
    if(status==AUTH_OK) {
        bool found=false;
        for(size_t i=0;i<RP2350_KEY_SLOTS;i++) if(p->crypto->keys[i].used && store_equal(p->crypto->keys[i].handle.bytes,handle.bytes,32)) {
            p->workspace->nonresident_key=p->crypto->keys[i]; found=true; break;
        }
        if(!found) status=AUTH_BAD_DATA;
    }
    if(status==AUTH_OK) status=rp2350_nonresident_seal_create_internal(&p->workspace->nonresident_seal,
        &p->workspace->nonresident_key,rp,policy,reserve_nonresident,p,p->selected_id,&p->workspace->nonresident);
    if(status==AUTH_OK) status=nonresident_metadata(p,p->selected_id,sizeof(p->selected_id),rp,policy,out);
    if(status==AUTH_OK) {
        memcpy(p->selected_rp,rp,32); p->selected_nonresident=true;
        memcpy(id,p->selected_id,sizeof(p->selected_id)); *length=sizeof(p->selected_id); memcpy(pub,generated,65);
    }
    auth_secure_zero(&handle,sizeof(handle)); auth_secure_zero(generated,sizeof(generated));
    return finish(p,status,true);
}
static AuthStatus counter_nonresident(void *ctx,const uint8_t *id,size_t length,const uint8_t rp[32],uint32_t expected,uint32_t next) {
    Rp2350StoreProvider *p=ctx;
    if(!p || !id || !rp) return AUTH_INVALID_ARGUMENT;
    if(!begin(p)) return AUTH_IO_ERROR;
    uint8_t policy=0; AuthStatus status=decode_nonresident(p,id,length,rp,&policy);
    if(status==AUTH_OK && (expected==UINT32_MAX || next!=expected+1U || p->cache.global.nonresident_counter!=expected)) status=AUTH_BAD_DATA;
    Rp2350StoreGlobal g=p->cache.global;
    if(status==AUTH_OK) { g.nonresident_counter=next; status=rp2350_store_global_encode(&g,p->workspace->global); }
    Rp2350StoreTransaction tx={.class_id=1,.count=1,.entries={{1,p->workspace->global,96}}};
    if(status==AUTH_OK) status=commit(p,&tx);
    auth_secure_zero(&g,sizeof(g)); return finish(p,status,status!=AUTH_NOT_FOUND);
}
AuthNonresidentProvider rp2350_store_provider_nonresident_internal(Rp2350StoreProvider *p) {
    return (AuthNonresidentProvider){p,create_nonresident,read_nonresident,counter_nonresident,release_nonresident};
}
