#include "storage_checkpoint_writer_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static AuthStatus encode_metadata(Rp2350StoreCheckpointWorkspace *w,const Rp2350Flash *flash,const Rp2350StoreBootConfig *c,size_t i,size_t *n) {
    AuthStatus status=rp2350_store_record_read_internal(&w->reader,flash,
        c,&w->source.root.seal,&w->source.selection,&w->source.records.metadata[i],NULL,&w->boot.io.log);
    if(status==AUTH_OK) status=rp2350_store_metadata_encode(&w->reader.credential,c->hash,c->records_context,w->data,sizeof(w->data),n);
    auth_secure_zero(&w->reader,sizeof(w->reader)); return status;
}
static AuthStatus append(Rp2350StoreCheckpointWorkspace *w,uint16_t class_id,uint16_t kind,size_t n,uint8_t digest[32]) {
    Rp2350StoreTransaction tx={.class_id=class_id,.count=1,.entries={{kind,w->data,n}}}; size_t length=0;
    AuthStatus status=rp2350_store_transaction_encode(&tx,w->plain,sizeof(w->plain),&length);
    if(status==AUTH_OK) status=rp2350_store_log_append_checkpoint_internal(&w->target,class_id,w->plain,length,&w->boot.io.log);
    auth_secure_zero(w->plain,sizeof(w->plain)); auth_secure_zero(w->data,sizeof(w->data));
    if(status!=AUTH_OK) return status;
    return w->target.flash.read(w->target.flash.context,w->target.base+w->target.end-256U+40U,digest,32);
}
static AuthStatus item(Rp2350StoreCheckpointWorkspace *w,uint16_t kind,size_t n) {
    if(w->items>=2U*AUTH_RESIDENT_MAX_COUNT+2U) return AUTH_CAPACITY;
    AuthStatus status=append(w,2,kind,n,w->ordered+24U+w->items*32U);
    if(status==AUTH_OK) w->items++;
    return status;
}
AuthStatus rp2350_store_checkpoint_keys_internal(Rp2350StoreCheckpointWorkspace *w,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,const Rp2350StoreSelection *selection,bool compare) {
    const Rp2350StoreReplayState *records=compare ? &w->boot.recovery.staged : &w->source.records;
    for(size_t i=0;i<w->source.records.metadata_count;i++) {
        size_t k=0; while(k<records->key_count && !store_equal(records->keys[k].handle.bytes,w->source.records.metadata[i].key.bytes,32)) k++;
        if(k==records->key_count || records->keys[k].retired) return AUTH_BAD_DATA;
        if(compare) {
            size_t prior=0; while(prior<w->source.records.key_count &&
                !store_equal(w->source.records.keys[prior].handle.bytes,records->keys[k].handle.bytes,32)) prior++;
            if(prior==w->source.records.key_count || !store_equal(w->source.records.keys[prior].digest,records->keys[k].digest,32)) return AUTH_BAD_DATA;
        }
        AuthStatus status=rp2350_store_record_read_internal(&w->reader,flash,config,&w->source.root.seal,
            selection,NULL,&records->keys[k],&w->boot.io.log);
        auth_secure_zero(&w->reader,sizeof(w->reader));
        if(status!=AUTH_OK) return status;
    }
    return AUTH_OK;
}
AuthStatus rp2350_store_checkpoint_matches_internal(Rp2350StoreCheckpointWorkspace *w,const Rp2350StoreBootConfig *c) {
    (void)c;
    const Rp2350StoreReplayState *a=&w->source.records,*b=&w->boot.recovery.staged;
    if(a->metadata_count!=b->metadata_count || b->key_count!=a->metadata_count || a->logical_sequence!=b->logical_sequence ||
        b->last_sequence!=3U+2U*a->metadata_count) return AUTH_BAD_DATA;
    AuthStatus status=rp2350_store_global_encode(&a->global,w->data);
    if(status==AUTH_OK) status=rp2350_store_global_encode(&b->global,w->compare);
    if(status!=AUTH_OK) return status;
    if(!store_equal(w->data,w->compare,96)) return AUTH_BAD_DATA;
    status=rp2350_store_pin_encode(&a->pin,w->data);
    if(status==AUTH_OK) status=rp2350_store_pin_encode(&b->pin,w->compare);
    if(status!=AUTH_OK) return status;
    if(!store_equal(w->data,w->compare,24)) return AUTH_BAD_DATA;
    for(size_t i=0;i<a->metadata_count;i++) {
        if(!rp2350_store_metadata_index_equal_internal(&a->metadata[i],&b->metadata[i]) || b->keys[i].retired ||
            !store_equal(b->keys[i].handle.bytes,a->metadata[i].key.bytes,32)) return AUTH_BAD_DATA;
        size_t source=0;
        while(source<a->key_count && !store_equal(a->keys[source].handle.bytes,b->keys[i].handle.bytes,32)) source++;
        if(source==a->key_count || !store_equal(a->keys[source].digest,b->keys[i].digest,32)) return AUTH_BAD_DATA;
    }
    return AUTH_OK;
}
AuthStatus rp2350_store_checkpoint_stage_internal(Rp2350StoreCheckpointCandidate *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreCheckpointWorkspace *w) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !config || !w) return AUTH_INVALID_ARGUMENT;
    if(!flash->program_page || !flash->erase_sector || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    AuthStatus status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot);
    if(status!=AUTH_OK) goto done;
    if(w->source.state!=RP2350_STORE_RECOVERED && w->source.state!=RP2350_STORE_MAINTENANCE) { status=AUTH_BUSY; goto done; }
    if(w->source.selection.selector.serial==UINT64_MAX || w->source.selection.selector.generation==UINT64_MAX) { status=AUTH_CAPACITY; goto done; }
    status=rp2350_store_checkpoint_keys_internal(w,flash,config,&w->source.selection,false);
    if(status!=AUTH_OK) goto done;
    /* Preflight all sizes/encodings and capture keys before any erase. */
    size_t needed=1536U+w->source.records.metadata_count*512U;
    for(size_t i=0;i<w->source.records.metadata_count;i++) {
        size_t n=0,extent=0;
        status=encode_metadata(w,flash,config,i,&n); if(status!=AUTH_OK) goto done;
        status=rp2350_store_frame_extent(n+16U,&extent); if(status!=AUTH_OK) goto done;
        needed+=extent;
    }
    if(needed>RP2350_STORE_ARENA_SIZE-RP2350_STORE_FRAME_MAX) { status=AUTH_CAPACITY; goto done; }
    uint32_t target=w->source.selection.selector.arena ? RP2350_STORE_ARENA_A : RP2350_STORE_ARENA_B;
    uint64_t generation=w->source.selection.selector.generation+1U;
    for(uint32_t at=target;at<target+RP2350_STORE_ARENA_SIZE;at+=4096U) {
        /* The inactive bank may already be completely blank after the last
         * scrub. Read every byte before skipping erase; any dirty byte still
         * requires physical erase and complete readback. Owner freezes all
         * mutations through staging/SWITCH, and target log open checks the
         * whole region again before any new checkpoint is published. */
        bool blank=true;
        for(uint32_t p=0;p<4096 && blank;p+=256U) {
            status=flash->read(flash->context,at+p,w->boot.io.log.page,256); if(status!=AUTH_OK) goto done;
            for(size_t i=0;i<256;i++) if(w->boot.io.log.page[i]!=0xff) { blank=false; break; }
        }
        if(blank) continue;
        status=flash->erase_sector(flash->context,at); if(status!=AUTH_OK) goto done;
        for(uint32_t p=0;p<4096;p+=256U) {
            status=flash->read(flash->context,at+p,w->boot.io.log.page,256); if(status!=AUTH_OK) goto done;
            for(size_t i=0;i<256;i++) if(w->boot.io.log.page[i]!=0xff) { status=AUTH_IO_ERROR; goto done; }
        }
    }
    status=rp2350_store_log_open_internal(&w->target,flash,&w->source.root.seal,target,RP2350_STORE_ARENA_SIZE,
        generation,w->source.root.root.epoch,NULL,NULL,&w->boot.io.log);
    if(status!=AUTH_NOT_FOUND || !w->target.initialized || w->target.end) { if(status==AUTH_OK || status==AUTH_NOT_FOUND) status=AUTH_BAD_DATA; goto done; }
    memcpy(w->ordered,"ctap-store-v2/checkpoint",24);
    Rp2350StoreManifest manifest={.metadata_count=(uint16_t)w->source.records.metadata_count,
        .key_count=(uint16_t)w->source.records.metadata_count,.last_sequence=w->source.records.logical_sequence};
    status=rp2350_store_global_encode(&w->source.records.global,w->data); if(status!=AUTH_OK) goto done;
    status=config->hash(config->records_context,w->data,96,manifest.global_digest); if(status!=AUTH_OK) goto done;
    status=item(w,1,96); if(status!=AUTH_OK) goto done;
    status=rp2350_store_pin_encode(&w->source.records.pin,w->data); if(status!=AUTH_OK) goto done;
    status=item(w,7,24); if(status!=AUTH_OK) goto done;
    for(size_t i=0;i<w->source.records.metadata_count;i++) {
        size_t n=0; status=encode_metadata(w,flash,config,i,&n); if(status!=AUTH_OK) goto done;
        status=item(w,2,n); if(status!=AUTH_OK) goto done;
    }
    for(size_t i=0;i<w->source.records.metadata_count;i++) {
        size_t k=0; while(k<w->source.records.key_count &&
            !store_equal(w->source.records.keys[k].handle.bytes,w->source.records.metadata[i].key.bytes,32)) k++;
        if(k==w->source.records.key_count) { status=AUTH_BAD_DATA; goto done; }
        status=rp2350_store_record_read_internal(&w->reader,flash,config,&w->source.root.seal,
            &w->source.selection,NULL,&w->source.records.keys[k],&w->boot.io.log);
        if(status!=AUTH_OK) goto done;
        memcpy(w->data,w->reader.key,136); auth_secure_zero(&w->reader,sizeof(w->reader));
        status=item(w,4,136); if(status!=AUTH_OK) goto done;
    }
    status=config->hash(config->records_context,w->ordered,24U+w->items*32U,manifest.ordered_digest); if(status!=AUTH_OK) goto done;
    status=rp2350_store_manifest_encode(&manifest,w->data); if(status!=AUTH_OK) goto done;
    uint8_t digest[32]; status=append(w,3,8,96,digest); if(status!=AUTH_OK) goto done;
    status=rp2350_store_recovery_checkpoint_begin(&w->boot.recovery,generation,w->source.root.root.epoch,
        w->source.root.root.reset_generation,digest,config->hash,config->key_inspect,config->records_context);
    if(status!=AUTH_OK) goto done;
    status=rp2350_store_recovery_read_log(&w->boot.recovery,&w->boot.log,flash,&w->source.root.seal,target,
        RP2350_STORE_ARENA_SIZE,&w->boot.io.log); if(status!=AUTH_OK) goto done;
    status=rp2350_store_checkpoint_matches_internal(w,config); if(status!=AUTH_OK) goto done;
    bool maintenance=true;
    status=rp2350_store_recovery_finish(&w->boot.recovery,&w->source.records,&maintenance);
    if(status!=AUTH_OK) goto done;
    if(maintenance || w->target.end!=needed) { status=AUTH_BAD_DATA; goto done; }
    out->proposed_switch=w->source.selection.selector; out->proposed_switch.serial++; out->proposed_switch.generation=generation;
    out->proposed_switch.arena^=1U; memcpy(out->proposed_switch.manifest_digest,digest,32);
    out->root_serial=w->source.root.root.serial; out->arena_base=target; out->bytes=w->target.end; out->verified=true;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}
