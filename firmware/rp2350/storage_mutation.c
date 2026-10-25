#include "storage_mutation_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static Rp2350StoreVersion version(const Rp2350StoreBootResult *s) {
    Rp2350StoreVersion v={.root_serial=s->root.root.serial,.selector_serial=s->selection.selector.serial,
        .generation=s->selection.selector.generation,.logical_sequence=s->records.logical_sequence};
    memcpy(v.epoch,s->root.root.epoch,16); return v;
}
static bool same_version(const Rp2350StoreVersion *a,const Rp2350StoreVersion *b) {
    return a->root_serial==b->root_serial && a->selector_serial==b->selector_serial && a->generation==b->generation &&
        a->logical_sequence==b->logical_sequence && store_equal(a->epoch,b->epoch,16);
}
static AuthStatus matches(Rp2350StoreMutationWorkspace *w,const Rp2350StoreBootConfig *c) {
    (void)c;
    const Rp2350StoreReplayState *a=&w->expected,*b=&w->after.records;
    if(a->metadata_count!=b->metadata_count || a->key_count!=b->key_count || a->logical_sequence!=b->logical_sequence ||
        a->last_sequence!=b->last_sequence) return AUTH_BAD_DATA;
    AuthStatus status=rp2350_store_global_encode(&a->global,w->left);
    if(status==AUTH_OK) status=rp2350_store_global_encode(&b->global,w->right);
    if(status!=AUTH_OK) return status;
    if(!store_equal(w->left,w->right,96)) return AUTH_BAD_DATA;
    status=rp2350_store_pin_encode(&a->pin,w->left);
    if(status==AUTH_OK) status=rp2350_store_pin_encode(&b->pin,w->right);
    if(status!=AUTH_OK) return status;
    if(!store_equal(w->left,w->right,24)) return AUTH_BAD_DATA;
    for(size_t i=0;i<a->metadata_count;i++) {
        if(!rp2350_store_metadata_index_equal_internal(&a->metadata[i],&b->metadata[i]) ||
            a->metadata[i].sequence!=b->metadata[i].sequence) return AUTH_BAD_DATA;
    }
    for(size_t i=0;i<a->key_count;i++) if(a->keys[i].retired!=b->keys[i].retired ||
        a->keys[i].sequence!=b->keys[i].sequence || !store_equal(a->keys[i].digest,b->keys[i].digest,32) ||
        !store_equal(a->keys[i].handle.bytes,b->keys[i].handle.bytes,32)) return AUTH_BAD_DATA;
    return AUTH_OK;
}
static AuthStatus run(Rp2350StoreMutationWriter *writer,Rp2350StoreMutationReceipt *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,const Rp2350StoreVersion *expected,const Rp2350StoreTransaction *tx,
        Rp2350StoreMutationWorkspace *w,bool commit) {
    if(writer && writer->busy) return AUTH_BUSY;
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!writer || !out || !flash || !flash->read || !config || !w || (commit && (!expected || !tx))) return AUTH_INVALID_ARGUMENT;
    if(commit && writer->locked) return AUTH_BUSY;
    writer->busy=true; writer->locked=true;
    AuthStatus status=AUTH_UNSUPPORTED;
    if(config->policy.profile!=1 || config->policy.backend || (commit && !flash->program_page)) goto done;
    status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot); if(status!=AUTH_OK) goto done;
    if(w->source.state!=RP2350_STORE_RECOVERED && w->source.state!=RP2350_STORE_MAINTENANCE) { status=AUTH_BUSY; goto done; }
    Rp2350StoreVersion before=version(&w->source);
    if(commit) {
        if(!same_version(&before,expected) || tx->class_id!=1) { status=AUTH_BAD_DATA; goto done; }
        status=rp2350_store_recovery_begin(&w->boot.recovery,&w->source.records,before.generation,before.epoch,
            config->hash,config->key_inspect,config->records_context); if(status!=AUTH_OK) goto done;
        Rp2350StoreIdentity id={.class_id=1,.sequence=w->source.records.last_sequence+1U,.generation=before.generation};
        memcpy(id.epoch,before.epoch,16);
        status=rp2350_store_recovery_apply(&w->boot.recovery,&id,tx); if(status!=AUTH_OK) goto done;
        w->expected=w->boot.recovery.staged; rp2350_store_recovery_abort(&w->boot.recovery);
        size_t n=0; status=rp2350_store_transaction_encode(tx,w->plain,sizeof(w->plain),&n); if(status!=AUTH_OK) goto done;
        status=rp2350_store_log_open_internal(&w->log,flash,&w->source.root.seal,w->source.selection.arena_base,
            RP2350_STORE_ARENA_SIZE,before.generation,before.epoch,NULL,NULL,&w->boot.io.log); if(status!=AUTH_OK) goto done;
        if(w->log.next_sequence!=id.sequence) { status=AUTH_BAD_DATA; goto done; }
        status=rp2350_store_log_append_internal(&w->log,1,w->plain,n,&w->boot.io.log); if(status!=AUTH_OK) goto done;
        status=rp2350_store_boot_internal(&w->after,flash,config,&w->boot); if(status!=AUTH_OK) goto done;
        Rp2350StoreVersion after=version(&w->after); before.logical_sequence++;
        if(!same_version(&before,&after) || (w->after.state!=RP2350_STORE_RECOVERED && w->after.state!=RP2350_STORE_MAINTENANCE)) {
            status=AUTH_BAD_DATA; goto done;
        }
        status=matches(w,config); if(status!=AUTH_OK) goto done;
        out->version=after; out->maintenance=w->after.state==RP2350_STORE_MAINTENANCE;
    } else { out->version=before; out->maintenance=w->source.state==RP2350_STORE_MAINTENANCE; }
    writer->locked=false; out->verified=true;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    writer->busy=false; auth_secure_zero(w,sizeof(*w)); return status;
}
AuthStatus rp2350_store_mutation_open_internal(Rp2350StoreMutationWriter *s,Rp2350StoreMutationReceipt *o,const Rp2350Flash *f,
        const Rp2350StoreBootConfig *c,Rp2350StoreMutationWorkspace *w) { return run(s,o,f,c,NULL,NULL,w,false); }
AuthStatus rp2350_store_mutation_commit_internal(Rp2350StoreMutationWriter *s,Rp2350StoreMutationReceipt *o,const Rp2350Flash *f,
        const Rp2350StoreBootConfig *c,const Rp2350StoreVersion *v,const Rp2350StoreTransaction *tx,Rp2350StoreMutationWorkspace *w) {
    return run(s,o,f,c,v,tx,w,true);
}
