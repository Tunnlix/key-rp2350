#include "storage_selector_writer_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static bool same_selector(Rp2350StoreCheckpointWorkspace *w,const Rp2350StoreSelector *a,const Rp2350StoreSelector *b) {
    return rp2350_store_selector_encode(a,w->data)==AUTH_OK && rp2350_store_selector_encode(b,w->compare)==AUTH_OK &&
        store_equal(w->data,w->compare,80);
}
static AuthStatus write_record(Rp2350StoreCheckpointWorkspace *w,const Rp2350Flash *flash,uint32_t at,const Rp2350StoreSelector *s) {
    AuthStatus status=rp2350_store_selector_encode(s,w->data); if(status!=AUTH_OK) return status;
    Rp2350StoreTransaction tx={.class_id=4,.count=1,.entries={{9,w->data,80}}}; size_t n=0,extent=0;
    status=rp2350_store_transaction_encode(&tx,w->plain,sizeof(w->plain),&n); if(status!=AUTH_OK) return status;
    Rp2350StoreIdentity id={.class_id=4,.sequence=s->serial,.generation=w->source.root.root.serial};
    memcpy(id.epoch,w->source.root.root.epoch,16);
    Rp2350StoreLogWorkspace *io=&w->boot.io.log;
    status=rp2350_store_seal_internal(&w->source.root.seal,&id,at,w->plain,n,io->frame,512,&extent,&io->seal);
    if(status!=AUTH_OK) return status;
    if(extent!=512 || at>8192U-512U || at%512U) return AUTH_BAD_DATA;
    /* Readbacks precede the next page; commit is always last. */
    for(size_t page=0;page<512;page+=256) {
        status=flash->program_page(flash->context,at+(uint32_t)page,io->frame+page); if(status!=AUTH_OK) return status;
        status=flash->read(flash->context,at+(uint32_t)page,io->page,256); if(status!=AUTH_OK) return status;
        if(!store_equal(io->page,io->frame+page,256)) return AUTH_IO_ERROR;
    }
    status=flash->read(flash->context,at,io->frame,512); if(status!=AUTH_OK) return status;
    status=rp2350_store_open_internal(&w->source.root.seal,&id,at,io->frame,512,w->plain,96,&n,&io->seal);
    if(status!=AUTH_OK) return status;
    status=rp2350_store_transaction_decode(4,w->plain,n,&tx); if(status!=AUTH_OK) return status;
    return tx.count==1 && tx.entries[0].kind==9 && tx.entries[0].length==80 &&
        store_equal(tx.entries[0].data,w->data,80) ? AUTH_OK : AUTH_BAD_DATA;
}
static AuthStatus append_selector(Rp2350StoreCheckpointWorkspace *w,const Rp2350Flash *flash,const Rp2350StoreSelector *next) {
    AuthStatus status; Rp2350StoreSelection selected={0};
    /* Only a sector ending in the current selector can append the next serial.
     * Free slots beside stale selectors are not a valid append location. */
    uint32_t at=8192;
    for(size_t sector=0;sector<2;sector++) if((w->source.selection.current_mask&(1U<<sector)) && w->source.selection.used[sector]<8) {
        at=(uint32_t)sector*4096U+(uint32_t)w->source.selection.used[sector]*512U; break;
    }
    if(at==8192) {
        unsigned recycle=w->source.selection.current_mask==1 ? 1U : 0U;
        /* mask 2 preserves sector 1; mask 3 has two current copies. */
        uint32_t base=recycle*4096U; status=flash->erase_sector(flash->context,base); if(status!=AUTH_OK) return status;
        for(uint32_t page=0;page<4096;page+=256) {
            status=flash->read(flash->context,base+page,w->boot.io.log.page,256); if(status!=AUTH_OK) return status;
            for(size_t i=0;i<256;i++) if(w->boot.io.log.page[i]!=0xff) { status=AUTH_IO_ERROR; return status; }
        }
        Rp2350StoreSelector anchor=w->source.selection.selector;
        status=write_record(w,flash,base,&anchor); if(status!=AUTH_OK) return status;
        status=rp2350_store_select_internal(&selected,flash,&w->source.root,&w->boot.io.selectors); if(status!=AUTH_OK) return status;
        if(!same_selector(w,&anchor,&selected.selector)) { status=AUTH_BAD_DATA; return status; }
        at=base+512U;
    }
    return write_record(w,flash,at,next);
}
AuthStatus rp2350_store_selector_commit_internal(Rp2350StoreSelection *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,const Rp2350StoreCheckpointCandidate *candidate,Rp2350StoreCheckpointWorkspace *w) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !config || !candidate || !w) return AUTH_INVALID_ARGUMENT;
    if(!flash->program_page || !flash->erase_sector || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    AuthStatus status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot); if(status!=AUTH_OK) goto done;
    if(w->source.state!=RP2350_STORE_RECOVERED && w->source.state!=RP2350_STORE_MAINTENANCE) { status=AUTH_BUSY; goto done; }
    const Rp2350StoreSelector *old=&w->source.selection.selector,*next=&candidate->proposed_switch;
    uint32_t target=old->arena ? RP2350_STORE_ARENA_A : RP2350_STORE_ARENA_B;
    if(!candidate->verified || candidate->root_serial!=w->source.root.root.serial || old->serial==UINT64_MAX ||
        old->generation==UINT64_MAX || next->state!=1 || next->serial!=old->serial+1U || next->generation!=old->generation+1U ||
        next->arena!=(old->arena^1U) || next->reset_generation!=old->reset_generation || !store_equal(next->epoch,old->epoch,16) ||
        candidate->arena_base!=target || !candidate->bytes || candidate->bytes>RP2350_STORE_ARENA_SIZE-RP2350_STORE_FRAME_MAX) {
        status=AUTH_BAD_DATA; goto done;
    }
    status=rp2350_store_checkpoint_keys_internal(w,flash,config,&w->source.selection,false); if(status!=AUTH_OK) goto done;
    status=rp2350_store_recovery_checkpoint_begin(&w->boot.recovery,next->generation,w->source.root.root.epoch,
        next->reset_generation,next->manifest_digest,config->hash,config->key_inspect,config->records_context);
    if(status!=AUTH_OK) goto done;
    status=rp2350_store_recovery_read_log(&w->boot.recovery,&w->boot.log,flash,&w->source.root.seal,target,
        RP2350_STORE_ARENA_SIZE,&w->boot.io.log); if(status!=AUTH_OK) goto done;
    if(w->boot.log.end!=candidate->bytes) { status=AUTH_BAD_DATA; goto done; }
    status=rp2350_store_checkpoint_matches_internal(w,config); if(status!=AUTH_OK) goto done;
    Rp2350StoreSelection selected={.selector=*next,.arena_base=target,.validated=true};
    status=rp2350_store_checkpoint_keys_internal(w,flash,config,&selected,true); if(status!=AUTH_OK) goto done;
    bool maintenance=true;
    status=rp2350_store_recovery_finish(&w->boot.recovery,&w->source.records,&maintenance);
    if(status!=AUTH_OK) goto done;
    if(maintenance) { status=AUTH_BAD_DATA; goto done; }
    auth_secure_zero(&w->reader,sizeof(w->reader));
    status=append_selector(w,flash,next); if(status!=AUTH_OK) goto done;
    status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot); if(status!=AUTH_OK) goto done;
    if(w->source.state!=RP2350_STORE_RECOVERED || w->source.root.root.serial!=candidate->root_serial ||
        !same_selector(w,next,&w->source.selection.selector)) { status=AUTH_BAD_DATA; goto done; }
    *out=w->source.selection;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}

AuthStatus rp2350_store_reset_intent_internal(Rp2350StoreSelection *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreResetAuthorize authorize,void *context,Rp2350StoreCheckpointWorkspace *w) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !config || !authorize || !w) return AUTH_INVALID_ARGUMENT;
    if(!flash->program_page || !flash->erase_sector || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    /* Consume application authorization and latch RAM service off before even
     * reading persistence. This callback is never an automatic consent source. */
    AuthStatus status=authorize(context); if(status!=AUTH_OK) goto done;
    status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot); if(status!=AUTH_OK) goto done;
    if(w->source.state==RP2350_STORE_RESETTING) { *out=w->source.selection; goto done; }
    if(w->source.state!=RP2350_STORE_RECOVERED && w->source.state!=RP2350_STORE_MAINTENANCE) { status=AUTH_BUSY; goto done; }
    Rp2350StoreSelector next={0};
    const Rp2350StoreSelector *old=&w->source.selection.selector;
    if(old->serial==UINT64_MAX) { status=AUTH_BAD_DATA; goto done; }
    next.state=2; next.arena=0xff; next.serial=old->serial+1U;
    next.reset_generation=old->reset_generation; memcpy(next.epoch,old->epoch,16);
    uint64_t root_serial=w->source.root.root.serial;
    status=append_selector(w,flash,&next); if(status!=AUTH_OK) goto done;
    status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot); if(status!=AUTH_OK) goto done;
    if(w->source.state!=RP2350_STORE_RESETTING || w->source.root.root.serial!=root_serial ||
        !same_selector(w,&next,&w->source.selection.selector)) { status=AUTH_BAD_DATA; goto done; }
    *out=w->source.selection;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}
