#include "storage_boot_internal.h"
void rp2350_store_boot_clear_internal(Rp2350StoreBootResult *out) {
    if(out) auth_secure_zero(out,sizeof(*out));
}
static AuthStatus virgin_partition(const Rp2350Flash *flash,uint8_t page[256]) {
    for(uint32_t at=0;at<RP2350_STORE_PARTITION_SIZE;at+=256U) {
        AuthStatus status=flash->read(flash->context,at,page,256);
        if(status!=AUTH_OK) return status==AUTH_NOT_FOUND ? AUTH_IO_ERROR : status;
        for(size_t i=0;i<256;i++) if(page[i]!=0xff) return AUTH_BAD_DATA;
    }
    return AUTH_OK;
}
AuthStatus rp2350_store_boot_internal(Rp2350StoreBootResult *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreBootWorkspace *w) {
    if(out) rp2350_store_boot_clear_internal(out);
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !config || !config->resolve || !config->hash || !config->key_inspect || !w)
        return AUTH_INVALID_ARGUMENT;
    bool virgin=false;
    AuthStatus status=rp2350_store_root_pair_open_internal(&w->root,flash,&config->policy,
        config->resolve,config->root_context,&w->io.roots);
    if(status==AUTH_NOT_FOUND) {
        status=virgin_partition(flash,w->io.blank);
        if(status==AUTH_OK) { out->state=RP2350_STORE_UNPROVISIONED; virgin=true; status=AUTH_NOT_FOUND; }
        goto done;
    }
    if(status!=AUTH_OK) goto done;
    status=rp2350_store_select_internal(&w->selection,flash,&w->root,&w->io.selectors);
    if(status!=AUTH_OK) goto done;
    if(w->selection.selector.state==2) {
        out->root=w->root; out->selection=w->selection; out->state=RP2350_STORE_RESETTING; goto done;
    }
    status=rp2350_store_recovery_checkpoint_begin(&w->recovery,w->selection.selector.generation,w->root.root.epoch,
        w->root.root.reset_generation,w->selection.selector.manifest_digest,config->hash,config->key_inspect,config->records_context);
    if(status!=AUTH_OK) goto done;
    status=rp2350_store_recovery_read_log(&w->recovery,&w->log,flash,&w->root.seal,
        w->selection.arena_base,RP2350_STORE_ARENA_SIZE,&w->io.log);
    if(status!=AUTH_OK) goto done;
    bool maintenance=false;
    status=rp2350_store_recovery_finish(&w->recovery,&out->records,&maintenance);
    if(status!=AUTH_OK) goto done;
    out->root=w->root; out->selection=w->selection;
    out->journal_end=w->log.end;
    out->state=maintenance ? RP2350_STORE_MAINTENANCE : RP2350_STORE_RECOVERED;
done:
    /* A missing selected arena/backend is a fault under an existing root. */
    if(status==AUTH_NOT_FOUND && !virgin) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK && !virgin) rp2350_store_boot_clear_internal(out);
    auth_secure_zero(w,sizeof(*w)); return status;
}
