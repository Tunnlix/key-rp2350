#include "storage_compaction_internal.h"
#include "storage_bytes_internal.h"
static AuthStatus audit(Rp2350StoreMaintenance *out,const Rp2350Flash *flash,const Rp2350StoreBootConfig *config,
        Rp2350StoreCheckpointWorkspace *w) {
    auth_secure_zero(out,sizeof(*out));
    AuthStatus status=rp2350_store_boot_internal(&w->source,flash,config,&w->boot); if(status!=AUTH_OK) return status;
    if(w->source.state!=RP2350_STORE_RECOVERED && w->source.state!=RP2350_STORE_MAINTENANCE) return AUTH_BUSY;
    out->selection=w->source.selection; out->active_key_cleanup=w->source.state==RP2350_STORE_MAINTENANCE;
    uint32_t base=out->selection.selector.arena ? RP2350_STORE_ARENA_A : RP2350_STORE_ARENA_B;
    /* Scan the whole owned bank; errors must not hide after the first dirty page. */
    for(uint32_t at=base;at<base+RP2350_STORE_ARENA_SIZE;at+=256U) {
        status=flash->read(flash->context,at,w->boot.io.log.page,256); if(status!=AUTH_OK) return status==AUTH_NOT_FOUND ? AUTH_IO_ERROR : status;
        for(size_t i=0;i<256;i++) if(w->boot.io.log.page[i]!=0xff) out->inactive_dirty=true;
    }
    out->clean=!out->inactive_dirty && !out->active_key_cleanup; return AUTH_OK;
}
static bool same(Rp2350StoreCheckpointWorkspace *w,const Rp2350StoreSelector *a,const Rp2350StoreSelector *b) {
    return rp2350_store_selector_encode(a,w->data)==AUTH_OK && rp2350_store_selector_encode(b,w->compare)==AUTH_OK &&
        store_equal(w->data,w->compare,80);
}
static AuthStatus scrub(const Rp2350Flash *flash,const Rp2350StoreBootConfig *config,Rp2350StoreCompactionWorkspace *w,
        const Rp2350StoreSelection *expected,uint64_t expected_root) {
    AuthStatus status=audit(&w->audit,flash,config,&w->scratch); if(status!=AUTH_OK) return status;
    if(expected && (w->scratch.source.root.root.serial!=expected_root || !same(&w->scratch,&expected->selector,&w->audit.selection.selector))) return AUTH_BAD_DATA;
    if(w->audit.active_key_cleanup) return AUTH_BUSY;
    Rp2350StoreSelector before=w->audit.selection.selector;
    uint64_t root_serial=w->scratch.source.root.root.serial;
    if(w->audit.inactive_dirty) {
        uint32_t base=before.arena ? RP2350_STORE_ARENA_A : RP2350_STORE_ARENA_B;
        for(uint32_t at=base;at<base+RP2350_STORE_ARENA_SIZE;at+=4096U) {
            /* A sparse inactive bank does not require 62 physical erases.
             * Skip a sector only after reading EVERY byte as erased. Dirty
             * sectors still receive a real erase and complete readback below.
             * The serialized owner and final full-bank audit remain required;
             * this optimization does not change the separate Reset eraser. */
            bool blank=true;
            for(uint32_t page=0;page<4096 && blank;page+=256U) {
                status=flash->read(flash->context,at+page,w->scratch.boot.io.log.page,256);
                if(status!=AUTH_OK) return status;
                for(size_t i=0;i<256;i++) if(w->scratch.boot.io.log.page[i]!=0xff) { blank=false; break; }
            }
            if(blank) continue;
            status=flash->erase_sector(flash->context,at); if(status!=AUTH_OK) return status;
            for(uint32_t page=0;page<4096;page+=256U) {
                status=flash->read(flash->context,at+page,w->scratch.boot.io.log.page,256); if(status!=AUTH_OK) return status;
                for(size_t i=0;i<256;i++) if(w->scratch.boot.io.log.page[i]!=0xff) return AUTH_IO_ERROR;
            }
        }
    }
    status=audit(&w->audit,flash,config,&w->scratch); if(status!=AUTH_OK) return status;
    if(!w->audit.clean || w->scratch.source.root.root.serial!=root_serial || !same(&w->scratch,&before,&w->audit.selection.selector)) return AUTH_BAD_DATA;
    return AUTH_OK;
}
static bool args(Rp2350StoreMaintenance *out,const Rp2350Flash *flash,const Rp2350StoreBootConfig *config,Rp2350StoreCompactionWorkspace *w) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    return out && flash && flash->read && config && w;
}
static AuthStatus finish(Rp2350StoreMaintenance *out,Rp2350StoreCompactionWorkspace *w,AuthStatus status,bool writer) {
    if(status==AUTH_NOT_FOUND && writer) status=AUTH_IO_ERROR;
    if(status==AUTH_OK) *out=w->audit; else auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}
static bool writable(const Rp2350Flash *flash,const Rp2350StoreBootConfig *config) {
    return flash->program_page && flash->erase_sector && config->policy.profile==1 && !config->policy.backend;
}
AuthStatus rp2350_store_maintenance_internal(Rp2350StoreMaintenance *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreCompactionWorkspace *w) {
    if(!args(out,flash,config,w)) return AUTH_INVALID_ARGUMENT;
    AuthStatus status=audit(&w->audit,flash,config,&w->scratch); return finish(out,w,status,false);
}
AuthStatus rp2350_store_compact_internal(Rp2350StoreMaintenance *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreCompactionWorkspace *w) {
    if(!args(out,flash,config,w)) return AUTH_INVALID_ARGUMENT;
    if(!writable(flash,config)) return AUTH_UNSUPPORTED;
    AuthStatus status=rp2350_store_checkpoint_stage_internal(&w->candidate,flash,config,&w->scratch);
    if(status==AUTH_OK) status=rp2350_store_selector_commit_internal(&w->committed,flash,config,&w->candidate,&w->scratch);
    if(status==AUTH_OK) status=scrub(flash,config,w,&w->committed,w->candidate.root_serial);
    return finish(out,w,status,true);
}
AuthStatus rp2350_store_compaction_resume_internal(Rp2350StoreMaintenance *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreCompactionWorkspace *w) {
    if(!args(out,flash,config,w)) return AUTH_INVALID_ARGUMENT;
    if(!writable(flash,config)) return AUTH_UNSUPPORTED;
    AuthStatus status=audit(&w->audit,flash,config,&w->scratch);
    if(status==AUTH_OK && w->audit.active_key_cleanup) {
        /* No trusted orphan-cleanup receipt survives a crash: fold the active
         * log afresh and commit a new authority before removing old copies. */
        auth_secure_zero(w,sizeof(*w)); return rp2350_store_compact_internal(out,flash,config,w);
    }
    if(status==AUTH_OK) status=scrub(flash,config,w,NULL,0);
    return finish(out,w,status,true);
}
