#include "storage_reset_internal.h"
_Static_assert(RP2350_STORE_ARENA_A==0x4000U && RP2350_STORE_ARENA_A+RP2350_STORE_ARENA_SIZE==RP2350_STORE_ARENA_B &&
    RP2350_STORE_ARENA_B+RP2350_STORE_ARENA_SIZE==RP2350_STORE_PARTITION_SIZE,"Reset must cover the exact model partition");
static AuthStatus scan(const Rp2350Flash *flash,uint8_t page[256],bool *blank) {
    *blank=true;
    for(uint32_t at=0;at<RP2350_STORE_PARTITION_SIZE;at+=256U) {
        AuthStatus status=flash->read(flash->context,at,page,256); if(status!=AUTH_OK) return status;
        for(size_t i=0;i<256;i++) if(page[i]!=0xff) *blank=false;
    }
    return AUTH_OK;
}
static AuthStatus erase_sector(const Rp2350Flash *flash,uint32_t at,uint8_t page[256]) {
    AuthStatus status=flash->erase_sector(flash->context,at); if(status!=AUTH_OK) return status;
    for(uint32_t offset=0;offset<4096U;offset+=256U) {
        status=flash->read(flash->context,at+offset,page,256); if(status!=AUTH_OK) return status;
        for(size_t i=0;i<256;i++) if(page[i]!=0xff) return AUTH_IO_ERROR;
    }
    return AUTH_OK;
}
static AuthStatus erase_partition(const Rp2350Flash *flash,uint32_t last,uint8_t page[256]) {
    /* Exact partition geometry is a model constant, not chip qualification. */
    for(uint32_t at=RP2350_STORE_ARENA_A;at<RP2350_STORE_PARTITION_SIZE;at+=4096U) {
        AuthStatus status=erase_sector(flash,at,page); if(status!=AUTH_OK) return status;
    }
    for(uint32_t at=0x2000U;at<RP2350_STORE_ARENA_A;at+=4096U) {
        AuthStatus status=erase_sector(flash,at,page); if(status!=AUTH_OK) return status;
    }
    AuthStatus status=erase_sector(flash,last^4096U,page); if(status!=AUTH_OK) return status;
    return erase_sector(flash,last,page);
}
static AuthStatus run(Rp2350StoreResetErasure *out,const Rp2350Flash *flash,const Rp2350StoreBootConfig *config,
        Rp2350StoreResetAuthorize authorize,void *context,Rp2350StoreResetWorkspace *w,bool recovery) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !config || !authorize || !w || (!recovery && !config->resolve))
        return AUTH_INVALID_ARGUMENT;
    if(!flash->erase_sector || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    AuthStatus status=authorize(context); if(status!=AUTH_OK) goto done;
    uint32_t last=0;
    if(!recovery) {
        status=rp2350_store_root_pair_open_internal(&w->root,flash,&config->policy,config->resolve,config->root_context,&w->io.roots);
        if(status!=AUTH_OK) goto done;
        status=rp2350_store_select_internal(&w->selection,flash,&w->root,&w->io.selectors); if(status!=AUTH_OK) goto done;
        if(w->selection.selector.state!=2) { status=AUTH_BUSY; goto done; }
        if(!w->selection.current_mask || w->selection.current_mask>3) { status=AUTH_BAD_DATA; goto done; }
        last=(w->selection.current_mask&1U) ? 0 : 4096U;
    }
    /* Discard derived keys/root descriptor before destructive IO. No credential
     * records or private scalars were restored by the normal authority gate. */
    rp2350_store_root_authority_clear_internal(&w->root);
    auth_secure_zero(&w->selection,sizeof(w->selection));
    bool blank=false;
    status=scan(flash,w->io.page,&blank); if(status!=AUTH_OK) goto done;
    if(!blank) {
        status=erase_partition(flash,last,w->io.page); if(status!=AUTH_OK) goto done;
        status=scan(flash,w->io.page,&blank); if(status!=AUTH_OK) goto done;
        if(!blank) { status=AUTH_IO_ERROR; goto done; }
    }
    out->verified_blank=true;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}
AuthStatus rp2350_store_reset_erase_internal(Rp2350StoreResetErasure *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreResetAuthorize authorize,void *context,Rp2350StoreResetWorkspace *w) {
    return run(out,flash,config,authorize,context,w,false);
}
AuthStatus rp2350_store_reset_recovery_erase_internal(Rp2350StoreResetErasure *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreResetAuthorize authorize,void *context,Rp2350StoreResetWorkspace *w) {
    return run(out,flash,config,authorize,context,w,true);
}
