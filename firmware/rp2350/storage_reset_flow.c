#include "storage_reset_flow_internal.h"
static AuthStatus phase_grant(void *ctx) {
    Rp2350StoreResetFlow *state=ctx;
    return state->busy && state->locked ? AUTH_OK : AUTH_BUSY;
}
static AuthStatus run(Rp2350StoreResetFlow *state,const Rp2350Flash *flash,const Rp2350StoreBootConfig *config,
        Rp2350Crypto *crypto,const Rp2350StoreResetHooks *hooks,Rp2350StoreResetFlowWorkspace *w,bool recovery) {
    if(state && state->busy) return AUTH_BUSY;
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!state || !flash || !flash->read || !config || !crypto || !hooks || !hooks->authorize ||
        !hooks->invalidate || !hooks->reinitialize || !w) return AUTH_INVALID_ARGUMENT;
    if(!flash->program_page || !flash->erase_sector || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    state->busy=true;
    AuthStatus status=hooks->authorize(hooks->context);
    if(status!=AUTH_OK) { state->busy=false; return status; }
    state->locked=true; state->complete=false;
    rp2350_crypto_invalidate_internal(crypto);
    status=hooks->invalidate(hooks->context); if(status!=AUTH_OK) goto done;
    if(!crypto->initialized || !crypto->keys_locked || crypto->faulted) { status=AUTH_CRYPTO_ERROR; goto done; }
    if(!recovery) {
        status=rp2350_store_reset_intent_internal(&w->selection,flash,config,phase_grant,state,&w->phase.intent);
        if(status!=AUTH_OK) goto done;
        status=rp2350_store_reset_erase_internal(&w->erased,flash,config,phase_grant,state,&w->phase.erase);
    } else status=rp2350_store_reset_recovery_erase_internal(&w->erased,flash,config,phase_grant,state,&w->phase.erase);
    if(status!=AUTH_OK) goto done;
    AuthCrypto primitives=rp2350_crypto_interface(crypto); AuthSecretCrypto secrets=rp2350_secret_interface(crypto);
    status=rp2350_store_provision_internal(&w->provisioned,flash,config,&primitives,&secrets,phase_grant,state,&w->phase.provision);
    if(status!=AUTH_OK) goto done;
    status=rp2350_store_boot_internal(&w->snapshot,flash,config,&w->phase.boot); if(status!=AUTH_OK) goto done;
    if(w->snapshot.state!=RP2350_STORE_RECOVERED || w->snapshot.records.metadata_count || w->snapshot.records.key_count ||
        w->snapshot.records.pin.set || w->snapshot.records.pin.retries!=AUTH_PIN_MAX_RETRIES ||
        w->snapshot.records.pin.min_length_rp_count!=0U) { status=AUTH_BAD_DATA; goto done; }
    status=rp2350_crypto_stage_epoch_internal(crypto,w->snapshot.records.global.handle_prefix,w->snapshot.records.global.handle_high);
    if(status!=AUTH_OK) goto done;
    status=hooks->reinitialize(hooks->context,&w->snapshot.records); if(status!=AUTH_OK) goto done;
    status=rp2350_crypto_activate_internal(crypto); if(status!=AUTH_OK) goto done;
    state->complete=true; state->locked=false;
done:
    if(status!=AUTH_OK) {
        rp2350_crypto_invalidate_internal(crypto);
        (void)hooks->invalidate(hooks->context);
        state->locked=true; state->complete=false;
    }
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    state->status=status; state->busy=false;
    auth_secure_zero(w,sizeof(*w)); return status;
}
AuthStatus rp2350_store_reset_flow_internal(Rp2350StoreResetFlow *s,const Rp2350Flash *f,const Rp2350StoreBootConfig *c,
        Rp2350Crypto *p,const Rp2350StoreResetHooks *h,Rp2350StoreResetFlowWorkspace *w) { return run(s,f,c,p,h,w,false); }
AuthStatus rp2350_store_reset_recovery_flow_internal(Rp2350StoreResetFlow *s,const Rp2350Flash *f,const Rp2350StoreBootConfig *c,
        Rp2350Crypto *p,const Rp2350StoreResetHooks *h,Rp2350StoreResetFlowWorkspace *w) { return run(s,f,c,p,h,w,true); }
