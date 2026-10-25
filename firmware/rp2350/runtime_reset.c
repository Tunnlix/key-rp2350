#include "runtime_reset_internal.h"
static bool reset_callback(void *);
static AuthStatus authorize(void *ctx) {
    Rp2350RuntimeReset *r=ctx; CtaphidCtapBackend *b=r->backend;
    bool valid=b->pending && b->awaiting_reset && b->reset_authorized && b->operation_id && b->operation_id!=r->consumed_operation &&
        b->presence.operation_id==b->operation_id && b->presence.result==CTAP_PRESENCE_CONFIRMED &&
        !b->reset.authorized_operation && b->reset.reset_storage==reset_callback && b->reset.storage_context==r &&
        b->credentials==r->service && b->pin==r->pin;
    if(valid) r->consumed_operation=b->operation_id;
    return valid ? AUTH_OK : AUTH_BUSY;
}
static AuthStatus invalidate(void *ctx) {
    Rp2350RuntimeReset *r=ctx; CtaphidCtapBackend *b=r->backend;
    ctap_client_pin_invalidate(r->pin); r->pin->faulted=true;
    auth_secure_zero(r->service,sizeof(*r->service));
    ctap_assertion_sequence_clear(&b->assertion_sequence); ctap_credential_management_clear(&b->management);
    b->assertion_cid=b->management_cid=0;
    auth_secure_zero(&b->make_credential,sizeof(b->make_credential));
    auth_secure_zero(&b->make_credential_workspace,sizeof(b->make_credential_workspace));
    auth_secure_zero(&b->get_assertion,sizeof(b->get_assertion));
    auth_secure_zero(&b->get_assertion_workspace,sizeof(b->get_assertion_workspace));
    auth_secure_zero(&b->pin_request,sizeof(b->pin_request));
    auth_secure_zero(b->credential_request,sizeof(b->credential_request)); b->credential_request_length=0;
    if(r->store->busy) return AUTH_BUSY;
    rp2350_store_provider_close_internal(r->store); return AUTH_OK;
}
static AuthStatus reinitialize(void *ctx,const Rp2350StoreReplayState *state) {
    Rp2350RuntimeReset *r=ctx;
    if(state->metadata_count || state->key_count || state->pin.set || state->pin.retries!=8 ||
        state->global.nonresident_issued || state->global.nonresident_counter) return AUTH_BAD_DATA;
    AuthStatus status=rp2350_store_provider_stage_internal(r->store,&r->flash,&r->config,r->crypto,r->store_workspace);
    if(status!=AUTH_OK) return status;
    AuthCrypto c=rp2350_store_provider_crypto_internal(r->store); AuthStorage storage=rp2350_store_provider_storage_internal(r->store);
    AuthSecretCrypto secrets=rp2350_store_provider_secrets_internal(r->store); AuthPinStorage pin=rp2350_store_provider_pin_internal(r->store);
    AuthNonresidentProvider nonresident=rp2350_store_provider_nonresident_internal(r->store);
    if(!auth_credentials_init(r->service,&c,&storage) || !auth_credentials_configure_secrets(r->service,&secrets) ||
        (r->nonresident_enabled && !auth_credentials_configure_nonresident(r->service,&nonresident)) ||
        !ctap_client_pin_init(r->pin,r->service,&pin)) return AUTH_CRYPTO_ERROR;
    r->backend->profile.pin_set=false; return AUTH_OK;
}
static bool reset_callback(void *ctx) {
    Rp2350RuntimeReset *r=ctx;
    Rp2350StoreResetHooks hooks={authorize,invalidate,reinitialize,r};
    return rp2350_store_reset_flow_internal(&r->flow,&r->flash,&r->config,r->crypto,&hooks,r->workspace)==AUTH_OK;
}
bool rp2350_runtime_reset_configure_internal(Rp2350RuntimeReset *r,Rp2350StoreResetFlowWorkspace *w,
        Rp2350StoreProvider *store,Rp2350StoreProviderWorkspace *sw,Rp2350Crypto *crypto,AuthCredentialService *service,
        CtapClientPin *pin,CtaphidCtapBackend *backend,uint32_t powered_at_ms) {
    if(!r || !w || !store || !sw || !crypto || !service || !pin || !backend || !store->live || store->busy ||
        crypto->faulted || crypto->keys_locked || backend->reset_configured || backend->pending || store->crypto!=crypto ||
        store->workspace!=sw || pin->service!=service || pin->faulted || service->crypto.context!=store || service->storage.context!=store) return false;
    *r=(Rp2350RuntimeReset){.workspace=w,.store=store,.store_workspace=sw,.crypto=crypto,.service=service,.pin=pin,
        .backend=backend,.flash=store->flash,.config=store->config,.flow={.complete=true},
        .nonresident_enabled=auth_credentials_nonresident_supported(service)};
    return ctaphid_ctap_backend_configure_reset(backend,powered_at_ms,reset_callback,r);
}
bool rp2350_runtime_ready_internal(const Rp2350RuntimeReset *r) {
    return r && !r->flow.busy && !r->flow.locked && r->flow.complete && r->store->live && !r->store->busy &&
        !r->crypto->faulted && !r->crypto->keys_locked && !r->pin->faulted;
}
void rp2350_runtime_start_internal(void *ctx,uint64_t operation,const uint8_t *request,size_t n) {
    Rp2350RuntimeReset *r=ctx;
    if(rp2350_runtime_ready_internal(r)) ctaphid_ctap_backend_start(r->backend,operation,request,n);
    else r->denied_operation=operation;
}
void rp2350_runtime_abort_internal(void *ctx,uint64_t operation) {
    Rp2350RuntimeReset *r=ctx;
    if(r->denied_operation==operation) r->denied_operation=0;
    ctaphid_ctap_backend_abort(r->backend,operation);
}
void rp2350_runtime_resync_internal(void *ctx,uint32_t cid) {
    Rp2350RuntimeReset *r=ctx; ctaphid_ctap_backend_resync(r->backend,cid);
}
CtaphidDeviceResult rp2350_runtime_poll_internal(Rp2350RuntimeReset *r,CtaphidDevice *device,uint32_t now) {
    if(!r || !device) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    if(r->denied_operation) {
        if(!rp2350_runtime_ready_internal(r)) {
            if(r->flow.status==AUTH_OK) r->flow.status=r->crypto->faulted ? AUTH_CRYPTO_ERROR : AUTH_IO_ERROR;
            r->flow.locked=true; r->flow.complete=false; rp2350_crypto_invalidate_internal(r->crypto); (void)invalidate(r);
        }
        uint8_t status=CTAP_STATUS_OTHER; uint64_t operation=r->denied_operation; r->denied_operation=0;
        CtaphidDeviceResult result=ctaphid_device_complete_cbor(device,operation,&status,1);
        return result==CTAPHID_DEVICE_INVALID_STATE ? CTAPHID_DEVICE_IGNORED : result;
    }
    if(!rp2350_runtime_ready_internal(r)) {
        if(r->flow.status==AUTH_OK) r->flow.status=r->crypto->faulted ? AUTH_CRYPTO_ERROR : AUTH_IO_ERROR;
        r->flow.locked=true; r->flow.complete=false; rp2350_crypto_invalidate_internal(r->crypto);
        if(r->backend->pending) { r->denied_operation=r->backend->operation_id; ctaphid_ctap_backend_abort(r->backend,r->backend->operation_id); }
        (void)invalidate(r); return CTAPHID_DEVICE_IGNORED;
    }
    CtaphidDeviceResult result=ctaphid_ctap_backend_poll(r->backend,device,now);
    if(!rp2350_runtime_ready_internal(r)) {
        if(r->flow.status==AUTH_OK) r->flow.status=r->crypto->faulted ? AUTH_CRYPTO_ERROR : AUTH_IO_ERROR;
        r->flow.locked=true; r->flow.complete=false; rp2350_crypto_invalidate_internal(r->crypto);
        if(r->backend->pending) { r->denied_operation=r->backend->operation_id; ctaphid_ctap_backend_abort(r->backend,r->backend->operation_id); }
        (void)invalidate(r);
    }
    return result;
}
