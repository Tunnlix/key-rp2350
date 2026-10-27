#include "provisioning.h"
#include "storage_key_record_internal.h"
#include <string.h>

static AuthStatus hash(void *ctx,const uint8_t *in,size_t n,uint8_t out[32]) {
    Rp2350Provisioning *p=ctx;
    return p->base.sha256(p->base.context,in,n,out);
}
static AuthStatus inspect(void *ctx,const uint8_t *in,size_t n,AuthKeyHandle *out) {
    (void)ctx;
    Rp2350Key key;
    AuthStatus status=rp2350_key_record_decode_internal(in,n,&key);
    if(status==AUTH_OK) *out=key.handle;
    auth_secure_zero(&key,sizeof(key));
    return status;
}
static AuthStatus resolve(void *ctx,const Rp2350StoreRoot *root,Rp2350StoreSeal *seal) {
    Rp2350Provisioning *p=ctx;
    if(root->profile!=1 || root->backend || root->descriptor_length!=32) return AUTH_UNSUPPORTED;
    return rp2350_store_seal_init_internal(seal,&p->base,&p->primitives,root->descriptor,root->epoch);
}
void rp2350_provisioning_close(Rp2350Provisioning *p) {
    if(!p) return;
    rp2350_store_provider_close_internal(&p->store);
    ctap_client_pin_invalidate(&p->pin);
    p->pin.faulted=true;
    auth_secure_zero(&p->service,sizeof(p->service));
}
static AuthStatus authorize(void *ctx) {
    Rp2350Provisioning *p=ctx;
    return p->authorize(p->authorization_context);
}
static AuthStatus invalidate(void *ctx) {
    rp2350_provisioning_close(ctx);
    return AUTH_OK;
}
static AuthStatus reinitialize(void *ctx,const Rp2350StoreReplayState *state) {
    Rp2350Provisioning *p=ctx;
    if(state->metadata_count || state->key_count || state->pin.set ||
        state->pin.retries!=AUTH_PIN_MAX_RETRIES) return AUTH_BAD_DATA;
    AuthStatus status=rp2350_store_provider_stage_internal(&p->store,&p->flash,
        &p->config,p->crypto,&p->store_workspace);
    if(status!=AUTH_OK) return status;
    AuthCrypto crypto=rp2350_store_provider_crypto_internal(&p->store);
    AuthSecretCrypto secrets=rp2350_store_provider_secrets_internal(&p->store);
    AuthStorage storage=rp2350_store_provider_storage_internal(&p->store);
    AuthPinStorage pins=rp2350_store_provider_pin_internal(&p->store);
    return auth_credentials_init(&p->service,&crypto,&storage) &&
        auth_credentials_configure_secrets(&p->service,&secrets) &&
        ctap_client_pin_init(&p->pin,&p->service,&pins) ? AUTH_OK : AUTH_CRYPTO_ERROR;
}
AuthStatus rp2350_provisioning_init(Rp2350Provisioning *p,const Rp2350Flash *flash,
        Rp2350Crypto *crypto,Rp2350StoreResetAuthorize consent,void *ctx) {
    if(!p || !flash || !flash->read || !crypto || !consent) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(p,sizeof(*p));
    p->crypto=crypto; p->flash=*flash; p->authorize=consent; p->authorization_context=ctx;
    p->base=rp2350_crypto_interface(crypto);
    p->primitives=rp2350_secret_interface(crypto);
    p->config=(Rp2350StoreBootConfig){.policy={.profile=1},.resolve=resolve,
        .root_context=p,.hash=hash,.key_inspect=inspect,.records_context=p};
    return AUTH_OK;
}
static AuthStatus set_initial_pin(Rp2350Provisioning *p) {
    static const uint8_t initial_pin[]="000000";
    _Static_assert(sizeof(initial_pin)-1U==RP2350_DEFAULT_MIN_PIN_LENGTH,"Factory PIN matches policy");
    uint8_t digest[32]={0};
    AuthPinStorage storage=rp2350_store_provider_pin_internal(&p->store);
    AuthPinRecord record={0};
    AuthStatus status=storage.read(storage.context,&record);
    if(status==AUTH_OK && (record.set || record.min_length!=RP2350_DEFAULT_MIN_PIN_LENGTH)) status=AUTH_BAD_DATA;
    if(status==AUTH_OK) status=p->base.sha256(p->base.context,initial_pin,sizeof(initial_pin)-1U,digest);
    if(status==AUTH_OK) {
        record.set=true; record.code_points=sizeof(initial_pin)-1U;
        record.force_change=true;
        memcpy(record.hash,digest,sizeof(record.hash));
        status=storage.write(storage.context,&record);
    }
    bool set=false;
    if(status==AUTH_OK && (ctap_client_pin_status(&p->pin,&set)!=CTAP_STATUS_OK || !set || !p->pin.force_change))
        status=AUTH_BAD_DATA;
    auth_secure_zero(digest,sizeof(digest)); auth_secure_zero(&record,sizeof(record));
    return status;
}
AuthStatus rp2350_provisioning_run(Rp2350Provisioning *p) {
    if(!p || !p->crypto || !p->authorize || p->attempted) return AUTH_BUSY;
    p->attempted=true;
    Rp2350StoreResetHooks hooks={authorize,invalidate,reinitialize,p};
    AuthStatus status=rp2350_store_reset_recovery_flow_internal(&p->flow,&p->flash,
        &p->config,p->crypto,&hooks,&p->reset);
    if(status==AUTH_OK && (p->store.cache.metadata_count || p->store.cache.key_count ||
        p->store.cache.pin.set || p->store.cache.pin.retries!=AUTH_PIN_MAX_RETRIES ||
        p->store.cache.global.handle_high || p->store.cache.global.nonresident_issued ||
        p->store.cache.global.nonresident_counter || p->pin.pin_set || p->pin.token_active ||
        p->pin.permissions)) status=AUTH_BAD_DATA;
    /* Only this explicitly loaded factory tool installs a temporary PIN.
     * Standard authenticatorReset continues to clear it. */
    if(status==AUTH_OK) status=set_initial_pin(p);
    if(status!=AUTH_OK) {
        rp2350_provisioning_close(p);
        rp2350_crypto_invalidate_internal(p->crypto);
    }
    return status;
}
