#include "application.h"
#include "storage_key_record_internal.h"
#include "ctap_device_version.h"
#include <string.h>
static AuthStatus hash(void *ctx,const uint8_t *in,size_t n,uint8_t out[32]) {
    Rp2350Application *a=ctx; return a->base.sha256(a->base.context,in,n,out);
}
static AuthStatus inspect(void *ctx,const uint8_t *in,size_t n,AuthKeyHandle *out) {
    (void)ctx; Rp2350Key key;
    AuthStatus status=rp2350_key_record_decode_internal(in,n,&key);
    if(status==AUTH_OK) *out=key.handle;
    auth_secure_zero(&key,sizeof(key)); return status;
}
static AuthStatus resolve(void *ctx,const Rp2350StoreRoot *root,Rp2350StoreSeal *seal) {
    Rp2350Application *a=ctx;
    if(root->profile!=1 || root->backend || root->descriptor_length!=32) return AUTH_UNSUPPORTED;
    return rp2350_store_seal_init_internal(seal,&a->base,&a->primitives,root->descriptor,root->epoch);
}
static void start(void *ctx,uint64_t operation,const uint8_t *request,size_t n) {
    Rp2350Application *a=ctx;
    if(n && request[0]==RP2350_UPDATE_COMMAND) rp2350_firmware_update_start(a,operation,request,n);
    else rp2350_runtime_start_internal(&a->runtime,operation,request,n);
}
static void abort_operation(void *ctx,uint64_t operation) {
    Rp2350Application *a=ctx;
    rp2350_firmware_update_abort(a,operation);
    rp2350_presence_abort(&a->presence,operation); rp2350_runtime_abort_internal(&a->runtime,operation);
}
static void resync(void *ctx,uint32_t cid) {
    Rp2350Application *a=ctx; rp2350_runtime_resync_internal(&a->runtime,cid);
}
static void close_owned(Rp2350Application *a) {
    if(a->device.in_flight && a->io.asynchronous && a->io.abort)
        a->io.abort(a->io.context,a->device.flight_id);
    if(a->backend.pending) abort_operation(a,a->backend.operation_id);
    rp2350_firmware_update_abort(a,a->update.operation);
    rp2350_presence_abort(&a->presence,a->presence.operation_id);
    rp2350_store_provider_close_internal(&a->store); rp2350_crypto_invalidate_internal(a->crypto);
    ctap_client_pin_invalidate(&a->pin); a->pin.faulted=true;
    auth_secure_zero(&a->service,sizeof(a->service));
    auth_secure_zero(&a->backend,sizeof(a->backend)); auth_secure_zero(&a->device,sizeof(a->device));
    auth_secure_zero(&a->reset_workspace,sizeof(a->reset_workspace));
    a->initialized=false;
}
void rp2350_application_close(Rp2350Application *a) {
    if(!a || a->busy) return;
    a->busy=true; close_owned(a); a->busy=false;
}
bool rp2350_application_ready(const Rp2350Application *a) {
    return a && a->initialized && rp2350_runtime_ready_internal(&a->runtime);
}
bool rp2350_application_disconnect(Rp2350Application *a) {
    if(!a || !a->initialized || a->busy || a->device.in_flight) return false;
    a->busy=true;
    if(a->backend.pending) abort_operation(a,a->backend.operation_id);
    rp2350_firmware_update_abort(a,a->update.operation);
    ctap_assertion_sequence_clear(&a->backend.assertion_sequence);
    ctap_credential_management_clear(&a->backend.management);
    ctap_client_pin_invalidate(&a->pin);
    ctap_large_blobs_clear(&a->backend.blobs);
    rp2350_presence_init(&a->presence,a->io.pressed(a->io.context),a->io.now_ms(a->io.context));
    CtaphidDeviceConfig config=a->device.config;
    uint64_t operation=a->device.transaction_id,transfer=a->device.next_transfer_id;
    bool ok=ctaphid_device_init(&a->device,&config)==CTAPHID_DEVICE_OK;
    /* Keep operation IDs unique across a USB reset in the same power cycle. */
    a->device.transaction_id=operation; a->device.next_transfer_id=transfer;
    a->busy=false;
    return ok;
}
AuthStatus rp2350_application_init(Rp2350Application *a,Rp2350Crypto *crypto,const Rp2350Flash *flash,
        const Rp2350ApplicationIo *io,const uint8_t aaguid[16],uint32_t powered_at_ms) {
    if(!a || !crypto || !flash || !io || !aaguid || !io->now_ms || !io->pressed || !io->submit ||
        (io->asynchronous && !io->abort)) return AUTH_INVALID_ARGUMENT;
    if(a->initialized || a->busy) return AUTH_BUSY;
    auth_secure_zero(a,sizeof(*a)); a->busy=true; a->crypto=crypto; a->io=*io;
    a->base=rp2350_crypto_interface(crypto); a->primitives=rp2350_secret_interface(crypto);
    Rp2350StoreBootConfig config={.policy={.profile=1},.resolve=resolve,.root_context=a,
        .hash=hash,.key_inspect=inspect,.records_context=a};
    AuthStatus status=io->trial_boot ?
        rp2350_store_provider_trial_internal(&a->store,flash,&config,crypto,&a->reset_workspace.phase.provider) :
        rp2350_store_provider_stage_internal(&a->store,flash,&config,crypto,&a->reset_workspace.phase.provider);
    if(status!=AUTH_OK) goto failed;
    AuthCrypto c=rp2350_store_provider_crypto_internal(&a->store);
    AuthStorage storage=rp2350_store_provider_storage_internal(&a->store);
    AuthSecretCrypto secrets=rp2350_store_provider_secrets_internal(&a->store);
    AuthPinStorage pins=rp2350_store_provider_pin_internal(&a->store);
    AuthNonresidentProvider nonresident=rp2350_store_provider_nonresident_internal(&a->store);
    if(!auth_credentials_init(&a->service,&c,&storage) || !auth_credentials_configure_secrets(&a->service,&secrets) ||
        !auth_credentials_configure_nonresident(&a->service,&nonresident) ||
        !ctap_client_pin_init(&a->pin,&a->service,&pins)) { status=AUTH_CRYPTO_ERROR; goto failed; }
    status=rp2350_crypto_activate_internal(crypto); if(status!=AUTH_OK) goto failed;
    CtapGetInfoProfile profile={.max_message_size=CTAP_MESSAGE_CAPACITY,.user_presence=true,
        .firmware_version=CTAP_DEVICE_FIRMWARE_VERSION,.usb_transport=io->usb_transport};
    memcpy(profile.aaguid,aaguid,16);
    if(!ctaphid_ctap_backend_init(&a->backend,&profile) ||
        !rp2350_runtime_reset_configure_internal(&a->runtime,&a->reset_workspace,&a->store,&a->reset_workspace.phase.provider,
            crypto,&a->service,&a->pin,&a->backend,powered_at_ms) ||
        !ctaphid_ctap_backend_configure_credentials(&a->backend,&a->service) ||
        !ctaphid_ctap_backend_configure_pin(&a->backend,&a->pin)) { status=AUTH_BAD_DATA; goto failed; }
    CtaphidDeviceConfig device={.submit_report=io->submit,.abort_report=io->abort,.transport_context=io->context,
        .asynchronous_transport=io->asynchronous,.start_cbor=start,.abort_cbor=abort_operation,
        .resync_channel=resync,.cbor_context=a,.cancel_requested=io->cancel_requested};
    if(ctaphid_device_init(&a->device,&device)!=CTAPHID_DEVICE_OK) { status=AUTH_BAD_DATA; goto failed; }
    uint32_t now=io->now_ms(io->context);
    rp2350_presence_init(&a->presence,io->pressed(io->context),now);
    a->initialized=true; a->busy=false; return AUTH_OK;
failed:
    close_owned(a); a->busy=false; return status;
}
CtaphidDeviceResult rp2350_application_receive(Rp2350Application *a,const uint8_t *report,size_t n) {
    if(!a || !a->initialized || a->busy) return CTAPHID_DEVICE_INVALID_STATE;
    /* Once consent is accepted, drain its final reply before ROM entry. New
     * queued input cannot replace the approved transaction or reuse its touch. */
    if(a->update.approved) return CTAPHID_DEVICE_IGNORED;
    a->busy=true;
    CtaphidDeviceResult result=ctaphid_device_receive_report(&a->device,report,n,a->io.now_ms(a->io.context));
    if(result!=CTAPHID_DEVICE_OK && result!=CTAPHID_DEVICE_IGNORED)
        rp2350_firmware_update_abort(a,a->update.operation);
    a->busy=false; return result;
}
CtaphidDeviceResult rp2350_application_report_sent(Rp2350Application *a,uint64_t transfer,bool success) {
    if(!a || !a->initialized || a->busy) return CTAPHID_DEVICE_INVALID_STATE;
    a->busy=true;
    CtaphidDeviceResult result=ctaphid_device_report_sent(&a->device,transfer,success);
    if(result!=CTAPHID_DEVICE_OK && result!=CTAPHID_DEVICE_IGNORED)
        rp2350_firmware_update_abort(a,a->update.operation);
    a->busy=false; return result;
}
CtaphidDeviceResult rp2350_application_poll(Rp2350Application *a) {
    if(!a || !a->initialized || a->busy) return CTAPHID_DEVICE_INVALID_STATE;
    a->busy=true; uint32_t now=a->io.now_ms(a->io.context);
    uint64_t event=rp2350_presence_sample(&a->presence,a->io.pressed(a->io.context),now);
    CtaphidDeviceResult result=ctaphid_device_poll(&a->device,now);
    if(result!=CTAPHID_DEVICE_OK) goto done;
    if(a->update.operation) {
        result=rp2350_firmware_update_poll(a,event,a->io.now_ms(a->io.context));
        if(result==CTAPHID_DEVICE_OK) result=ctaphid_device_poll(&a->device,a->io.now_ms(a->io.context));
        goto done;
    }
    result=rp2350_runtime_poll_internal(&a->runtime,&a->device,now);
    if(result!=CTAPHID_DEVICE_OK && result!=CTAPHID_DEVICE_IGNORED) goto done;
    now=a->io.now_ms(a->io.context);
    /* Continuously sample idle/held state too; a new operation must never
     * reinterpret an already-held contact as fresh presence. */
    if(a->backend.pending && a->backend.awaiting_presence && a->backend.presence_started) {
        if(a->presence.operation_id!=a->backend.operation_id)
            rp2350_presence_begin(&a->presence,a->backend.operation_id,now);
    } else rp2350_presence_abort(&a->presence,a->presence.operation_id);
    if(event) (void)ctaphid_ctap_backend_signal_presence(&a->backend,event,true,now);
    result=rp2350_runtime_poll_internal(&a->runtime,&a->device,now);
    if(result!=CTAPHID_DEVICE_OK && result!=CTAPHID_DEVICE_IGNORED) goto done;
    result=ctaphid_device_poll(&a->device,a->io.now_ms(a->io.context));
done:
    if(result!=CTAPHID_DEVICE_OK && result!=CTAPHID_DEVICE_IGNORED)
        rp2350_firmware_update_abort(a,a->update.operation);
    a->busy=false; return result;
}

static AuthStatus refresh_blobs(Rp2350Application *a) {
    if(a->blobs.faulted || !a->store.live) return AUTH_IO_ERROR;
    if(a->blobs.epoch==a->store.cache.global.reset_generation &&
        memcmp(a->blobs.store_id,a->store.cache.global.device_id,16U)==0) return AUTH_OK;
    Rp2350Flash flash=a->blobs.flash;
    return rp2350_blob_store_open(&a->blobs,&flash,a->store.cache.global.reset_generation,a->store.cache.global.device_id);
}
static AuthStatus read_blobs(void *ctx,size_t at,uint8_t *out,size_t n,size_t *total) {
    Rp2350Application *a=ctx; AuthStatus status=refresh_blobs(a);
    CtapLargeBlobStorage storage=rp2350_blob_store_interface(&a->blobs);
    return status==AUTH_OK ? storage.read(storage.context,at,out,n,total) : status;
}
static AuthStatus commit_blobs(void *ctx,const uint8_t *in,size_t n) {
    Rp2350Application *a=ctx; AuthStatus status=refresh_blobs(a);
    CtapLargeBlobStorage storage=rp2350_blob_store_interface(&a->blobs);
    return status==AUTH_OK ? storage.commit(storage.context,in,n) : status;
}
AuthStatus rp2350_application_configure_blobs(Rp2350Application *a,const Rp2350Flash *flash) {
    if(!rp2350_application_ready(a) || a->busy || a->backend.profile.large_blobs) return AUTH_BUSY;
    AuthStatus status=rp2350_blob_store_open(&a->blobs,flash,a->store.cache.global.reset_generation,a->store.cache.global.device_id);
    if(status!=AUTH_OK) return status;
    CtapLargeBlobStorage storage={a,read_blobs,commit_blobs};
    return ctaphid_ctap_backend_configure_blobs(&a->backend,&storage) ? AUTH_OK : AUTH_BAD_DATA;
}
