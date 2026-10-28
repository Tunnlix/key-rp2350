#include "storage_provision_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static AuthStatus blank_range(const Rp2350Flash *flash,uint32_t base,uint32_t size,uint8_t page[256]) {
    bool blank=true;
    for(uint32_t at=base;at<base+size;at+=256U) {
        AuthStatus status=flash->read(flash->context,at,page,256); if(status!=AUTH_OK) return status;
        for(size_t i=0;i<256;i++) if(page[i]!=0xff) blank=false;
    }
    return blank ? AUTH_OK : AUTH_BUSY;
}
static AuthStatus fresh(const AuthCrypto *crypto,uint8_t *out,size_t n) {
    AuthStatus status=crypto->random(crypto->context,out,n);
    return status!=AUTH_OK ? status : store_nonzero(out,n) ? AUTH_OK : AUTH_CRYPTO_ERROR;
}
static AuthStatus open_empty(Rp2350StoreProvisionWorkspace *w,const Rp2350Flash *flash,uint32_t base,uint32_t size) {
    AuthStatus status=rp2350_store_log_open_internal(&w->log,flash,&w->seal,base,size,1,w->root.epoch,NULL,NULL,&w->boot.io.log);
    if(status==AUTH_NOT_FOUND && w->log.initialized && !w->log.end) return AUTH_OK;
    return status==AUTH_OK || status==AUTH_NOT_FOUND ? AUTH_BAD_DATA : status;
}
static AuthStatus append(Rp2350StoreProvisionWorkspace *w,uint16_t class_id,uint16_t kind,size_t n,uint8_t *digest) {
    Rp2350StoreTransaction tx={.class_id=class_id,.count=1,.entries={{kind,w->data,n}}}; size_t length=0;
    AuthStatus status=rp2350_store_transaction_encode(&tx,w->plain,sizeof(w->plain),&length);
    if(status==AUTH_OK) status=rp2350_store_log_append_internal(&w->log,class_id,w->plain,length,&w->boot.io.log);
    auth_secure_zero(w->plain,sizeof(w->plain)); auth_secure_zero(w->data,sizeof(w->data));
    if(status!=AUTH_OK || !digest) return status;
    return w->log.flash.read(w->log.flash.context,w->log.base+w->log.end-320U,digest,32);
}
static AuthStatus root_slots(Rp2350StoreProvisionWorkspace *w,const Rp2350Flash *flash) {
    for(uint32_t base=0x2000U;base<=0x3000U;base+=4096U) for(uint32_t page=0;page<512;page+=256U) {
        AuthStatus status=flash->program_page(flash->context,base+page,w->root_wire+page); if(status!=AUTH_OK) return status;
        status=flash->read(flash->context,base+page,w->boot.io.blank,256); if(status!=AUTH_OK) return status;
        if(!store_equal(w->root_wire+page,w->boot.io.blank,256)) return AUTH_IO_ERROR;
    }
    return AUTH_OK;
}
static AuthStatus validate(Rp2350StoreProvisionWorkspace *w,const Rp2350Flash *flash,const Rp2350StoreBootConfig *config) {
    AuthStatus status=rp2350_store_boot_internal(&w->recovered,flash,config,&w->boot); if(status!=AUTH_OK) return status;
    const Rp2350StoreBootResult *r=&w->recovered;
    if(r->state!=RP2350_STORE_RECOVERED || r->root.root.profile!=1 || r->root.root.backend ||
        r->root.root.serial!=1 || r->root.root.reset_generation!=1 || r->root.root.descriptor_length!=32 ||
        !store_equal(r->root.root.descriptor,w->root.descriptor,32) || !store_equal(r->root.root.epoch,w->root.epoch,16) ||
        r->selection.selector.state!=1 || r->selection.selector.serial!=1 || r->selection.selector.generation!=1 ||
        r->selection.selector.arena!=0 || !store_equal(r->selection.selector.manifest_digest,w->selector.manifest_digest,32) ||
        r->records.metadata_count || r->records.key_count || r->records.logical_sequence || r->records.last_sequence!=3) return AUTH_BAD_DATA;
    status=rp2350_store_global_encode(&w->global,w->data);
    if(status==AUTH_OK) status=rp2350_store_global_encode(&r->records.global,w->compare);
    if(status!=AUTH_OK) return status;
    if(!store_equal(w->data,w->compare,96)) return AUTH_BAD_DATA;
    status=rp2350_store_pin_encode(&w->pin,w->data);
    if(status==AUTH_OK) status=rp2350_store_pin_encode(&r->records.pin,w->compare);
    if(status!=AUTH_OK) return status;
    if(!store_equal(w->data,w->compare,24)) return AUTH_BAD_DATA;
    return blank_range(flash,RP2350_STORE_ARENA_B,RP2350_STORE_ARENA_SIZE,w->boot.io.blank);
}
AuthStatus rp2350_store_provision_internal(Rp2350StoreProvisioned *out,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,const AuthCrypto *crypto,const AuthSecretCrypto *secrets,
        Rp2350StoreResetAuthorize authorize,void *context,Rp2350StoreProvisionWorkspace *w) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !config || !config->resolve || !config->hash || !config->key_inspect ||
        !crypto || !crypto->random || !crypto->sha256 || !secrets || !secrets->hmac_sha256 || !secrets->aes256_cbc || !authorize || !w)
        return AUTH_INVALID_ARGUMENT;
    if(!flash->program_page || config->policy.profile!=1 || config->policy.backend) return AUTH_UNSUPPORTED;
    AuthStatus status=authorize(context); if(status!=AUTH_OK) goto done;
    status=blank_range(flash,0,RP2350_STORE_PARTITION_SIZE,w->boot.io.blank); if(status!=AUTH_OK) goto done;
    w->root.profile=1; w->root.descriptor_length=32; w->root.serial=w->root.reset_generation=1;
    w->global.reset_generation=1; w->pin.retries=AUTH_PIN_MAX_RETRIES;
    w->pin.min_length=RP2350_DEFAULT_MIN_PIN_LENGTH;
    status=fresh(crypto,w->root.descriptor,32); if(status!=AUTH_OK) goto done;
    status=fresh(crypto,w->root.epoch,16); if(status!=AUTH_OK) goto done;
    status=fresh(crypto,w->global.handle_prefix,24); if(status!=AUTH_OK) goto done;
    status=fresh(crypto,w->global.store_state,16); if(status!=AUTH_OK) goto done;
    status=fresh(crypto,w->global.device_id,16); if(status!=AUTH_OK) goto done;
    status=rp2350_store_seal_init_internal(&w->seal,crypto,secrets,w->root.descriptor,w->root.epoch); if(status!=AUTH_OK) goto done;
    status=rp2350_store_root_encode_internal(&w->seal,&w->root,w->root_wire); if(status!=AUTH_OK) goto done;
    status=open_empty(w,flash,RP2350_STORE_ARENA_A,RP2350_STORE_ARENA_SIZE); if(status!=AUTH_OK) goto done;
    memcpy(w->ordered,"ctap-store-v2/checkpoint",24);
    status=rp2350_store_global_encode(&w->global,w->data); if(status!=AUTH_OK) goto done;
    status=config->hash(config->records_context,w->data,96,w->manifest.global_digest); if(status!=AUTH_OK) goto done;
    status=append(w,2,1,96,w->ordered+24); if(status!=AUTH_OK) goto done;
    status=rp2350_store_pin_encode(&w->pin,w->data); if(status!=AUTH_OK) goto done;
    status=append(w,2,7,24,w->ordered+56); if(status!=AUTH_OK) goto done;
    status=config->hash(config->records_context,w->ordered,sizeof(w->ordered),w->manifest.ordered_digest); if(status!=AUTH_OK) goto done;
    status=rp2350_store_manifest_encode(&w->manifest,w->data); if(status!=AUTH_OK) goto done;
    status=append(w,3,8,96,w->selector.manifest_digest); if(status!=AUTH_OK) goto done;
    if(w->log.end!=2048) { status=AUTH_BAD_DATA; goto done; }
    status=root_slots(w,flash); if(status!=AUTH_OK) goto done;
    /* Only the final selector commit makes this new empty epoch bootable. */
    w->selector.state=1; w->selector.serial=w->selector.generation=w->selector.reset_generation=1;
    memcpy(w->selector.epoch,w->root.epoch,16);
    status=open_empty(w,flash,0,8192); if(status!=AUTH_OK) goto done;
    status=rp2350_store_selector_encode(&w->selector,w->data); if(status!=AUTH_OK) goto done;
    status=append(w,4,9,80,NULL); if(status!=AUTH_OK) goto done;
    status=validate(w,flash,config); if(status!=AUTH_OK) goto done;
    out->verified=true;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}
