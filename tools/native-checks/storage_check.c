#include "storage_provision_internal.h"
#include "storage_provider_internal.h"
#include "storage_key_record_internal.h"
#include "application.h"
#include "enterprise_attestation.h"
#include "ctap/ctap_large_blobs.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/ctap_authenticator_config.h"
#include "ctap/cbor_writer.h"
#include "mbedtls/ecdsa.h"
#include "ctaes.h"
#include "monocypher-ed25519.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Isolated synthetic flash only. This executable never opens a USB device. */
static uint8_t media[RP2350_STORE_PARTITION_SIZE],saved[RP2350_STORE_PARTITION_SIZE];
static Rp2350Crypto crypto;
static Rp2350StoreProvider provider;
static Rp2350StoreProviderWorkspace workspace;
static Rp2350StoreProvisionWorkspace provisioning;
static AuthCrypto base;
static AuthSecretCrypto secrets;
static Rp2350StoreBootConfig config;
static unsigned rng_state=738192,reads,writes,erases,entropy_calls;
static int write_budget=-1;
static int erase_budget=-1,erase_prefix=-1;
static int partial_prefix=-1;
static unsigned partial_keep;
static bool locked,trial_mode;
static void identifier_get_info(AuthCredentialService *,CtapClientPin *,uint8_t[64]);
static uint8_t blob_media[32768];
static int entropy(void *ctx,unsigned char *out,size_t n) {
    (void)ctx;
    entropy_calls++;
    for(size_t i=0;i<n;i++) { rng_state^=rng_state<<13; rng_state^=rng_state>>17; rng_state^=rng_state<<5; out[i]=(uint8_t)rng_state; }
    return 0;
}
static AuthStatus read_media(void *ctx,uint32_t at,uint8_t *out,size_t n) {
    size_t capacity=ctx ? sizeof(blob_media) : sizeof(media);
    uint8_t *bytes=ctx ? ctx : media;
    if(at>capacity || n>capacity-at) return AUTH_IO_ERROR;
    reads++; memcpy(out,bytes+at,n); return AUTH_OK;
}
static AuthStatus program_media(void *ctx,uint32_t at,const uint8_t page[256]) {
    if(locked) return AUTH_BUSY;
    uint8_t *bytes=ctx ? ctx : media;
    size_t capacity=ctx ? sizeof(blob_media) : sizeof(media);
    if(at>capacity-256 || at%256) return AUTH_INVALID_ARGUMENT;
    if(write_budget==0) {
        if(partial_prefix>=0) for(int i=0;i<partial_prefix;i++) bytes[at+(unsigned)i]&=(uint8_t)(page[i]|partial_keep);
        return AUTH_IO_ERROR;
    }
    if(write_budget>0) write_budget--;
    for(size_t i=0;i<256;i++) if(bytes[at+i]!=0xff) return AUTH_BAD_DATA;
    writes++; memcpy(bytes+at,page,256); return AUTH_OK;
}
static AuthStatus erase_media(void *ctx,uint32_t at) {
    if(locked) return AUTH_BUSY;
    uint8_t *bytes=ctx ? ctx : media;
    size_t capacity=ctx ? sizeof(blob_media) : sizeof(media);
    if(at>capacity-4096 || at%4096) return AUTH_INVALID_ARGUMENT;
    if(erase_budget==0) {
        if(erase_prefix>=0) memset(bytes+at,0xff,(size_t)erase_prefix);
        return AUTH_IO_ERROR;
    }
    if(erase_budget>0) erase_budget--;
    erases++; memset(bytes+at,0xff,4096); return AUTH_OK;
}
static Rp2350Flash flash={NULL,read_media,program_media,erase_media};
static AuthStatus hash(void *ctx,const uint8_t *in,size_t n,uint8_t out[32]) {
    (void)ctx; return base.sha256(base.context,in,n,out);
}
static AuthStatus inspect(void *ctx,const uint8_t *in,size_t n,AuthKeyHandle *out) {
    (void)ctx; Rp2350Key key;
    AuthStatus status=rp2350_key_record_decode_internal(in,n,&key);
    if(status==AUTH_OK) *out=key.handle;
    auth_secure_zero(&key,sizeof(key)); return status;
}
static AuthStatus resolve(void *ctx,const Rp2350StoreRoot *root,Rp2350StoreSeal *seal) {
    (void)ctx; return rp2350_store_seal_init_internal(seal,&base,&secrets,root->descriptor,root->epoch);
}
static AuthStatus consent(void *ctx) { (void)ctx; return AUTH_OK; }
static AuthStatus reset_consent(void *ctx) {
    (void)ctx; rp2350_store_provider_close_internal(&provider); return AUTH_OK;
}
static void initialize_crypto(void) {
    assert(rp2350_crypto_init(&crypto,entropy,NULL)==AUTH_OK);
    base=rp2350_crypto_interface(&crypto); secrets=rp2350_secret_interface(&crypto);
}
static AuthStatus cold_boot(void) {
    rp2350_store_provider_close_internal(&provider);
    memset(&provider,0,sizeof(provider));
    rp2350_crypto_free(&crypto); initialize_crypto();
    return trial_mode ? rp2350_store_provider_trial_internal(&provider,&flash,&config,&crypto,&workspace) :
        rp2350_store_provider_recover_internal(&provider,&flash,&config,&crypto,&workspace);
}
static void check_signature(AuthCrypto *c,const AuthCredential *item,const uint8_t pub[65]) {
    uint8_t signature[72],digest[32]={42}; size_t signature_size=0;
    if(item->algorithm==AUTH_COSE_ALG_EDDSA) {
        assert(c->sign_ed25519(c->context,&item->key,digest,32,signature)==AUTH_OK);
        assert(crypto_ed25519_check(signature,pub,digest,32)==0);
    } else {
        assert(c->sign_p256_digest(c->context,&item->key,digest,signature,&signature_size)==AUTH_OK);
        mbedtls_ecdsa_context verifier; mbedtls_ecdsa_init(&verifier);
        assert(mbedtls_ecp_group_load(&verifier.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1)==0);
        assert(mbedtls_ecp_point_read_binary(&verifier.MBEDTLS_PRIVATE(grp),&verifier.MBEDTLS_PRIVATE(Q),pub,65)==0);
        assert(mbedtls_ecdsa_read_signature(&verifier,digest,32,signature,signature_size)==0);
        mbedtls_ecdsa_free(&verifier);
    }
}
static size_t blob_array(uint8_t out[256],unsigned first,unsigned count) {
    CborWriter writer; cbor_writer_init(&writer,out,240);
    assert(cbor_write_array(&writer,count));
    for(unsigned i=first;i<first+count;i++) {
        uint8_t ciphertext[16],nonce[12];
        memset(ciphertext,(int)i,sizeof(ciphertext)); memset(nonce,(int)i,sizeof(nonce));
        assert(cbor_write_map(&writer,3) && cbor_write_uint(&writer,1) && cbor_write_bytes(&writer,ciphertext,16) &&
            cbor_write_uint(&writer,2) && cbor_write_bytes(&writer,nonce,12) &&
            cbor_write_uint(&writer,3) && cbor_write_uint(&writer,32));
    }
    uint8_t digest[32]; assert(hash(NULL,out,writer.length,digest)==AUTH_OK);
    memcpy(out+writer.length,digest,16); return writer.length+16;
}
static uint8_t pin_token_permissions(CtapClientPin *pin,uint8_t protocol,const uint8_t pin_hash[16],
        uint8_t permissions,uint8_t token[32]) {
    CtapClientPinRequest request={.protocol=protocol,.subcommand=9,.permissions=permissions};
    if(permissions & (CTAP_PIN_PERMISSION_MC | CTAP_PIN_PERMISSION_GA)) {
        request.rp_present=true; request.rp_length=13; memcpy(request.rp_id,"audit.invalid",13);
    }
    memcpy(request.peer,crypto.agreement_public,65);
    uint8_t keys[64],reply[256]; size_t reply_size=0;
    assert(ctap_pin_protocol_shared_version(&base,&secrets,protocol,request.peer,keys)==CTAP_STATUS_OK);
    assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,pin_hash,16,request.pin_hash_enc)==CTAP_STATUS_OK);
    uint8_t status=ctap_client_pin_execute(pin,&request,reply,sizeof(reply),&reply_size,1000);
    if(status==CTAP_STATUS_OK) {
        CborValue root,value;
        assert(cbor_read_document(reply,reply_size,&root) && cbor_map_uint(&root,2,&value));
        assert(ctap_pin_protocol_decrypt(&secrets,protocol,keys,value.data,(size_t)value.value,token)==CTAP_STATUS_OK);
    }
    auth_secure_zero(keys,sizeof(keys)); return status;
}
static uint8_t pin_token(CtapClientPin *pin,uint8_t protocol,const uint8_t pin_hash[16],uint8_t token[32]) {
    return pin_token_permissions(pin,protocol,pin_hash,CTAP_PIN_PERMISSION_LBW,token);
}
static void check_up_permissions(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static CtapGetAssertionWorkspace ga_workspace;
    static CtapMakeCredentialWorkspace mc_workspace;
    static AuthCredential credential;
    assert(service->storage.enumerate(service->storage.context,0,&credential)==AUTH_OK);
    uint8_t pin_hash[16],token[32],message[32]={9},mac[32],reply[1024],aaguid[16]={0};
    memset(pin_hash,42,sizeof(pin_hash));
    const uint8_t other_permissions=CTAP_PIN_PERMISSION_MC | CTAP_PIN_PERMISSION_GA |
        CTAP_PIN_PERMISSION_CM | CTAP_PIN_PERMISSION_CONFIG;
    for(unsigned with_lbw=0;with_lbw<2;with_lbw++) for(unsigned path=0;path<5;path++) {
        CtapClientPin pin;
        assert(ctap_client_pin_init(&pin,service,pins)); pin.large_blobs=true;
        uint8_t permissions=other_permissions | (with_lbw ? CTAP_PIN_PERMISSION_LBW : 0U);
        assert(pin_token_permissions(&pin,protocol,pin_hash,permissions,token)==CTAP_STATUS_OK);
        CtapPinAuth auth={.present=true,.protocol=protocol};
        assert(secrets.hmac_sha256(secrets.context,token,32,message,sizeof(message),auth.mac)==AUTH_OK);
        /* Prepare-phase authorization snapshots generation before waiting for UP. */
        uint8_t operation=path<2 || path==4 ? CTAP_PIN_PERMISSION_GA : CTAP_PIN_PERMISSION_MC;
        assert(ctap_client_pin_authorize(&pin,&auth,credential.rp_id_hash,message,operation,1001,true)==CTAP_STATUS_OK);
        uint64_t generation=pin.token_generation;
        size_t reply_size=0;
        if(operation==CTAP_PIN_PERMISSION_GA) {
            static CtapGetAssertion request;
            memset(&request,0,sizeof(request));
            request.pin=&pin; request.auth=auth; request.user_verified=true;
            request.user_presence_required=path!=1; request.credential_id_length=AUTH_CREDENTIAL_ID_SIZE;
            request.uvm_requested=true;
            memcpy(request.credential_id,credential.credential_id,AUTH_CREDENTIAL_ID_SIZE);
            memcpy(request.rp_id_hash,credential.rp_id_hash,32); memcpy(request.client_data_hash,message,32);
            request.extension_status=path==4 ? CTAP_STATUS_INVALID_OPTION : CTAP_STATUS_OK;
            assert(ctap_get_assertion_finish_at(service,&ga_workspace,&request,reply,sizeof(reply),&reply_size,1002)==
                (path==4 ? CTAP_STATUS_INVALID_OPTION : CTAP_STATUS_OK));
            if(path!=4) {
                CborValue root,data,ext,uvm;
                assert(cbor_read_document(reply,reply_size,&root) && cbor_map_uint(&root,2,&data));
                assert(data.value>37 && (data.data[32]&0x80));
                assert(cbor_read_document(data.data+37,(size_t)data.value-37,&ext) && cbor_map_text(&ext,"uvm",&uvm));
                assert(uvm.major==4 && uvm.value==(path==1 ? 1 : 2));
            }
        } else {
            static CtapMakeCredential request;
            memset(&request,0,sizeof(request));
            request.pin=&pin; request.auth=auth; request.user_verified=true;
            request.credential_excluded=path==2; request.extension_status=CTAP_STATUS_INVALID_OPTION;
            memcpy(request.rp_id_hash,credential.rp_id_hash,32); memcpy(request.client_data_hash,message,32);
            assert(ctap_make_credential_finish_at(service,&mc_workspace,&request,aaguid,reply,sizeof(reply),&reply_size,1002)==
                (path==2 ? CTAP_STATUS_CREDENTIAL_EXCLUDED : CTAP_STATUS_INVALID_OPTION));
        }
        assert(pin.permissions==(path==1 ? permissions : with_lbw ? CTAP_PIN_PERMISSION_LBW : 0U));
        assert(pin.token_active && pin.token_used && pin.token_generation==generation && pin.issued_at_ms==1000);
        assert(pin.token_rp_bound && !memcmp(pin.token_rp_hash,credential.rp_id_hash,32));
        assert(!memcmp(pin.token,token,32));
        assert(secrets.hmac_sha256(secrets.context,token,32,message,sizeof(message),mac)==AUTH_OK);
        assert(ctap_client_pin_authorize_permission(&pin,protocol,CTAP_PIN_PERMISSION_LBW,message,sizeof(message),mac,1003)==
            (with_lbw ? CTAP_STATUS_OK : CTAP_STATUS_PIN_AUTH_INVALID));
        if(path!=1) for(unsigned bit=1;bit<=CTAP_PIN_PERMISSION_CONFIG;bit<<=1) {
            if(bit==CTAP_PIN_PERMISSION_LBW) continue;
            assert(ctap_client_pin_authorize_permission(&pin,protocol,(uint8_t)bit,message,sizeof(message),mac,1003)==CTAP_STATUS_PIN_AUTH_INVALID);
        }
        /* A replacement never accepts the old token, even with lbw retained. */
        assert(pin_token_permissions(&pin,protocol,pin_hash,other_permissions | CTAP_PIN_PERMISSION_LBW,token)==CTAP_STATUS_OK);
        assert(pin.token_generation>generation);
        assert(ctap_client_pin_authorize_permission(&pin,protocol,CTAP_PIN_PERMISSION_LBW,message,sizeof(message),mac,1003)==CTAP_STATUS_PIN_AUTH_INVALID);
        CtapPinAuth stale=auth;
        assert(secrets.hmac_sha256(secrets.context,token,32,message,sizeof(message),stale.mac)==AUTH_OK);
        assert(ctap_client_pin_authorize(&pin,&stale,credential.rp_id_hash,message,CTAP_PIN_PERMISSION_GA,1003,false)==CTAP_STATUS_PIN_AUTH_INVALID);
        ctap_client_pin_clear_permissions_except_lbw(&pin);
        assert(secrets.hmac_sha256(secrets.context,token,32,message,sizeof(message),mac)==AUTH_OK);
        assert(ctap_client_pin_authorize_permission(&pin,protocol,CTAP_PIN_PERMISSION_LBW,message,sizeof(message),mac,1003)==CTAP_STATUS_OK);
        assert(ctap_client_pin_authorize_permission(&pin,protocol,CTAP_PIN_PERMISSION_LBW,message,sizeof(message),mac,601000)==CTAP_STATUS_PIN_AUTH_INVALID);
        assert(!pin.token_active);
        ctap_client_pin_clear_permissions_except_lbw(&pin);
        assert(!pin.token_active && pin.permissions==0);
    }
    auth_secure_zero(token,sizeof(token));
    memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
    printf("PIN protocol %u: UP preserves only LBW after assertions, excluded/deferred-error registrations; silent GA, replacement/generation and expiry pass\n",protocol);
}
static uint8_t blob_fragment(CtapLargeBlobs *blobs,CtapClientPin *pin,uint8_t protocol,const uint8_t token[32],
        uint32_t channel,const uint8_t *data,size_t chunk,size_t offset,size_t total,uint32_t now) {
    uint8_t message[70],mac[32],command[256],reply[256]; size_t reply_size=0;
    memset(message,0xff,32); message[32]=0x0c; message[33]=0;
    for(unsigned i=0;i<4;i++) message[34+i]=(uint8_t)(offset>>(8*i));
    assert(hash(NULL,data,chunk,message+38)==AUTH_OK);
    assert(secrets.hmac_sha256(secrets.context,token,32,message,70,mac)==AUTH_OK);
    CborWriter writer; cbor_writer_init(&writer,command,sizeof(command));
    assert(cbor_write_map(&writer,offset ? 4 : 5) && cbor_write_uint(&writer,2) &&
        cbor_write_bytes(&writer,data,chunk) && cbor_write_uint(&writer,3) && cbor_write_uint(&writer,offset));
    if(!offset) assert(cbor_write_uint(&writer,4) && cbor_write_uint(&writer,total));
    assert(cbor_write_uint(&writer,5) && cbor_write_bytes(&writer,mac,ctap_pin_protocol_auth_length(protocol)) &&
        cbor_write_uint(&writer,6) && cbor_write_uint(&writer,protocol));
    return ctap_large_blobs_execute(blobs,pin,channel,command,writer.length,reply,sizeof(reply),&reply_size,now);
}
static void check_blobs(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    CtapClientPin pin;
    assert(ctap_client_pin_init(&pin,service,pins)); pin.large_blobs=true;
    uint8_t pin_hash[16],token[32];
    memset(pin_hash,42,16);
    assert(pin_token(&pin,protocol,pin_hash,token)==CTAP_STATUS_OK);
    static Rp2350BlobStore store;
    static CtapLargeBlobs blobs;
    Rp2350Flash blob_flash={blob_media,read_media,program_media,erase_media};
    uint8_t store_id[16]={1}; memset(blob_media,0xff,sizeof(blob_media));
    assert(rp2350_blob_store_open(&store,&blob_flash,1,store_id)==AUTH_OK);
    blobs=(CtapLargeBlobs){.storage=rp2350_blob_store_interface(&store)};
    /* Store two opaque RP entries, remove the first while preserving the
     * second byte-for-byte, then clear the entire array. Fragment each write. */
    for(unsigned stage=0;stage<3;stage++) {
        uint8_t serialized[256];
        size_t size=blob_array(serialized,stage==1 ? 2 : 1,2-stage);
        for(size_t offset=0;offset<size;) {
            size_t chunk=size-offset; if(chunk>13) chunk=13;
            assert(blob_fragment(&blobs,&pin,protocol,token,1,serialized+offset,chunk,offset,size,1001)==CTAP_STATUS_OK);
            offset+=chunk;
        }
        /* Reopen the bank, not only the RAM cursor, to prove persistence. */
        assert(rp2350_blob_store_open(&store,&blob_flash,1,store_id)==AUTH_OK);
        uint8_t actual[256]; size_t total=0;
        CtapLargeBlobStorage storage=rp2350_blob_store_interface(&store);
        assert(storage.read(storage.context,0,actual,size,&total)==AUTH_OK && total==size && !memcmp(actual,serialized,size));
    }
    uint8_t empty[256]; size_t empty_size=blob_array(empty,1,0);
    assert(blob_fragment(&blobs,&pin,protocol,token,1,empty,8,0,empty_size,1001)==CTAP_STATUS_OK);
    assert(blob_fragment(&blobs,&pin,protocol,token,2,empty+8,empty_size-8,8,0,1002)==CTAP_STATUS_INVALID_SEQUENCE);
    assert(blob_fragment(&blobs,&pin,protocol,token,1,empty,8,0,empty_size,1001)==CTAP_STATUS_OK);
    assert(blob_fragment(&blobs,&pin,protocol,token,1,empty+8,empty_size-8,8,0,31002)==CTAP_STATUS_INVALID_SEQUENCE);
    empty[empty_size-1]^=1;
    assert(blob_fragment(&blobs,&pin,protocol,token,1,empty,empty_size,0,empty_size,1001)==CTAP_STATUS_INTEGRITY_FAILURE);
    empty[empty_size-1]^=1;
    static uint8_t before_blob_write[sizeof(blob_media)];
    memcpy(before_blob_write,blob_media,sizeof(blob_media));
    uint8_t updated[256]; size_t updated_size=blob_array(updated,1,2);
    for(int cut=0;cut<=2;cut++) {
        memcpy(blob_media,before_blob_write,sizeof(blob_media));
        assert(rp2350_blob_store_open(&store,&blob_flash,1,store_id)==AUTH_OK);
        CtapLargeBlobStorage storage=rp2350_blob_store_interface(&store);
        write_budget=cut; (void)storage.commit(storage.context,updated,updated_size); write_budget=-1;
        assert(rp2350_blob_store_open(&store,&blob_flash,1,store_id)==AUTH_OK);
        size_t total=0; uint8_t actual[256];
        assert(storage.read(storage.context,0,NULL,0,&total)==AUTH_OK);
        assert(total==(cut<2 ? empty_size : updated_size));
        assert(storage.read(storage.context,0,actual,total,&total)==AUTH_OK);
        assert(!memcmp(actual,cut<2 ? empty : updated,total));
    }
    uint8_t message[1]={0},mac[32];
    assert(secrets.hmac_sha256(secrets.context,token,32,message,1,mac)==AUTH_OK);
    assert(ctap_client_pin_authorize_permission(&pin,protocol,CTAP_PIN_PERMISSION_CM,message,1,mac,1002)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(ctap_client_pin_authorize_permission(&pin,protocol,CTAP_PIN_PERMISSION_LBW,message,1,mac,601000)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(!pin.token_active);
    auth_secure_zero(token,sizeof(token));
    if(protocol==2) {
        uint8_t before[32],after[32];
        assert(hash(NULL,blob_media,sizeof(blob_media),before)==AUTH_OK);
        AuthStorage storage=rp2350_store_provider_storage_internal(&provider);
        static AuthCredential deleted;
        assert(storage.enumerate(storage.context,0,&deleted)==AUTH_OK);
        assert(auth_credentials_delete(service,deleted.credential_id,deleted.rp_id_hash)==AUTH_OK);
        assert(hash(NULL,blob_media,sizeof(blob_media),after)==AUTH_OK && !memcmp(before,after,32));
        memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
        puts("Credential deletion preserves the separate blob array; orphan cleanup remains a client operation");
    }
    printf("PIN protocol %u: LBW scoped/expiring token, fragment/channel/timeout/integrity checks and interrupted blob commits pass\n",protocol);
}
static uint8_t configure_rp_list_permission(CtapClientPin *pin,uint8_t protocol,const char *const *rps,size_t count,
        uint8_t permission,bool tamper) {
    uint8_t pin_hash[16],token[32],params[512],request[640],message[546],mac[32];
    memset(pin_hash,42,sizeof(pin_hash));
    assert(pin_token_permissions(pin,protocol,pin_hash,permission,token)==CTAP_STATUS_OK);
    CborWriter p; cbor_writer_init(&p,params,sizeof(params));
    assert(cbor_write_map(&p,1) && cbor_write_uint(&p,2) && cbor_write_array(&p,count));
    for(size_t i=0;i<count;i++) assert(cbor_write_text(&p,rps[i]));
    memset(message,0xff,32); message[32]=0x0d; message[33]=3;
    memcpy(message+34,params,p.length);
    assert(secrets.hmac_sha256(secrets.context,token,32,message,34+p.length,mac)==AUTH_OK);
    if(tamper) mac[0]^=1;
    CborWriter w; cbor_writer_init(&w,request,sizeof(request));
    assert(cbor_write_map(&w,4) && cbor_write_uint(&w,1) && cbor_write_uint(&w,3) && cbor_write_uint(&w,2));
    assert(w.length+p.length<=sizeof(request)); memcpy(request+w.length,params,p.length); w.length+=p.length;
    assert(cbor_write_uint(&w,3) && cbor_write_uint(&w,protocol) && cbor_write_uint(&w,4) &&
        cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)));
    return ctap_authenticator_config_execute(pin,request,w.length,1001);
}
static uint8_t configure_rp_list(CtapClientPin *pin,uint8_t protocol,const char *const *rps,size_t count) {
    return configure_rp_list_permission(pin,protocol,rps,count,CTAP_PIN_PERMISSION_CONFIG,false);
}
static void check_min_pin_length(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)],configured[sizeof(media)];
    memcpy(baseline,media,sizeof(media));
    CtapClientPin pin; AuthPinRecord record,decoded;
    uint8_t wire[RP2350_STORE_PIN_MAX],allowed[32],denied[32],minimum=0;
    assert(ctap_client_pin_init(&pin,service,pins));
    CtapGetInfoProfile profile={.make_credential=true,.hmac_secret=true,.user_presence=true,
        .pin_uv_auth=true,.max_message_size=CTAP_MESSAGE_CAPACITY,.min_pin_length=6};
    uint8_t info_reply[CTAP_GET_INFO_MAX_CBOR_SIZE]; size_t info_length=0;
    CborValue info_map,info_value;
    assert(ctap_get_info_encode(&profile,info_reply,sizeof(info_reply),&info_length));
    assert(cbor_read_document(info_reply,info_length,&info_map));
    assert(cbor_map_uint(&info_map,0x10,&info_value) && info_value.major==0 && info_value.value==AUTH_PIN_MAX_RP_IDS);
    assert(cbor_map_uint(&info_map,0x1f,&info_value) && info_value.major==4 && info_value.value==3);
    const uint8_t *config_cursor=info_value.data,*config_end=info_value.encoded+info_value.encoded_length;
    assert(cbor_read_next(&config_cursor,config_end,&info_value) && info_value.major==0 && info_value.value==2);
    assert(cbor_read_next(&config_cursor,config_end,&info_value) && info_value.major==0 && info_value.value==3);
    assert(cbor_read_next(&config_cursor,config_end,&info_value) && info_value.major==0 && info_value.value==4 && config_cursor==config_end);
    assert(cbor_map_uint(&info_map,0x1d,&info_value) && info_value.major==0 && info_value.value==63);
    assert(cbor_map_uint(&info_map,0x18,&info_value) && info_value.major==7 && info_value.value==20);
    assert(hash(NULL,(const uint8_t *)"audit.invalid",13,allowed)==AUTH_OK);
    assert(hash(NULL,(const uint8_t *)"other.invalid",13,denied)==AUTH_OK);
    assert(ctap_client_pin_min_length_for_rp(&pin,allowed,&minimum)==CTAP_STATUS_OK && minimum==0);
    const char *rps[]={"audit.invalid","other.invalid","audit.invalid"};
    assert(configure_rp_list_permission(&pin,protocol,rps,3,CTAP_PIN_PERMISSION_CONFIG,true)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(configure_rp_list_permission(&pin,protocol,rps,3,CTAP_PIN_PERMISSION_CM,false)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(pins->read(pins->context,&record)==AUTH_OK && record.min_length_rp_count==0);
    assert(configure_rp_list(&pin,protocol,rps,3)==CTAP_STATUS_OK && !pin.token_active);
    assert(pins->read(pins->context,&record)==AUTH_OK && record.min_length_rp_count==2);
    assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK && rp2350_store_pin_size(&record)==RP2350_STORE_PIN_LEGACY_MAX);
    assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_OK && !memcmp(&record,&decoded,sizeof(record)));
    /* Legacy decoder rejects the new typed record; never interprets it as an
     * old policy. New decoder still accepts the original 24-byte encoding. */
    assert(wire[0]==2 && wire[1]==0);
    uint8_t corrupted[RP2350_STORE_PIN_MAX]; memcpy(corrupted,wire,sizeof(wire)); corrupted[7]=5;
    assert(rp2350_store_pin_decode(corrupted,sizeof(corrupted),&decoded)==AUTH_BAD_DATA);
    memcpy(configured,media,sizeof(media));
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins));
    assert(ctap_client_pin_min_length_for_rp(&pin,allowed,&minimum)==CTAP_STATUS_OK && minimum==6);
    assert(configure_rp_list(&pin,protocol,NULL,0)==CTAP_STATUS_OK);
    assert(ctap_client_pin_min_length_for_rp(&pin,allowed,&minimum)==CTAP_STATUS_OK && minimum==6);
    const char *replacement[]={"other.invalid"};
    assert(configure_rp_list(&pin,protocol,replacement,1)==CTAP_STATUS_OK);
    assert(ctap_client_pin_min_length_for_rp(&pin,allowed,&minimum)==CTAP_STATUS_OK && minimum==0);
    assert(ctap_client_pin_min_length_for_rp(&pin,denied,&minimum)==CTAP_STATUS_OK && minimum==6);
    const char *at_capacity[]={"a.invalid","b.invalid","c.invalid","other.invalid"};
    assert(configure_rp_list(&pin,protocol,at_capacity,AUTH_PIN_MAX_RP_IDS)==CTAP_STATUS_OK);
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins));
    assert(pins->read(pins->context,&record)==AUTH_OK && record.min_length_rp_count==AUTH_PIN_MAX_RP_IDS);
    const char *too_many[]={"a.invalid","b.invalid","c.invalid","d.invalid","e.invalid"};
    assert(configure_rp_list(&pin,protocol,too_many,5)==CTAP_STATUS_LIMIT_EXCEEDED);
    assert(ctap_client_pin_min_length_for_rp(&pin,denied,&minimum)==CTAP_STATUS_OK && minimum==6);
    /* Inject interruption at each write boundary of the real policy append.
     * Recovery must publish the entire old or new list, never partial policy. */
    for(int cut=0;cut<4;cut++) {
        memcpy(media,configured,sizeof(media)); assert(cold_boot()==AUTH_OK);
        assert(pins->read(pins->context,&record)==AUTH_OK);
        record.min_length_rp_count=1; memset(record.min_length_rp_hashes,0,sizeof(record.min_length_rp_hashes));
        memcpy(record.min_length_rp_hashes[0],denied,32);
        write_budget=cut; AuthStatus update=pins->write(pins->context,&record); write_budget=-1;
        AuthStatus recovery=cold_boot();
        printf("RP-list interrupted append: cut=%d update=%u recovery=%u\n",cut,update,recovery);
        assert(recovery==AUTH_OK && pins->read(pins->context,&decoded)==AUTH_OK);
        assert(decoded.min_length_rp_count==1 || decoded.min_length_rp_count==2);
        if(update==AUTH_OK) assert(decoded.min_length_rp_count==1);
        assert(!memcmp(decoded.min_length_rp_hashes[decoded.min_length_rp_count==1 ? 0 : 1],denied,32));
    }
    /* Real successful credential creation, signed extension and denial paths. */
    memcpy(media,configured,sizeof(media)); assert(cold_boot()==AUTH_OK);
    AuthNonresidentProvider old=service->nonresident;
    service->nonresident=rp2350_store_provider_nonresident_internal(&provider);
    for(unsigned permit=0;permit<4;permit++) {
        assert(ctap_client_pin_init(&pin,service,pins));
        CtapMakeCredential request;
        uint8_t parameters[512],client_hash[32]; memset(client_hash,7,32);
        CborWriter input; cbor_writer_init(&input,parameters,sizeof(parameters));
        assert(cbor_write_map(&input,permit==2 ? 4 : 5) && cbor_write_uint(&input,1) &&
            cbor_write_bytes(&input,client_hash,32) && cbor_write_uint(&input,2) &&
            cbor_write_map(&input,1) && cbor_write_text(&input,"id") &&
            cbor_write_text(&input,permit==1 ? "denied.invalid" : "audit.invalid") &&
            cbor_write_uint(&input,3) && cbor_write_map(&input,1) && cbor_write_text(&input,"id") &&
            cbor_write_bytes(&input,(const uint8_t *)"test-user",9) && cbor_write_uint(&input,4) &&
            cbor_write_array(&input,1) && cbor_write_map(&input,2) && cbor_write_text(&input,"alg") &&
            cbor_write_int(&input,AUTH_COSE_ALG_ES256) && cbor_write_text(&input,"type") && cbor_write_text(&input,"public-key"));
        if(permit!=2) assert(cbor_write_uint(&input,6) && cbor_write_map(&input,permit==0 ? 3 : 2) &&
            (permit!=0 || (cbor_write_text(&input,"uvm") && cbor_write_bool(&input,true))) &&
            cbor_write_text(&input,"minPinLength") && cbor_write_bool(&input,permit!=3) &&
            cbor_write_text(&input,"pinComplexityPolicy") && cbor_write_bool(&input,permit!=3));
        uint8_t output[1024],aaguid[16]={1}; size_t length=0;
        static CtapMakeCredentialWorkspace mc;
        assert(ctap_make_credential_prepare_with_pin(service,&mc,&pin,1001,
            parameters,input.length,&request)==CTAP_STATUS_OK);
        assert(ctap_make_credential_finish_at(service,&mc,&request,aaguid,output,sizeof(output),&length,1002)==CTAP_STATUS_OK);
        CborValue root,data,extension,value,statement,sig;
        assert(cbor_read_document(output,length,&root) && cbor_map_uint(&root,2,&data));
        size_t id_length=((size_t)data.data[53]<<8)|data.data[54];
        const uint8_t *cursor=data.data+55+id_length,*end=data.data+data.value;
        CborValue public_key; assert(cbor_read_next(&cursor,end,&public_key));
        if(permit==0) {
            assert(data.data[32]&0x80);
            assert(cbor_read_document(cursor,(size_t)(end-cursor),&extension) &&
                cbor_map_text(&extension,"minPinLength",&value) && value.major==0 && value.value==6);
            assert(!cbor_map_text(&extension,"pinComplexityPolicy",&value));
            assert(cbor_map_text(&extension,"uvm",&value) && value.major==4 && value.value==1);
        } else assert(!(data.data[32]&0x80) && cursor==end);
        /* Verify packed self-attestation covers the output, not merely that the
         * encoder placed bytes in the map. */
        assert(cbor_map_uint(&root,3,&statement) && cbor_map_text(&statement,"sig",&sig));
        uint8_t signed_data[1024],digest[32],point[65]={4};
        assert(data.value+32<=sizeof(signed_data)); memcpy(signed_data,data.data,(size_t)data.value);
        memcpy(signed_data+data.value,request.client_data_hash,32);
        assert(hash(NULL,signed_data,(size_t)data.value+32,digest)==AUTH_OK);
        assert(cbor_map_uint(&public_key,0,&value)==false);
        const uint8_t *key_cursor=public_key.data,*key_end=public_key.encoded+public_key.encoded_length;
        for(uint64_t i=0;i<public_key.value;i++) {
            CborValue k,v; assert(cbor_read_next(&key_cursor,key_end,&k) && cbor_read_next(&key_cursor,key_end,&v));
            if(k.major==1 && (k.value==1 || k.value==2)) {
                assert(v.major==2 && v.value==32); memcpy(point+(k.value==1 ? 1 : 33),v.data,32);
            }
        }
        mbedtls_ecdsa_context verifier; mbedtls_ecdsa_init(&verifier);
        assert(mbedtls_ecp_group_load(&verifier.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1)==0);
        assert(mbedtls_ecp_point_read_binary(&verifier.MBEDTLS_PRIVATE(grp),&verifier.MBEDTLS_PRIVATE(Q),point,65)==0);
        assert(mbedtls_ecdsa_read_signature(&verifier,digest,32,sig.data,(size_t)sig.value)==0);
        mbedtls_ecdsa_free(&verifier);
    }
    service->nonresident=old;
    /* The real destructive reset primitives clear the configured list along
     * with credentials and restore the original empty-policy encoding. */
    static Rp2350StoreCheckpointWorkspace intent_workspace;
    static Rp2350StoreResetWorkspace erase_workspace;
    Rp2350StoreSelection selection;
    Rp2350StoreResetErasure erased;
    Rp2350StoreProvisioned receipt;
    assert(rp2350_store_reset_intent_internal(&selection,&flash,&config,reset_consent,NULL,&intent_workspace)==AUTH_OK);
    assert(rp2350_store_reset_erase_internal(&erased,&flash,&config,reset_consent,NULL,&erase_workspace)==AUTH_OK);
    assert(rp2350_store_provision_internal(&receipt,&flash,&config,&base,&secrets,consent,NULL,&provisioning)==AUTH_OK);
    assert(cold_boot()==AUTH_OK && provider.cache.metadata_count==0);
    assert(pins->read(pins->context,&record)==AUTH_OK && !record.set && !record.min_length_rp_count && record.min_length==6);
    memcpy(media,baseline,sizeof(media)); assert(cold_boot()==AUTH_OK);
    assert(pins->read(pins->context,&record)==AUTH_OK && !record.min_length_rp_count);
    assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK && rp2350_store_pin_size(&record)==24);
    assert(rp2350_store_pin_decode(wire,24,&decoded)==AUTH_OK);
    puts("minPinLength: authenticated RP list, duplicate/empty/replacement/capacity, legacy/new records, interrupted writes and signed authorized-only output pass");
}
static uint8_t enable_long_touch(CtapClientPin *pin,uint8_t protocol,uint8_t permissions,bool tamper) {
    uint8_t pin_hash[16],token[32],message[34],mac[32],request[96];
    memset(pin_hash,42,sizeof(pin_hash));
    uint8_t status=pin_token_permissions(pin,protocol,pin_hash,permissions,token);
    if(status!=CTAP_STATUS_OK) return status;
    memset(message,0xff,32); message[32]=0x0d; message[33]=4;
    assert(secrets.hmac_sha256(secrets.context,token,sizeof(token),message,sizeof(message),mac)==AUTH_OK);
    if(tamper) mac[0]^=1;
    CborWriter w; cbor_writer_init(&w,request,sizeof(request));
    assert(cbor_write_map(&w,3) && cbor_write_uint(&w,1) && cbor_write_uint(&w,4) &&
        cbor_write_uint(&w,3) && cbor_write_uint(&w,protocol) && cbor_write_uint(&w,4) &&
        cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)));
    return ctap_authenticator_config_execute(pin,request,w.length,1001);
}
static void check_long_touch_policy(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)]; memcpy(baseline,media,sizeof(media));
    CtapClientPin pin; AuthPinRecord record,decoded; uint8_t wire[RP2350_STORE_PIN_MAX];
    assert(ctap_client_pin_init(&pin,service,pins) && !pin.long_touch_reset);
    assert(enable_long_touch(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,true)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(enable_long_touch(&pin,protocol,CTAP_PIN_PERMISSION_CM,false)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(pins->read(pins->context,&record)==AUTH_OK && !record.long_touch_reset);
    assert(enable_long_touch(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_OK && pin.long_touch_reset);
    assert(pins->read(pins->context,&record)==AUTH_OK && record.long_touch_reset);
    assert(rp2350_store_pin_size(&record)==RP2350_STORE_PIN_LEGACY_MAX);
    assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK && wire[0]==3 && wire[1]==0);
    assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_OK && decoded.long_touch_reset);
    wire[0]=2; assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_BAD_DATA);
    wire[0]=3; wire[6]&=(uint8_t)~4U;
    assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_BAD_DATA);
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins) && pin.long_touch_reset);
    /* Version 3 preserves the RP allowlist alongside the new reset policy. */
    record.min_length_rp_count=1; memset(record.min_length_rp_hashes[0],0x71,32);
    assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK);
    assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_OK);
    assert(decoded.long_touch_reset && decoded.min_length_rp_count==1 &&
        memcmp(decoded.min_length_rp_hashes[0],record.min_length_rp_hashes[0],32)==0);
    /* Re-enabling is an authenticated idempotent no-op, with no flash wear. */
    uint8_t hash[16],token[32]; memset(hash,42,sizeof(hash));
    assert(pin_token_permissions(&pin,protocol,hash,CTAP_PIN_PERMISSION_CONFIG,token)==CTAP_STATUS_OK);
    unsigned before=writes;
    assert(ctap_client_pin_configure(&pin,4,0,false)==CTAP_STATUS_OK && writes==before);
    for(int cut=0;cut<5;cut++) {
        memcpy(media,baseline,sizeof(media)); assert(cold_boot()==AUTH_OK);
        assert(ctap_client_pin_init(&pin,service,pins));
        assert(pin_token_permissions(&pin,protocol,hash,CTAP_PIN_PERMISSION_CONFIG,token)==CTAP_STATUS_OK);
        write_budget=cut;
        uint8_t status=ctap_client_pin_configure(&pin,4,0,false);
        write_budget=-1;
        assert(status==CTAP_STATUS_OK || status==CTAP_STATUS_OTHER);
        assert(cold_boot()==AUTH_OK && pins->read(pins->context,&record)==AUTH_OK);
        if(status==CTAP_STATUS_OK) assert(record.long_touch_reset);
        assert(auth_pin_record_valid(&record));
    }
    /* Exercise the real reset storage flow with the policy enabled. */
    memcpy(media,baseline,sizeof(media)); assert(cold_boot()==AUTH_OK);
    assert(ctap_client_pin_init(&pin,service,pins));
    assert(enable_long_touch(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_OK);
    assert(pin_token_permissions(&pin,protocol,hash,CTAP_PIN_PERMISSION_PCMR,token)==CTAP_STATUS_OK);
    uint8_t old_identifier[16],old_store_state[16],after_reset[64];
    memcpy(old_identifier,provider.cache.global.device_id,16);
    memcpy(old_store_state,provider.cache.global.store_state,16);
    static Rp2350StoreCheckpointWorkspace intent_workspace;
    static Rp2350StoreResetWorkspace erase_workspace;
    Rp2350StoreSelection selection; Rp2350StoreResetErasure erased; Rp2350StoreProvisioned receipt;
    assert(rp2350_store_reset_intent_internal(&selection,&flash,&config,reset_consent,NULL,&intent_workspace)==AUTH_OK);
    assert(rp2350_store_reset_erase_internal(&erased,&flash,&config,reset_consent,NULL,&erase_workspace)==AUTH_OK);
    assert(rp2350_store_provision_internal(&receipt,&flash,&config,&base,&secrets,consent,NULL,&provisioning)==AUTH_OK);
    assert(cold_boot()==AUTH_OK && pins->read(pins->context,&record)==AUTH_OK);
    assert(!record.long_touch_reset && !record.legacy_pin_complexity && !record.persistent_readonly && !record.set && !record.min_length_rp_count);
    assert(memcmp(old_identifier,provider.cache.global.device_id,16) && memcmp(old_store_state,provider.cache.global.store_state,16));
    assert(ctap_client_pin_init(&pin,service,pins));identifier_get_info(service,&pin,after_reset);
    assert(pin.persistent_token_present && !pin.persistent_readonly && !pin.pin_set && memcmp(token,pin.persistent_token,32));
    memcpy(media,baseline,sizeof(media)); assert(cold_boot()==AUTH_OK);
    puts("longTouchForReset: authenticated enable, wrong-MAC/permission rejection, v3 fail-closed policy, reboot and interrupted append pass");
}
static void check_pin_boundaries(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)]; memcpy(baseline,media,sizeof(media));
    for(unsigned test=0;test<6;test++) {
        memcpy(media,baseline,sizeof(media)); assert(cold_boot()==AUTH_OK);
        CtapClientPin pin; assert(ctap_client_pin_init(&pin,service,pins));
        uint8_t pp_hash[16],pp_token[32];memset(pp_hash,42,sizeof(pp_hash));
        assert(pin_token_permissions(&pin,protocol,pp_hash,CTAP_PIN_PERMISSION_PCMR,pp_token)==CTAP_STATUS_OK);
        CtapClientPinRequest change={.protocol=protocol,.subcommand=4,
            .auth_length=ctap_pin_protocol_auth_length(protocol)};
        uint8_t plain[64]={0},keys[64],old[16],message[112],reply[256]; size_t reply_size=0;
        memset(old,42,sizeof(old));
        unsigned points=0;
        if(test==0) { memset(plain,'A',63);points=63; }
        if(test==1) memset(plain,'A',64);
        if(test==2) { for(unsigned i=0;i<21;i++) { plain[i*3]=0xe2;plain[i*3+1]=0x82;plain[i*3+2]=0xac; } points=21; }
        if(test==3) for(unsigned i=0;i<32;i++) { plain[i*2]=0xc3;plain[i*2+1]=0xa4; }
        if(test==4) { memset(plain,'A',62);plain[62]=0xc3; }
        if(test==5) { memcpy(plain,"abcdefgh",8);plain[10]='x'; }
        memcpy(change.peer,crypto.agreement_public,65);
        assert(ctap_pin_protocol_shared_version(&base,&secrets,protocol,change.peer,keys)==CTAP_STATUS_OK);
        assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,old,16,change.pin_hash_enc)==CTAP_STATUS_OK);
        assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,plain,64,change.new_pin_enc)==CTAP_STATUS_OK);
        size_t prefix=ctap_pin_protocol_prefix(protocol),new_size=64+prefix,old_size=16+prefix;
        memcpy(message,change.new_pin_enc,new_size);memcpy(message+new_size,change.pin_hash_enc,old_size);
        assert(secrets.hmac_sha256(secrets.context,keys,32,message,new_size+old_size,change.auth)==AUTH_OK);
        uint8_t result=ctap_client_pin_execute(&pin,&change,reply,sizeof(reply),&reply_size,1000);
        assert(result==(points ? CTAP_STATUS_OK : CTAP_STATUS_PIN_POLICY_VIOLATION));
        AuthPinRecord record;assert(pins->read(pins->context,&record)==AUTH_OK);
        if(points) assert(record.code_points==points && !record.persistent_readonly && !pin.persistent_readonly);
        else assert(!memcmp(record.hash,old,16));
        auth_secure_zero(keys,sizeof(keys));auth_secure_zero(&change,sizeof(change));
    }
    memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
    printf("PIN protocol %u: 63/64-byte ASCII, multibyte limits, truncated UTF-8 and nonzero padding checks pass\n",protocol);
}
static uint8_t cm_request(AuthCredentialService *service,CtapClientPin *pin,CtapCredentialManagement *cm,
    uint8_t protocol,const uint8_t token[32],uint8_t command,const uint8_t rp[32],const uint8_t id[32],uint32_t now) {
    uint8_t params[96],message[97],mac[32],wire[160],reply[1024];size_t reply_size=0;
    CborWriter p;cbor_writer_init(&p,params,sizeof(params));
    if(command==4) assert(cbor_write_map(&p,1) && cbor_write_uint(&p,1) && cbor_write_bytes(&p,rp,32));
    if(command==6) assert(cbor_write_map(&p,1) && cbor_write_uint(&p,2) && cbor_write_map(&p,2) &&
        cbor_write_text(&p,"id") && cbor_write_bytes(&p,id,32) && cbor_write_text(&p,"type") && cbor_write_text(&p,"public-key"));
    message[0]=command;memcpy(message+1,params,p.length);
    assert(secrets.hmac_sha256(secrets.context,token,32,message,1+p.length,mac)==AUTH_OK);
    CborWriter w;cbor_writer_init(&w,wire,sizeof(wire));
    bool next=command==3 || command==5;
    assert(cbor_write_map(&w,next ? 1 : p.length ? 4 : 3) && cbor_write_uint(&w,1) && cbor_write_uint(&w,command));
    if(p.length) { assert(cbor_write_uint(&w,2));memcpy(wire+w.length,params,p.length);w.length+=p.length; }
    if(!next) assert(cbor_write_uint(&w,3) && cbor_write_uint(&w,protocol) && cbor_write_uint(&w,4) &&
        cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)));
    return ctap_credential_management_execute(service,pin,cm,wire,w.length,reply,sizeof(reply),&reply_size,now);
}
static void check_pcmr(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)];memcpy(baseline,media,sizeof(media));
    CtapClientPin pin;static CtapCredentialManagement cm;AuthCredential credential;
    uint8_t correct[16],token[32],again[32],ordinary[32],message[32]={1},mac[32],wire[RP2350_STORE_PIN_MAX];
    memset(correct,42,16);
    assert(service->storage.enumerate(service->storage.context,0,&credential)==AUTH_OK);
    assert(ctap_client_pin_init(&pin,service,pins));
    assert(pin_token_permissions(&pin,protocol,correct,CTAP_PIN_PERMISSION_CM,ordinary)==CTAP_STATUS_OK);
    uint64_t ordinary_generation=pin.token_generation;
    assert(pin_token_permissions(&pin,protocol,correct,CTAP_PIN_PERMISSION_PCMR,token)==CTAP_STATUS_OK);
    assert(pin.persistent_readonly && pin.token_active && pin.token_generation==ordinary_generation && !memcmp(pin.token,ordinary,32));
    assert(pin_token_permissions(&pin,protocol==1 ? 2 : 1,correct,CTAP_PIN_PERMISSION_PCMR,again)==CTAP_STATUS_OK && !memcmp(token,again,32));
    assert(pin_token_permissions(&pin,protocol,correct,CTAP_PIN_PERMISSION_PCMR|CTAP_PIN_PERMISSION_CONFIG,again)==CTAP_STATUS_UNAUTHORIZED_PERMISSION);
    assert(cm_request(service,&pin,&cm,protocol,token,1,credential.rp_id_hash,credential.credential_id,601001)==CTAP_STATUS_OK);
    ctap_client_pin_poll(&pin,601001);assert(!pin.token_active && pin.persistent_readonly);
    assert(cm_request(service,&pin,&cm,protocol,token,4,credential.rp_id_hash,credential.credential_id,601002)==CTAP_STATUS_OK && cm.persistent_authorization);
    assert(cm_request(service,&pin,&cm,protocol,token,5,NULL,NULL,601003)==CTAP_STATUS_OK);
    assert(pin_token_permissions(&pin,protocol,correct,CTAP_PIN_PERMISSION_CM,ordinary)==CTAP_STATUS_OK);
    assert(cm_request(service,&pin,&cm,protocol,token,5,NULL,NULL,601004)==CTAP_STATUS_OK);
    assert(secrets.hmac_sha256(secrets.context,token,32,message,32,mac)==AUTH_OK);
    for(unsigned bit=1;bit<=CTAP_PIN_PERMISSION_PCMR;bit<<=1) {
        assert(ctap_client_pin_authorize_permission(&pin,protocol,(uint8_t)bit,message,32,mac,1001)==CTAP_STATUS_PIN_AUTH_INVALID);
    }
    unsigned before=writes;
    assert(cm_request(service,&pin,&cm,protocol,token,6,credential.rp_id_hash,credential.credential_id,601005)==CTAP_STATUS_PIN_AUTH_INVALID && writes==before);
    AuthPinRecord record,decoded;assert(pins->read(pins->context,&record)==AUTH_OK && record.persistent_readonly);
    assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK && wire[0]==5 && rp2350_store_pin_size(&record)==RP2350_STORE_PIN_TOKEN_MAX);
    assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_OK && !memcmp(decoded.persistent_token,token,32));
    assert(rp2350_store_pin_decode(wire,RP2350_STORE_PIN_LEGACY_MAX,&decoded)==AUTH_BAD_DATA);
    const uint8_t aes_key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint8_t aes_plain[16]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t aes_expected[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    AES128_ctx aes_check;uint8_t aes_cipher[16];AES128_init(&aes_check,aes_key);
    AES128_encrypt(&aes_check,1U,aes_cipher,aes_plain);assert(!memcmp(aes_cipher,aes_expected,16));
    auth_secure_zero(&aes_check,sizeof(aes_check));
    uint8_t ids[64],next_ids[64],prk[32],key[32],salt[32]={0},info[18],iv[16],plain[16];
    assert(pins->encrypted_identifiers && pins->encrypted_identifiers(pins->context,token,ids)==AUTH_OK);
    assert(pins->encrypted_identifiers(pins->context,token,next_ids)==AUTH_OK && memcmp(ids,next_ids,16) && memcmp(ids+32,next_ids+32,16));
    assert(secrets.hmac_sha256(secrets.context,salt,32,token,32,prk)==AUTH_OK);
    const char *domains[]={"encIdentifier","encCredStoreState"};
    for(unsigned i=0;i<2;i++) {
        size_t n=strlen(domains[i]);memcpy(info,domains[i],n);info[n]=1;
        assert(secrets.hmac_sha256(secrets.context,prk,32,info,n+1,key)==AUTH_OK);
        memcpy(iv,ids+i*32,16);AES128_ctx aes;AES128_init(&aes,key);
        /* One CBC block = AES-decrypt(ciphertext) XOR IV. */
        AES128_decrypt(&aes,1U,plain,ids+i*32+16);
        for(unsigned j=0;j<16;j++) plain[j]^=iv[j];
        assert(!memcmp(plain,i ? provider.cache.global.store_state : provider.cache.global.device_id,16));
        auth_secure_zero(&aes,sizeof(aes));
    }
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins) && pin.persistent_readonly && !pin.token_active);
    assert(cm_request(service,&pin,&cm,protocol,token,1,NULL,NULL,42)==CTAP_STATUS_OK);
    assert(ctap_client_pin_configure_rpids(&pin,3,0,true,NULL,0)==CTAP_STATUS_OK && !pin.persistent_readonly);
    assert(cm_request(service,&pin,&cm,protocol,token,1,NULL,NULL,43)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins) && !pin.persistent_readonly);
    for(int cut=0;cut<4;cut++) {
        memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK && pins->read(pins->context,&record)==AUTH_OK);
        record.persistent_readonly=record.persistent_token_present=true;memcpy(record.persistent_token,token,32);
        write_budget=cut;AuthStatus status=pins->write(pins->context,&record);write_budget=-1;
        assert(cold_boot()==AUTH_OK && pins->read(pins->context,&decoded)==AUTH_OK);
        if(status==AUTH_OK) assert(decoded.persistent_readonly);
        if(decoded.persistent_readonly) assert(!memcmp(decoded.persistent_token,token,32));
    }
    memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);ctap_credential_management_clear(&cm);
    printf("PIN protocol %u pcmr: isolated persistent read-only token, reuse across protocols/reboot, ordinary expiry/replacement, enumeration, mutation denial, forced-PIN revocation and torn writes pass\n",protocol);
}
static uint8_t enterprise_enable(CtapClientPin *pin,uint8_t protocol,uint8_t permission,bool tamper) {
    uint8_t hash[16],token[32],message[34],mac[32],input[96];memset(hash,42,16);
    uint8_t status=pin_token_permissions(pin,protocol,hash,permission,token);if(status!=CTAP_STATUS_OK) return status;
    memset(message,0xff,32);message[32]=0x0d;message[33]=1;
    assert(secrets.hmac_sha256(secrets.context,token,32,message,sizeof(message),mac)==AUTH_OK);
    if(tamper) mac[0]^=1;
    CborWriter w;cbor_writer_init(&w,input,sizeof(input));
    assert(cbor_write_map(&w,3) && cbor_write_uint(&w,1) && cbor_write_uint(&w,1) &&
        cbor_write_uint(&w,3) && cbor_write_uint(&w,protocol) && cbor_write_uint(&w,4) &&
        cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)));
    return ctap_authenticator_config_execute(pin,input,w.length,1001);
}
static uint8_t enterprise_mc(AuthCredentialService *service,CtapClientPin *pin,uint8_t protocol,const char *rp,
    int enterprise,bool resident,bool ed,bool none,uint8_t *reply,size_t *reply_length) {
    uint8_t hash[16],token[32],keys[64],cipher_reply[64],client[32]={7},mac[32],input[768],user[32];
    memset(hash,42,16);memset(user,1,32);
    CtapClientPinRequest t={.protocol=protocol,.subcommand=5,.permissions=3};
    memcpy(t.peer,crypto.agreement_public,65);
    assert(ctap_pin_protocol_shared_version(&base,&secrets,protocol,t.peer,keys)==CTAP_STATUS_OK);
    assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,hash,16,t.pin_hash_enc)==CTAP_STATUS_OK);
    size_t n=0;assert(ctap_client_pin_execute(pin,&t,cipher_reply,sizeof(cipher_reply),&n,1000)==CTAP_STATUS_OK);
    CborValue root,value;assert(cbor_read_document(cipher_reply,n,&root) && cbor_map_uint(&root,2,&value));
    assert(ctap_pin_protocol_decrypt(&secrets,protocol,keys,value.data,(size_t)value.value,token)==CTAP_STATUS_OK);
    assert(secrets.hmac_sha256(secrets.context,token,32,client,32,mac)==AUTH_OK);
    CborWriter w;cbor_writer_init(&w,input,sizeof(input));
    assert(cbor_write_map(&w,7+(enterprise>=0 ? 1 : 0)+(none ? 1 : 0)) &&
        cbor_write_uint(&w,1) && cbor_write_bytes(&w,client,32) && cbor_write_uint(&w,2) &&
        cbor_write_map(&w,1) && cbor_write_text(&w,"id") && cbor_write_text(&w,rp) &&
        cbor_write_uint(&w,3) && cbor_write_map(&w,1) && cbor_write_text(&w,"id") && cbor_write_bytes(&w,user,32) &&
        cbor_write_uint(&w,4) && cbor_write_array(&w,1) && cbor_write_map(&w,2) && cbor_write_text(&w,"alg") &&
        cbor_write_int(&w,ed ? -8 : -7) && cbor_write_text(&w,"type") && cbor_write_text(&w,"public-key") &&
        cbor_write_uint(&w,7) && cbor_write_map(&w,1) && cbor_write_text(&w,"rk") && cbor_write_bool(&w,resident) &&
        cbor_write_uint(&w,8) && cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)) &&
        cbor_write_uint(&w,9) && cbor_write_uint(&w,protocol));
    if(enterprise>=0) assert(cbor_write_uint(&w,10) && cbor_write_uint(&w,(unsigned)enterprise));
    if(none) assert(cbor_write_uint(&w,11) && cbor_write_array(&w,1) && cbor_write_text(&w,"none"));
    static CtapMakeCredentialWorkspace mc;CtapMakeCredential request;uint8_t aaguid[16];
    const uint8_t model[16]={0xfa,0x02,0x4a,0x59,0xa2,0xa6,0x41,0xd9,0xbd,0x40,0xed,0x6a,0x78,0x91,0x5b,0xca};memcpy(aaguid,model,16);
    uint8_t status=ctap_make_credential_prepare_with_pin(service,&mc,pin,1001,input,w.length,&request);
    if(status==CTAP_STATUS_OK) status=ctap_make_credential_finish_at(service,&mc,&request,aaguid,reply,CTAP_MAX_RESPONSE_SIZE,reply_length,1002);
    auth_secure_zero(keys,sizeof(keys));auth_secure_zero(token,sizeof(token));return status;
}
static AuthStatus enterprise_sign_fail(void *ctx,const uint8_t digest[32],uint8_t out[72],size_t *n) {
    (void)ctx;(void)digest;memset(out,0,72);*n=0;return AUTH_CRYPTO_ERROR;
}
static void attestation_fixture(const char *role,uint8_t protocol,unsigned resident,unsigned ed,unsigned mode,const uint8_t *reply,size_t n) {
    const char *folder=getenv("TUNNLIX_ENTERPRISE_TEST_OUTPUT");if(!folder) return;
    char path[256];int length=snprintf(path,sizeof(path),"%s/%s-%u-%u-%u-%u.cbor",folder,role,protocol,resident,ed,mode);
    assert(length>0 && (size_t)length<sizeof(path));FILE *f=fopen(path,"wb");assert(f && fwrite(reply,1,n,f)==n && fclose(f)==0);
}
static void check_ordinary_chain(AuthCredentialService *service,const CborValue *statement,bool omitted) {
    CborValue chain,leaf;
    if(omitted || !auth_batch_valid(&service->batch)) { assert(!cbor_map_text(statement,"x5c",&chain));return; }
    assert(cbor_map_text(statement,"x5c",&chain) && chain.major==4 && chain.value==service->batch.certificate_count);
    const uint8_t *cursor=chain.data,*end=chain.encoded+chain.encoded_length;
    assert(cbor_read_next(&cursor,end,&leaf) && leaf.major==2 && leaf.value==service->batch.certificate_lengths[0]);
    assert(!memcmp(leaf.data,service->batch.certificates[0],(size_t)leaf.value));
    assert(leaf.value!=service->enterprise.certificate_lengths[0] || memcmp(leaf.data,service->enterprise.certificates[0],(size_t)leaf.value));
}
static void check_enterprise(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)],enabled[sizeof(media)];memcpy(baseline,media,sizeof(media));
    AuthNonresidentProvider nr=service->nonresident;AuthEnterpriseAttestation ep=service->enterprise;
    AuthBatchAttestation batch_saved=service->batch;
    service->nonresident=rp2350_store_provider_nonresident_internal(&provider);
    assert(rp2350_enterprise_configure_internal(service,&crypto));
    assert(rp2350_batch_configure_internal(service,&crypto));
    CtapClientPin pin;assert(ctap_client_pin_init(&pin,service,pins));
    uint8_t reply[CTAP_MAX_RESPONSE_SIZE];size_t n=0;
    assert(enterprise_mc(service,&pin,protocol,"audit.invalid",1,false,false,false,reply,&n)==CTAP_STATUS_INVALID_PARAMETER);
    if(!auth_enterprise_valid(&service->enterprise)) {
        assert(enterprise_enable(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_INVALID_PARAMETER);
        goto restore;
    }
    /* The general harness starts with a full resident store. Reserve a slot
     * for wrong-RP discoverable registrations; restore the original media below. */
    static AuthCredential room;
    AuthStatus room_status=service->storage.enumerate(service->storage.context,AUTH_RESIDENT_MAX_COUNT-1U,&room);
    if(room_status==AUTH_OK) assert(auth_credentials_delete(service,room.credential_id,room.rp_id_hash)==AUTH_OK);
    else assert(room_status==AUTH_NOT_FOUND);
    assert(!ctap_client_pin_enterprise_enabled(&pin));
    assert(enterprise_enable(&pin,protocol,CTAP_PIN_PERMISSION_CM,false)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(enterprise_enable(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,true)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(enterprise_enable(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_OK && ctap_client_pin_enterprise_enabled(&pin));
    uint8_t pp_hash[16],pp_token[32];memset(pp_hash,42,sizeof(pp_hash));
    assert(pin_token_permissions(&pin,protocol,pp_hash,CTAP_PIN_PERMISSION_PCMR,pp_token)==CTAP_STATUS_OK);
    unsigned before=writes;assert(ctap_client_pin_configure(&pin,1,0,false)==CTAP_STATUS_OK && writes==before);
    AuthPinRecord record,decoded;uint8_t wire[RP2350_STORE_PIN_MAX];
    assert(pins->read(pins->context,&record)==AUTH_OK && record.enterprise_enabled);
    assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK && wire[0]==6 && rp2350_store_pin_size(&record)==sizeof(wire));
    assert(rp2350_store_pin_decode(wire,sizeof(wire),&decoded)==AUTH_OK && decoded.enterprise_enabled);
    wire[0]=5;assert(rp2350_store_pin_decode(wire,sizeof(wire),&decoded)==AUTH_BAD_DATA);
    memcpy(enabled,media,sizeof(media));
    {
        CtapClientPinRequest change={.protocol=protocol,.subcommand=4,.auth_length=ctap_pin_protocol_auth_length(protocol)};
        uint8_t keys[64],plain[64]={0},message[112];size_t changed=0;
        memcpy(plain,"Abc123",6);memcpy(change.peer,crypto.agreement_public,65);
        assert(ctap_pin_protocol_shared_version(&base,&secrets,protocol,change.peer,keys)==CTAP_STATUS_OK);
        assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,pp_hash,16,change.pin_hash_enc)==CTAP_STATUS_OK);
        assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,plain,64,change.new_pin_enc)==CTAP_STATUS_OK);
        size_t prefix=ctap_pin_protocol_prefix(protocol),nnew=64+prefix,nold=16+prefix;
        memcpy(message,change.new_pin_enc,nnew);memcpy(message+nnew,change.pin_hash_enc,nold);
        assert(secrets.hmac_sha256(secrets.context,keys,32,message,nnew+nold,change.auth)==AUTH_OK);
        assert(ctap_client_pin_execute(&pin,&change,reply,sizeof(reply),&changed,1002)==CTAP_STATUS_OK);
        assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins) && ctap_client_pin_enterprise_enabled(&pin));
        assert(!pin.persistent_readonly && pin.persistent_token_present);
        assert(pins->read(pins->context,&record)==AUTH_OK && record.enterprise_enabled && record.persistent_token_present);
        auth_secure_zero(keys,sizeof(keys));
    }
    for(unsigned resident=0;resident<2;resident++) for(unsigned ed=0;ed<2;ed++) for(unsigned mode=1;mode<=2;mode++) {
        memcpy(media,enabled,sizeof(media));assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins));
        assert(ctap_client_pin_enterprise_enabled(&pin));
        assert(enterprise_mc(service,&pin,protocol,"audit.invalid",(int)mode,resident,ed,false,reply,&n)==CTAP_STATUS_OK);
        CborValue root,flag,statement,chain,alg;
        assert(cbor_read_document(reply,n,&root) && cbor_map_uint(&root,4,&flag) && flag.value==21);
        assert(cbor_map_uint(&root,3,&statement) && cbor_map_text(&statement,"x5c",&chain) && chain.major==4 && chain.value==1);
        assert(cbor_map_text(&statement,"alg",&alg) && alg.major==1 && alg.value==6);
        attestation_fixture("reply",protocol,resident,ed,mode,reply,n);
        assert(enterprise_mc(service,&pin,protocol,"audit.invalid",(int)mode,resident,ed,true,reply,&n)==CTAP_STATUS_OK);
        attestation_fixture("none",protocol,resident,ed,mode,reply,n);
        CborValue none_format,none_data;
        assert(cbor_read_document(reply,n,&root) && !cbor_map_uint(&root,4,&flag));
        assert(cbor_map_uint(&root,1,&none_format) && cbor_text_equal(&none_format,"none"));
        assert(cbor_map_uint(&root,3,&statement) && statement.major==5 && statement.value==0);
        assert(cbor_map_uint(&root,2,&none_data));
        for(unsigned byte=37;byte<53;byte++) assert(none_data.data[byte]==0);
        for(unsigned none=0;none<2;none++) {
            assert(enterprise_mc(service,&pin,protocol,"audit.invalid",-1,resident,ed,none!=0,reply,&n)==CTAP_STATUS_OK);
            assert(cbor_read_document(reply,n,&root) && !cbor_map_uint(&root,4,&flag));
            assert(cbor_map_uint(&root,3,&statement));
            check_ordinary_chain(service,&statement,none!=0);
            if(!none && auth_batch_valid(&service->batch)) attestation_fixture("ordinary",protocol,resident,ed,mode,reply,n);
        }
        if(!service->enterprise.platform_managed) {
            assert(enterprise_mc(service,&pin,protocol,"denied.invalid",(int)mode,resident,ed,false,reply,&n)==CTAP_STATUS_OK);
            assert(cbor_read_document(reply,n,&root) && !cbor_map_uint(&root,4,&flag));
            assert(cbor_map_uint(&root,3,&statement));
            check_ordinary_chain(service,&statement,false);
            if(auth_batch_valid(&service->batch)) attestation_fixture("fallback",protocol,resident,ed,mode,reply,n);
        }
    }
    /* Exercise the official tool's RP only when this identity provisions it. */
    uint8_t official_hash[32];
    const char *official_rp="enterprisetest.certinfra.fidoalliance.org";
    assert(hash(NULL,(const uint8_t *)official_rp,strlen(official_rp),official_hash)==AUTH_OK);
    bool official_allowed=false;
    for(size_t i=0;i<service->enterprise.rp_count;i++)
        official_allowed|=ctap_pin_equal(official_hash,service->enterprise.rp_hashes[i],32);
    if(official_allowed) for(unsigned mode=1;mode<=2;mode++) {
        assert(enterprise_mc(service,&pin,protocol,official_rp,(int)mode,false,false,false,reply,&n)==CTAP_STATUS_OK);
        CborValue root,flag,statement,chain,leaf;
        assert(cbor_read_document(reply,n,&root) && cbor_map_uint(&root,4,&flag) && flag.value==21);
        assert(cbor_map_uint(&root,3,&statement) && cbor_map_text(&statement,"x5c",&chain) && chain.value==1);
        const uint8_t *cursor=chain.data,*end=chain.encoded+chain.encoded_length;
        assert(cbor_read_next(&cursor,end,&leaf) && leaf.major==2);
        assert(leaf.value==service->enterprise.certificate_lengths[0] &&
            memcmp(leaf.data,service->enterprise.certificates[0],(size_t)leaf.value)==0);
    }
    assert(enterprise_mc(service,&pin,protocol,"audit.invalid",0,false,false,false,reply,&n)==CTAP_STATUS_INVALID_OPTION);
    assert(enterprise_mc(service,&pin,protocol,"audit.invalid",3,false,false,false,reply,&n)==CTAP_STATUS_INVALID_OPTION);
    AuthEnterpriseAttestation vendor_policy=service->enterprise;
    service->enterprise.platform_managed=true;service->enterprise.fingerprint[0]^=1;
    assert(!ctap_client_pin_enterprise_enabled(&pin));
    assert(enterprise_enable(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_OK);
    assert(enterprise_mc(service,&pin,protocol,"denied.invalid",2,false,false,false,reply,&n)==CTAP_STATUS_OK);
    CborValue managed_root,managed_flag;assert(cbor_read_document(reply,n,&managed_root) && cbor_map_uint(&managed_root,4,&managed_flag));
    assert(enterprise_mc(service,&pin,protocol,"denied.invalid",1,false,false,false,reply,&n)==CTAP_STATUS_OK);
    assert(cbor_read_document(reply,n,&managed_root) && !cbor_map_uint(&managed_root,4,&managed_flag));
    service->enterprise=vendor_policy;
    assert(!ctap_client_pin_enterprise_enabled(&pin));
    assert(enterprise_enable(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_OK);
    service->enterprise.fingerprint[0]^=1;
    assert(!ctap_client_pin_enterprise_enabled(&pin));
    assert(enterprise_mc(service,&pin,protocol,"audit.invalid",1,false,false,false,reply,&n)==CTAP_STATUS_INVALID_PARAMETER);
    service->enterprise.fingerprint[0]^=1;
    AuthStatus (*sign)(void *,const uint8_t[32],uint8_t[72],size_t *)=service->enterprise.sign_digest;
    service->enterprise.sign_digest=enterprise_sign_fail;
    assert(enterprise_mc(service,&pin,protocol,"audit.invalid",1,true,false,false,reply,&n)==CTAP_STATUS_OTHER);
    service->enterprise.sign_digest=sign;
    if(auth_batch_valid(&service->batch)) {
        AuthStatus (*batch_sign)(void *,const uint8_t[32],uint8_t[72],size_t *)=service->batch.sign_digest;
        service->batch.sign_digest=enterprise_sign_fail;
        assert(enterprise_mc(service,&pin,protocol,"denied.invalid",1,true,false,false,reply,&n)==CTAP_STATUS_OTHER);
        service->batch.sign_digest=batch_sign;
        size_t batch_length=service->batch.certificate_lengths[0];service->batch.certificate_lengths[0]=0;
        assert(enterprise_mc(service,&pin,protocol,"denied.invalid",1,true,false,false,reply,&n)==CTAP_STATUS_OTHER);
        assert(enterprise_mc(service,&pin,protocol,"denied.invalid",1,true,false,true,reply,&n)==CTAP_STATUS_OK);
        service->batch.certificate_lengths[0]=batch_length;

        static AuthCredentialService probe;memset(&probe,0,sizeof(probe));probe.enterprise=service->enterprise;
        AuthBatchAttestation invalid=service->batch;
        invalid.certificates[0]=service->enterprise.certificates[0];invalid.certificate_lengths[0]=service->enterprise.certificate_lengths[0];
        assert(!auth_credentials_configure_batch(&probe,&invalid));
        memset(&probe,0,sizeof(probe));probe.batch=service->batch;
        AuthEnterpriseAttestation invalid_ep=service->enterprise;
        invalid_ep.certificates[0]=service->batch.certificates[0];invalid_ep.certificate_lengths[0]=service->batch.certificate_lengths[0];
        assert(!auth_credentials_configure_enterprise(&probe,&invalid_ep));
    }
    for(int cut=0;cut<8;cut++) {
        memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins));
        assert(pins->read(pins->context,&record)==AUTH_OK);record.enterprise_enabled=true;memcpy(record.enterprise_fingerprint,service->enterprise.fingerprint,32);
        write_budget=cut;AuthStatus status=pins->write(pins->context,&record);write_budget=-1;
        assert(cold_boot()==AUTH_OK && pins->read(pins->context,&decoded)==AUTH_OK);
        assert(!decoded.enterprise_enabled || !memcmp(decoded.enterprise_fingerprint,record.enterprise_fingerprint,32));
        if(status==AUTH_OK) { assert(decoded.enterprise_enabled);break; }
        assert(cut<7);
    }
    {
        static Rp2350StoreCheckpointWorkspace intent;static Rp2350StoreResetWorkspace erase;
        Rp2350StoreSelection selected;Rp2350StoreResetErasure erased;Rp2350StoreProvisioned receipt;
        assert(rp2350_store_reset_intent_internal(&selected,&flash,&config,reset_consent,NULL,&intent)==AUTH_OK);
        assert(rp2350_store_reset_erase_internal(&erased,&flash,&config,reset_consent,NULL,&erase)==AUTH_OK);
        assert(rp2350_store_provision_internal(&receipt,&flash,&config,&base,&secrets,consent,NULL,&provisioning)==AUTH_OK);
        assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins) && !ctap_client_pin_enterprise_enabled(&pin));
    }
restore:
    service->enterprise=ep;service->batch=batch_saved;service->nonresident=nr;memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
    printf("PIN protocol %u enterprise: identity-gated enable, default/reset off, authenticated consent, ordinary/unauthorized RP privacy, modes 1/2, both credential algorithms/types, fingerprint and signing failure, torn writes pass\n",protocol);
}
static void check_payment(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)];memcpy(baseline,media,sizeof(media));
    AuthNonresidentProvider old=service->nonresident;
    service->nonresident=rp2350_store_provider_nonresident_internal(&provider);
    assert(auth_credentials_payment_supported(service));
    for(unsigned resident=0;resident<2;resident++) for(unsigned ed=0;ed<2;ed++) for(unsigned payment=0;payment<3;payment++) {
        memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
        CtapClientPin pin;assert(ctap_client_pin_init(&pin,service,pins));
        uint8_t old_hash[16],token[32],mac[32],client[32]={7},params[768],reply[1024],aaguid[16]={1},user[32];
        memset(old_hash,42,16);memset(user,1,32);
        assert(pin_token_permissions(&pin,protocol,old_hash,CTAP_PIN_PERMISSION_MC,token)==CTAP_STATUS_OK);
        assert(secrets.hmac_sha256(secrets.context,token,32,client,32,mac)==AUTH_OK);
        CborWriter w;cbor_writer_init(&w,params,sizeof(params));
        assert(cbor_write_map(&w,8) && cbor_write_uint(&w,1) && cbor_write_bytes(&w,client,32) &&
            cbor_write_uint(&w,2) && cbor_write_map(&w,1) && cbor_write_text(&w,"id") && cbor_write_text(&w,"audit.invalid") &&
            cbor_write_uint(&w,3) && cbor_write_map(&w,1) && cbor_write_text(&w,"id") && cbor_write_bytes(&w,user,32) &&
            cbor_write_uint(&w,4) && cbor_write_array(&w,1) && cbor_write_map(&w,2) && cbor_write_text(&w,"alg") &&
            cbor_write_int(&w,ed ? -8 : -7) && cbor_write_text(&w,"type") && cbor_write_text(&w,"public-key") &&
            cbor_write_uint(&w,6) && cbor_write_map(&w,payment==2 ? 0 : 1));
        if(payment!=2) assert(cbor_write_text(&w,"thirdPartyPayment") && cbor_write_bool(&w,payment==1));
        assert(cbor_write_uint(&w,7) && cbor_write_map(&w,1) && cbor_write_text(&w,"rk") && cbor_write_bool(&w,resident!=0) &&
            cbor_write_uint(&w,8) && cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)) &&
            cbor_write_uint(&w,9) && cbor_write_uint(&w,protocol));
        static CtapMakeCredentialWorkspace mc;CtapMakeCredential request;size_t length=0;
        assert(ctap_make_credential_prepare_with_pin(service,&mc,&pin,1001,params,w.length,&request)==CTAP_STATUS_OK);
        assert(ctap_make_credential_finish_at(service,&mc,&request,aaguid,reply,sizeof(reply),&length,1002)==CTAP_STATUS_OK);
        CborValue root,data;assert(cbor_read_document(reply,length,&root) && cbor_map_uint(&root,2,&data));
        assert(!(data.data[32]&0x80)); /* No unsolicited MC extension output. */
        size_t id_length=((size_t)data.data[53]<<8)|data.data[54];uint8_t id[256];memcpy(id,data.data+55,id_length);
        if(!resident) assert(id_length==256 && id[4]==(payment==1 ? 2 : 1));
        assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins));
        AuthCredential credential;assert(auth_credentials_get_id(service,id,id_length,request.rp_id_hash,&credential)==AUTH_OK);
        assert(credential.third_party_payment==(payment==1));
        if(!resident) {
            uint8_t tampered[256];memcpy(tampered,id,256);tampered[100]^=1;
            assert(auth_credentials_get_id(service,tampered,256,request.rp_id_hash,&credential)==AUTH_NOT_FOUND);
        }
        assert(pin_token_permissions(&pin,protocol,old_hash,CTAP_PIN_PERMISSION_GA,token)==CTAP_STATUS_OK);
        assert(secrets.hmac_sha256(secrets.context,token,32,client,32,mac)==AUTH_OK);
        cbor_writer_init(&w,params,sizeof(params));
        assert(cbor_write_map(&w,6) && cbor_write_uint(&w,1) && cbor_write_text(&w,"audit.invalid") &&
            cbor_write_uint(&w,2) && cbor_write_bytes(&w,client,32) && cbor_write_uint(&w,3) && cbor_write_array(&w,1) &&
            cbor_write_map(&w,2) && cbor_write_text(&w,"id") && cbor_write_bytes(&w,id,id_length) &&
            cbor_write_text(&w,"type") && cbor_write_text(&w,"public-key") && cbor_write_uint(&w,4) &&
            cbor_write_map(&w,2) && cbor_write_text(&w,"uvm") && cbor_write_bool(&w,true) &&
            cbor_write_text(&w,"thirdPartyPayment") && cbor_write_bool(&w,true) &&
            cbor_write_uint(&w,6) && cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)) &&
            cbor_write_uint(&w,7) && cbor_write_uint(&w,protocol));
        static CtapGetAssertionWorkspace ga;CtapGetAssertion assertion;
        assert(ctap_get_assertion_prepare_with_pin(service,&ga,&pin,1001,params,w.length,&assertion)==CTAP_STATUS_OK);
        assert(ctap_get_assertion_finish_at(service,&ga,&assertion,reply,sizeof(reply),&length,1002)==CTAP_STATUS_OK);
        CborValue ext,value;assert(cbor_read_document(reply,length,&root) && cbor_map_uint(&root,2,&data));
        assert(data.value>37 && cbor_read_document(data.data+37,(size_t)data.value-37,&ext));
        assert(cbor_map_text(&ext,"thirdPartyPayment",&value) && value.value==(payment==1 ? 21 : 20));
        assert(cbor_map_text(&ext,"uvm",&value) && value.value==2);
        /* Verify the signed payment/UVM bytes with independent signature verification. */
        uint8_t pub[65],signed_data[1024],digest[32];CborValue sig;
        assert(auth_credentials_get_id(service,id,id_length,request.rp_id_hash,&credential)==AUTH_OK);
        assert(service->crypto.public_key(service->crypto.context,&credential.key,pub)==AUTH_OK);
        assert(cbor_map_uint(&root,3,&sig) && data.value+32<=sizeof(signed_data));
        memcpy(signed_data,data.data,(size_t)data.value);memcpy(signed_data+data.value,client,32);
        if(ed) {
            assert(sig.value==64 && crypto_ed25519_check(sig.data,pub,signed_data,(size_t)data.value+32)==0);
            signed_data[data.value-1]^=1;
            assert(crypto_ed25519_check(sig.data,pub,signed_data,(size_t)data.value+32)!=0);
        } else {
            mbedtls_ecdsa_context verifier;mbedtls_ecdsa_init(&verifier);
            assert(mbedtls_ecp_group_load(&verifier.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1)==0);
            assert(mbedtls_ecp_point_read_binary(&verifier.MBEDTLS_PRIVATE(grp),&verifier.MBEDTLS_PRIVATE(Q),pub,65)==0);
            assert(hash(NULL,signed_data,(size_t)data.value+32,digest)==AUTH_OK);
            assert(mbedtls_ecdsa_read_signature(&verifier,digest,32,sig.data,(size_t)sig.value)==0);
            signed_data[data.value-1]^=1;
            assert(hash(NULL,signed_data,(size_t)data.value+32,digest)==AUTH_OK);
            assert(mbedtls_ecdsa_read_signature(&verifier,digest,32,sig.data,(size_t)sig.value)!=0);
            mbedtls_ecdsa_free(&verifier);
        }
        auth_credentials_release_nonresident(service);
    }
    service->nonresident=old;memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
    printf("PIN protocol %u payment: real MC/GA, both credential types/algorithms, true/false/absent, no MC output, sealed authentication and reboot pass\n",protocol);
}
static uint8_t send_unused_complexity_parameter(CtapClientPin *pin,uint8_t protocol,bool tamper) {
    uint8_t pin_hash[16],token[32],message[37],mac[32],wire[96];
    memset(pin_hash,42,sizeof(pin_hash));
    uint8_t status=pin_token_permissions(pin,protocol,pin_hash,CTAP_PIN_PERMISSION_CONFIG,token);
    if(status!=CTAP_STATUS_OK) return status;
    memset(message,0xff,32);message[32]=0x0d;message[33]=3;
    message[34]=0xa1;message[35]=4;message[36]=0xf5;
    assert(secrets.hmac_sha256(secrets.context,token,32,message,sizeof(message),mac)==AUTH_OK);
    if(tamper) mac[0]^=1;
    CborWriter w;cbor_writer_init(&w,wire,sizeof(wire));
    assert(cbor_write_map(&w,4) && cbor_write_uint(&w,1) && cbor_write_uint(&w,3) &&
        cbor_write_uint(&w,2) && cbor_write_map(&w,1) && cbor_write_uint(&w,4) && cbor_write_bool(&w,true) &&
        cbor_write_uint(&w,3) && cbor_write_uint(&w,protocol) && cbor_write_uint(&w,4) &&
        cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)));
    return ctap_authenticator_config_execute(pin,wire,w.length,1001);
}
static void check_removed_complexity(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)];memcpy(baseline,media,sizeof(media));
    CtapClientPin pin;AuthPinRecord record,decoded;uint8_t wire[RP2350_STORE_PIN_MAX];
    assert(ctap_client_pin_init(&pin,service,pins));
    assert(send_unused_complexity_parameter(&pin,protocol,true)==CTAP_STATUS_PIN_AUTH_INVALID);
    assert(send_unused_complexity_parameter(&pin,protocol,false)==CTAP_STATUS_OK && !pin.force_change);
    assert(pins->read(pins->context,&record)==AUTH_OK && !record.legacy_pin_complexity && !record.force_change);
    /* Unsupported optional Config input must not obstruct the following P-7. */
    assert(enable_long_touch(&pin,protocol,CTAP_PIN_PERMISSION_CONFIG,false)==CTAP_STATUS_OK && pin.long_touch_reset);
    for(unsigned variant=0;variant<3;variant++) {
        memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK && pins->read(pins->context,&record)==AUTH_OK);
        record.legacy_pin_complexity=true;record.force_change=false;
        record.persistent_token_present=variant!=0;record.persistent_readonly=false;
        memset(record.persistent_token,variant ? 0x6a : 0,32);
        record.enterprise_enabled=variant==2;memset(record.enterprise_fingerprint,variant==2 ? 0x5a : 0,32);
        assert(rp2350_store_pin_encode(&record,wire)==AUTH_OK && wire[0]==4+variant);
        assert(rp2350_store_pin_decode(wire,rp2350_store_pin_size(&record),&decoded)==AUTH_OK && decoded.legacy_pin_complexity);
        assert(pins->write(pins->context,&record)==AUTH_OK && cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins));
        uint8_t old_hash[16],token[32];memset(old_hash,42,sizeof(old_hash));
        assert(pin_token_permissions(&pin,protocol,old_hash,CTAP_PIN_PERMISSION_CONFIG,token)==CTAP_STATUS_OK);
        /* Legitimate explicit forced-change state still blocks token requests. */
        assert(ctap_client_pin_configure(&pin,3,0,true)==CTAP_STATUS_OK && pin.force_change);
        assert(ctap_client_pin_configure(&pin,3,0,false)==CTAP_STATUS_OK && pin.force_change);
        assert(pin_token_permissions(&pin,protocol,old_hash,CTAP_PIN_PERMISSION_CONFIG,token)==CTAP_STATUS_PIN_POLICY_VIOLATION);
        /* A numeric PIN now follows only the standard length/UTF-8 rules,
         * including when a legacy complexity bit was stored in v4/v5/v6. */
        CtapClientPinRequest change={.protocol=protocol,.subcommand=4,.auth_length=ctap_pin_protocol_auth_length(protocol)};
        uint8_t plain[64]={0},keys[64],message[112],reply[64];size_t size=0;
        memcpy(plain,"12345678",8);memcpy(change.peer,crypto.agreement_public,65);
        assert(ctap_pin_protocol_shared_version(&base,&secrets,protocol,change.peer,keys)==CTAP_STATUS_OK);
        assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,old_hash,16,change.pin_hash_enc)==CTAP_STATUS_OK);
        assert(ctap_pin_protocol_encrypt(&base,&secrets,protocol,keys,plain,64,change.new_pin_enc)==CTAP_STATUS_OK);
        size_t prefix=ctap_pin_protocol_prefix(protocol),n=64+prefix,m=16+prefix;
        memcpy(message,change.new_pin_enc,n);memcpy(message+n,change.pin_hash_enc,m);
        assert(secrets.hmac_sha256(secrets.context,keys,32,message,n+m,change.auth)==AUTH_OK);
        assert(ctap_client_pin_execute(&pin,&change,reply,sizeof(reply),&size,2000)==CTAP_STATUS_OK && !pin.force_change);
        assert(pins->read(pins->context,&record)==AUTH_OK && !record.force_change && record.retries==8);
        uint8_t digest[32];assert(hash(NULL,plain,8,digest)==AUTH_OK);
        assert(pin_token_permissions(&pin,protocol,digest,CTAP_PIN_PERMISSION_CONFIG,token)==CTAP_STATUS_OK);
        auth_secure_zero(keys,sizeof(keys));auth_secure_zero(token,sizeof(token));
    }
    memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
    printf("PIN protocol %u removed complexity: unsupported Config ignored, following P-7 authorized, legacy v4/v5/v6 readable and inactive, numeric PIN accepted, explicit forced change preserved\n",protocol);
}
/* Conformance v1.9.3 ClientPIN2 F-2 encrypts a random 64..128-byte
 * buffer. Its crypto.update emits complete blocks without final padding.
 * CTAP 2.3 setPIN step 7 requires INVALID_PARAMETER for paddedNewPin !=64.
 * The opt-in PIN2 experiment intentionally classifies oversized setPIN as
 * policy violation instead. Keep both build variants covered. */
static void check_pin_wire_lengths(AuthCredentialService *service,AuthPinStorage *pins,uint8_t protocol) {
    static uint8_t baseline[sizeof(media)]; memcpy(baseline,media,sizeof(media));
    for(size_t plain_size=16;plain_size<=128;plain_size+=16) {
        memcpy(media,baseline,sizeof(media)); assert(cold_boot()==AUTH_OK);
        AuthPinRecord record; assert(pins->read(pins->context,&record)==AUTH_OK);
        record.set=false; memset(record.hash,0,sizeof(record.hash));record.code_points=0;
        record.retries=8;record.force_change=false;
        assert(pins->write(pins->context,&record)==AUTH_OK);
        CtapClientPin pin;assert(ctap_client_pin_init(&pin,service,pins));
        uint8_t plain[128],encrypted[144]={0},keys[64],iv[16]={0},mac[32],wire[512],reply[256];
        memset(plain,'A',sizeof(plain));
        size_t prefix=ctap_pin_protocol_prefix(protocol),encrypted_size=plain_size+prefix;
        assert(ctap_pin_protocol_shared_version(&base,&secrets,protocol,crypto.agreement_public,keys)==CTAP_STATUS_OK);
        assert(secrets.aes256_cbc(secrets.context,true,keys+32,iv,plain,plain_size,encrypted+prefix)==AUTH_OK);
        assert(secrets.hmac_sha256(secrets.context,keys,32,encrypted,encrypted_size,mac)==AUTH_OK);
        CborWriter w;cbor_writer_init(&w,wire,sizeof(wire));
        assert(cbor_write_map(&w,5) && cbor_write_uint(&w,1) && cbor_write_uint(&w,protocol) &&
            cbor_write_uint(&w,2) && cbor_write_uint(&w,3) && cbor_write_uint(&w,3) && cbor_write_map(&w,5) &&
            cbor_write_int(&w,1) && cbor_write_int(&w,2) && cbor_write_int(&w,3) && cbor_write_int(&w,-25) &&
            cbor_write_int(&w,-1) && cbor_write_int(&w,1) && cbor_write_int(&w,-2) &&
            cbor_write_bytes(&w,crypto.agreement_public+1,32) && cbor_write_int(&w,-3) &&
            cbor_write_bytes(&w,crypto.agreement_public+33,32) && cbor_write_uint(&w,4) &&
            cbor_write_bytes(&w,mac,ctap_pin_protocol_auth_length(protocol)) && cbor_write_uint(&w,5) &&
            cbor_write_bytes(&w,encrypted,encrypted_size));
        CtapClientPinRequest request,unchanged;memset(&request,0x5a,sizeof(request));unchanged=request;
        unsigned before=writes;size_t reply_size=0;
        uint8_t status=ctap_client_pin_prepare(wire,w.length,&request);
        if(plain_size==64) {
            assert(status==CTAP_STATUS_OK);
            status=ctap_client_pin_execute(&pin,&request,reply,sizeof(reply),&reply_size,1000);
            assert(status==CTAP_STATUS_PIN_POLICY_VIOLATION);
        } else {
            uint8_t expected=CTAP_EXPERIMENTAL_PIN2_OVERSIZE_POLICY && protocol==2U && plain_size>64U ?
                CTAP_STATUS_PIN_POLICY_VIOLATION : CTAP_STATUS_INVALID_PARAMETER;
            assert(status==expected && !memcmp(&request,&unchanged,sizeof(request)));
        }
        assert(writes==before && pins->read(pins->context,&record)==AUTH_OK && !record.set && record.retries==8);
        printf("PIN protocol %u wire plaintext=%zu cipher=%zu returns 0x%02x, no persistent changes\n",protocol,plain_size,encrypted_size,status);
        auth_secure_zero(keys,sizeof(keys));auth_secure_zero(&request,sizeof(request));
    }
    memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
}
static void check_pin2_experiment_rejections(void) {
    /* Only the opted-in protocol-2/setPIN/aligned-oversize shape may change.
     * These failures must not publish a request or touch storage/crypto state. */
    for(unsigned test=0;test<11;test++) {
        uint8_t wire[512],cipher[144]={0},mac[32]={0},old[32]={0};
        size_t sizes[]={0,16,79,81,95,96,96,96,96,96,96};
        uint8_t protocol=test==10 ? 1U : 2U;
        unsigned command=test==8 ? 4U : 3U;
        size_t auth_size=test==6 ? 31U : ctap_pin_protocol_auth_length(protocol);
        CborWriter w;cbor_writer_init(&w,wire,sizeof(wire));
        assert(cbor_write_map(&w,command==4 ? 6 : 5) && cbor_write_uint(&w,1) && cbor_write_uint(&w,protocol) &&
            cbor_write_uint(&w,2) && cbor_write_uint(&w,command) && cbor_write_uint(&w,3) &&
            cbor_write_map(&w,5) && cbor_write_int(&w,1) && cbor_write_int(&w,2) &&
            cbor_write_int(&w,3) && cbor_write_int(&w,-25) && cbor_write_int(&w,-1) &&
            cbor_write_int(&w,test==7 ? 2 : 1) && cbor_write_int(&w,-2) &&
            cbor_write_bytes(&w,crypto.agreement_public+1,32) && cbor_write_int(&w,-3) &&
            cbor_write_bytes(&w,crypto.agreement_public+33,32) && cbor_write_uint(&w,4) &&
            cbor_write_bytes(&w,mac,auth_size) && cbor_write_uint(&w,5));
        if(test==9) assert(cbor_write_text(&w,"not a ciphertext"));
        else assert(cbor_write_bytes(&w,cipher,sizes[test]));
        if(command==4) assert(cbor_write_uint(&w,6) && cbor_write_bytes(&w,old,sizeof(old)));
        CtapClientPinRequest request,unchanged;memset(&request,0x5a,sizeof(request));unchanged=request;
        unsigned before=writes;
        uint8_t status=ctap_client_pin_prepare(wire,w.length,&request);
        uint8_t expected=test==9 ? CTAP_STATUS_CBOR_UNEXPECTED_TYPE :
            test==5 && CTAP_EXPERIMENTAL_PIN2_OVERSIZE_POLICY ? CTAP_STATUS_PIN_POLICY_VIOLATION : CTAP_STATUS_INVALID_PARAMETER;
        assert(status==expected && !memcmp(&request,&unchanged,sizeof(request)) && writes==before);
    }
    puts("PIN2 experiment: short/unaligned/type/MAC-length/curve/changePIN/protocol-1 errors retain their rejection; request and storage unchanged");
}
static void check_pin_policy(AuthCredentialService *service,AuthPinStorage *pins) {
    CtapClientPin pin; AuthPinRecord record; uint8_t wrong[16],correct[16],token[32];
    memset(wrong,43,16); memset(correct,42,16);
    for(unsigned attempt=0;attempt<8;attempt++) {
        if(attempt%3==0) {
            assert(cold_boot()==AUTH_OK);
            assert(ctap_client_pin_init(&pin,service,pins)); pin.large_blobs=true;
        }
        uint8_t status=pin_token(&pin,2,wrong,token);
        assert(status==(attempt==7 ? CTAP_STATUS_PIN_BLOCKED : attempt%3==2 ? CTAP_STATUS_PIN_AUTH_BLOCKED : CTAP_STATUS_PIN_INVALID));
        assert(pins->read(pins->context,&record)==AUTH_OK && record.retries==7-attempt);
        if(attempt%3==2) {
            assert(pin_token(&pin,2,correct,token)==CTAP_STATUS_PIN_AUTH_BLOCKED);
            assert(pins->read(pins->context,&record)==AUTH_OK && record.retries==7-attempt);
        }
    }
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins)); pin.large_blobs=true;
    assert(pin_token(&pin,2,correct,token)==CTAP_STATUS_PIN_BLOCKED);
    memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
    assert(pins->read(pins->context,&record)==AUTH_OK); record.force_change=true;
    assert(pins->write(pins->context,&record)==AUTH_OK);
    assert(ctap_client_pin_init(&pin,service,pins)); pin.large_blobs=true;
    assert(pin_token(&pin,2,correct,token)==CTAP_STATUS_PIN_POLICY_VIOLATION && !pin.token_active);
    CtapClientPinRequest change={.protocol=2,.subcommand=4,.auth_length=32};
    uint8_t keys[64],plain[64]={0},message[112],reply[256],digest[32]; size_t reply_size=0;
    memcpy(plain,"12345678",8); memcpy(change.peer,crypto.agreement_public,65);
    assert(ctap_pin_protocol_shared_version(&base,&secrets,2,change.peer,keys)==CTAP_STATUS_OK);
    assert(ctap_pin_protocol_encrypt(&base,&secrets,2,keys,correct,16,change.pin_hash_enc)==CTAP_STATUS_OK);
    assert(ctap_pin_protocol_encrypt(&base,&secrets,2,keys,plain,64,change.new_pin_enc)==CTAP_STATUS_OK);
    memcpy(message,change.new_pin_enc,80); memcpy(message+80,change.pin_hash_enc,32);
    assert(secrets.hmac_sha256(secrets.context,keys,32,message,sizeof(message),change.auth)==AUTH_OK);
    assert(ctap_client_pin_execute(&pin,&change,reply,sizeof(reply),&reply_size,1000)==CTAP_STATUS_OK);
    assert(hash(NULL,plain,8,digest)==AUTH_OK);
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&pin,service,pins)); pin.large_blobs=true;
    assert(pin_token(&pin,2,digest,token)==CTAP_STATUS_OK);
    assert(pins->read(pins->context,&record)==AUTH_OK && !record.force_change && record.retries==8 && record.code_points==8);
    auth_secure_zero(keys,sizeof(keys)); auth_secure_zero(token,sizeof(token)); ctap_client_pin_invalidate(&pin);
    puts("PIN policy: 3-try power-cycle block, durable 8-try exhaustion, forced change and new-PIN unlock pass");
}
static AuthStatus zero_identifier_random(void *ctx,uint8_t *out,size_t n) {
    (void)ctx;memset(out,0,n);return AUTH_OK;
}
static bool identifier_reset_unavailable(void *ctx) {(void)ctx;return false;}
static bool identifier_capture(void *ctx,const uint8_t report[64],uint64_t transfer) {
    (void)transfer;memcpy(ctx,report,64);return true;
}
static void identifier_get_info(AuthCredentialService *service,CtapClientPin *pin,uint8_t output[64]) {
    static CtaphidCtapBackend backend;static CtaphidDevice device;
    uint8_t captured[64]={0},report[64]={0};
    CtapGetInfoProfile profile={.max_message_size=CTAPHID_MAX_MESSAGE_SIZE,.user_presence=true,.usb_transport=true};
    assert(ctaphid_ctap_backend_init(&backend,&profile));
    assert(ctaphid_ctap_backend_configure_credentials(&backend,service));
    assert(ctaphid_ctap_backend_configure_reset(&backend,0,identifier_reset_unavailable,NULL));
    assert(ctaphid_ctap_backend_configure_pin(&backend,pin));
    CtaphidDeviceConfig config={.submit_report=identifier_capture,.transport_context=captured,
        .start_cbor=ctaphid_ctap_backend_start,.abort_cbor=ctaphid_ctap_backend_abort,.cbor_context=&backend};
    assert(ctaphid_device_init(&device,&config)==CTAPHID_DEVICE_OK);
    memset(report,0xff,4);report[4]=0x86;report[6]=8;
    assert(ctaphid_device_receive_report(&device,report,64,1)==CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&device,1)==CTAPHID_DEVICE_OK && captured[4]==0x86);
    memcpy(report,captured+15,4);report[4]=0x90;report[6]=1;report[7]=4;
    assert(ctaphid_device_receive_report(&device,report,64,2)==CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&device,2)==CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&backend,&device,2)==CTAPHID_DEVICE_OK);
    assert(device.response_count && device.response[0].bytes[7]==CTAP_STATUS_OK && backend.profile.encrypted_identifiers);
    uint8_t encoded[CTAP_GET_INFO_MAX_CBOR_SIZE];size_t size=0;CborValue map,value;
    assert(ctap_get_info_encode(&backend.profile,encoded,sizeof encoded,&size) && cbor_read_document(encoded,size,&map));
    assert(cbor_map_uint(&map,0x19,&value) && value.major==2 && value.value==32);memcpy(output,value.data,32);
    assert(cbor_map_uint(&map,0x1e,&value) && value.major==2 && value.value==32);memcpy(output+32,value.data,32);
    ctaphid_ctap_backend_abort(&backend,backend.operation_id);
}
static void check_identifier_startup(AuthCredentialService *service) {
    static uint8_t baseline[sizeof(media)];memcpy(baseline,media,sizeof(media));
    AuthPinStorage pins=rp2350_store_provider_pin_internal(&provider);
    AuthPinRecord record;CtapClientPin pin,again;
    assert(pins.read(pins.context,&record)==AUTH_OK && !record.set && !record.persistent_token_present);
    unsigned boot_writes=writes,boot_erases=erases;
    locked=true;trial_mode=true;
    assert(cold_boot()==AUTH_OK && provider.read_only && ctap_client_pin_init(&again,service,&pins));
    assert(writes==boot_writes && erases==boot_erases && !again.persistent_token_present);
    locked=false;trial_mode=false;assert(cold_boot()==AUTH_OK);
    AuthPinStorage without_identifiers=pins;without_identifiers.encrypted_identifiers=NULL;
    assert(ctap_client_pin_init(&again,service,&without_identifiers));
    assert(ctap_client_pin_ensure_identifier_token(&again)==CTAP_STATUS_OK && !again.persistent_token_present && writes==boot_writes);
    assert(ctap_client_pin_init(&pin,service,&pins));
    assert(!pin.persistent_token_present);
    uint8_t initial_output[64];identifier_get_info(service,&pin,initial_output);
    assert(!pin.pin_set && pin.persistent_token_present && !pin.persistent_readonly);
    assert(pins.read(pins.context,&record)==AUTH_OK && auth_pin_record_valid(&record));
    uint8_t token[32],hash[16]={0},reply[32],ids[64],next[64];memcpy(token,record.persistent_token,32);
    record.persistent_readonly=true;assert(!auth_pin_record_valid(&record));record.persistent_readonly=false;
    unsigned before=writes;
    assert(ctap_client_pin_init(&again,service,&pins) && !memcmp(again.persistent_token,token,32) && writes==before);
    assert(ctap_client_pin_ensure_identifier_token(&again)==CTAP_STATUS_OK && writes==before);
    for(unsigned protocol=1;protocol<=2;protocol++)
        assert(pin_token_permissions(&pin,(uint8_t)protocol,hash,CTAP_PIN_PERMISSION_PCMR,reply)==CTAP_STATUS_PIN_NOT_SET);
    assert(pins.encrypted_identifiers(pins.context,token,ids)==AUTH_OK);
    assert(pins.encrypted_identifiers(pins.context,token,next)==AUTH_OK);
    assert(memcmp(ids,next,16) && memcmp(ids+32,next+32,16) && writes==before);
    identifier_get_info(service,&pin,next);
    assert(memcmp(initial_output,next,16) && memcmp(initial_output+32,next+32,16) && writes==before);
    assert(cold_boot()==AUTH_OK && ctap_client_pin_init(&again,service,&pins));
    assert(!memcmp(again.persistent_token,token,32) && !again.persistent_readonly && !again.pin_set);
    /* Failed RNG/migration writes must never publish a usable token. Restore
     * the original synthetic media between interrupted migration attempts. */
    memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
    AuthStatus (*random)(void *,uint8_t *,size_t)=service->crypto.random;
    assert(ctap_client_pin_init(&again,service,&pins));service->crypto.random=zero_identifier_random;
    assert(ctap_client_pin_ensure_identifier_token(&again)==CTAP_STATUS_OTHER && again.faulted);service->crypto.random=random;
    assert(pins.read(pins.context,&record)==AUTH_OK && !record.persistent_token_present);
    for(int cut=0;cut<5;cut++) {
        memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
        assert(ctap_client_pin_init(&again,service,&pins));write_budget=cut;
        bool initialized=ctap_client_pin_ensure_identifier_token(&again)==CTAP_STATUS_OK;write_budget=-1;
        assert(cold_boot()==AUTH_OK && pins.read(pins.context,&record)==AUTH_OK && auth_pin_record_valid(&record));
        if(initialized) assert(record.persistent_token_present && !record.persistent_readonly && !record.set);
        assert(ctap_client_pin_init(&again,service,&pins));
        assert(ctap_client_pin_ensure_identifier_token(&again)==CTAP_STATUS_OK && again.persistent_token_present && !again.persistent_readonly);
    }
    memcpy(media,baseline,sizeof(media));assert(cold_boot()==AUTH_OK);
    auth_secure_zero(token,sizeof token);auth_secure_zero(reply,sizeof reply);
    auth_secure_zero(&pin,sizeof pin);auth_secure_zero(&again,sizeof again);auth_secure_zero(&record,sizeof record);
    puts("PASS identifier startup: pre-PIN discovery token, no unauthenticated grants, stable reboot/no repeated writes, zero-RNG and interrupted migration recovery");
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    printf("Native sizes: application=%zu, provider workspace=%zu, reset workspace=%zu, replay state=%zu bytes\n",
        sizeof(Rp2350Application),sizeof(Rp2350StoreProviderWorkspace),sizeof(Rp2350StoreResetFlowWorkspace),sizeof(Rp2350StoreReplayState));
    memset(media,0xff,sizeof(media)); initialize_crypto();
    config=(Rp2350StoreBootConfig){.policy={.profile=1},.resolve=resolve,.hash=hash,.key_inspect=inspect};
    bool bench_only=argc==2 && strcmp(argv[1],"--bench")==0;
    bool policy_only=argc==2 && strcmp(argv[1],"--policy")==0;
    bool identifiers_only=argc==2 && strcmp(argv[1],"--identifiers")==0;
    if(argc==2 && !bench_only && !policy_only && !identifiers_only) {
        FILE *file=fopen(argv[1],"rb");
        assert(file && fread(media,1,sizeof(media),file)==sizeof(media));
        assert(fgetc(file)==EOF && fclose(file)==0);
        assert(cold_boot()==AUTH_OK && provider.cache.metadata_count==32);
        AuthStorage storage=rp2350_store_provider_storage_internal(&provider);
        AuthCrypto c=rp2350_store_provider_crypto_internal(&provider);
        static AuthCredential item;
        for(size_t i=0;i<32;i++) {
            assert(storage.enumerate(storage.context,i,&item)==AUTH_OK);
            uint8_t pub[65];
            assert(c.public_key(c.context,&item.key,pub)==AUTH_OK);
            check_signature(&c,&item,pub);
        }
        AuthPinStorage pins=rp2350_store_provider_pin_internal(&provider); AuthPinRecord pin;
        assert(pins.read(pins.context,&pin)==AUTH_OK); pin.retries=7;
        assert(pins.write(pins.context,&pin)==AUTH_OK);
        assert(cold_boot()==AUTH_OK && provider.cache.metadata_count==32);
        assert(pins.read(pins.context,&pin)==AUTH_OK && pin.retries==7);
        assert(storage.enumerate(storage.context,0,&item)==AUTH_OK);
        AuthSecretCrypto primitive=rp2350_store_provider_secrets_internal(&provider);
        static AuthCredentialService service;
        assert(auth_credentials_init(&service,&c,&storage));
        assert(auth_credentials_configure_secrets(&service,&primitive));
        /* Resident deletion must also advance storeState; the plain erase
         * callback correctly refuses to bypass that invariant. */
        assert(auth_credentials_delete(&service,item.credential_id,item.rp_id_hash)==AUTH_OK);
        assert(cold_boot()==AUTH_OK && provider.cache.metadata_count==31);
        rp2350_crypto_free(&crypto);
        puts("PASS: v1.3 snapshot opens 32 keys, signs both algorithms, persists v3 PIN update and compacts to 31 keys");
        return 0;
    }
    Rp2350StoreProvisioned receipt;
    assert(rp2350_store_provision_internal(&receipt,&flash,&config,&base,&secrets,consent,NULL,&provisioning)==AUTH_OK);
    assert(rp2350_store_provider_recover_internal(&provider,&flash,&config,&crypto,&workspace)==AUTH_OK);
    static AuthCredentialService service;
    AuthCrypto c=rp2350_store_provider_crypto_internal(&provider);
    AuthStorage storage=rp2350_store_provider_storage_internal(&provider);
    AuthSecretCrypto secret_provider=rp2350_store_provider_secrets_internal(&provider);
    assert(auth_credentials_init(&service,&c,&storage));
    assert(auth_credentials_configure_secrets(&service,&secret_provider));
    check_identifier_startup(&service);
    if(identifiers_only) {
        AuthPinStorage pins=rp2350_store_provider_pin_internal(&provider);AuthPinRecord pin;
        assert(pins.read(pins.context,&pin)==AUTH_OK);pin.set=true;pin.code_points=6;memset(pin.hash,42,16);
        assert(pins.write(pins.context,&pin)==AUTH_OK);
        check_long_touch_policy(&service,&pins,1);check_long_touch_policy(&service,&pins,2);
        rp2350_crypto_free(&crypto);return 0;
    }
    for(unsigned count=0;count<=32;count++) {
        if(count==0 || count==8 || count==16 || count==32) {
            AuthPinStorage pins=rp2350_store_provider_pin_internal(&provider); AuthPinRecord pin;
            assert(pins.read(pins.context,&pin)==AUTH_OK); pin.set=true; pin.code_points=6; memset(pin.hash,42,16);
            reads=writes=entropy_calls=0; double start=(double)clock()/CLOCKS_PER_SEC;
            for(unsigned i=0;i<10;i++) {
                pin.retries=7; assert(pins.write(pins.context,&pin)==AUTH_OK);
                pin.retries=8; assert(pins.write(pins.context,&pin)==AUTH_OK);
            }
            printf("PIN write benchmark: credentials=%u, journal=%u, reads=%u, writes=%u, entropy calls=%u, CPU seconds/10 pairs=%.6f\n",
                count,provider.journal_end,reads,writes,entropy_calls,(double)clock()/CLOCKS_PER_SEC-start);
            reads=0; start=(double)clock()/CLOCKS_PER_SEC;
            static AuthCredential item;
            for(size_t i=0;i<count;i++) assert(storage.enumerate(storage.context,i,&item)==AUTH_OK);
            printf("Enumerate benchmark: credentials=%u, reads=%u, CPU seconds=%.6f\n",count,reads,(double)clock()/CLOCKS_PER_SEC-start);
        }
        if(count==32) break;
        static AuthCredential metadata,credential; uint8_t pub[65];
        memset(&metadata,0,sizeof(metadata));
        memcpy(metadata.rp_id,"audit.invalid",13); metadata.rp_id_length=13;
        metadata.user_id_length=32; memset(metadata.user_id,(int)(count+1),32);
        metadata.cred_protect=3; metadata.algorithm=count%2 ? -8 : -7;
        assert(hash(NULL,metadata.rp_id,metadata.rp_id_length,metadata.rp_id_hash)==AUTH_OK);
        assert(auth_credentials_create_resident(&service,&metadata,&credential,pub)==AUTH_OK);
        check_signature(&c,&credential,pub);
    }
    reads=writes=erases=entropy_calls=0;
    double listing_start=(double)clock()/CLOCKS_PER_SEC;
    for(size_t i=0;i<32;i++) {
        static AuthCredential listed; uint8_t pub[65],blob_key[32];
        assert(storage.enumerate(storage.context,i,&listed)==AUTH_OK);
        assert(c.public_key(c.context,&listed.key,pub)==AUTH_OK);
        assert(secret_provider.large_blob_key(secret_provider.context,&listed.key,blob_key)==AUTH_OK);
        auth_secure_zero(blob_key,sizeof(blob_key));
    }
    printf("CM-style list 32: reads=%u, entropy calls=%u, CPU seconds=%.6f\n",reads,entropy_calls,(double)clock()/CLOCKS_PER_SEC-listing_start);
    double clearing_start=(double)clock()/CLOCKS_PER_SEC;
    for(unsigned i=0;i<1000;i++) auth_secure_zero(&workspace,sizeof(workspace));
    printf("Workspace clearing x1000: %zu bytes each, CPU seconds=%.6f\n",sizeof(workspace),(double)clock()/CLOCKS_PER_SEC-clearing_start);
    memcpy(saved,media,sizeof(media));
    if(policy_only) {
        AuthPinStorage pins=rp2350_store_provider_pin_internal(&provider);
        check_min_pin_length(&service,&pins,1); check_min_pin_length(&service,&pins,2);
        check_long_touch_policy(&service,&pins,1); check_long_touch_policy(&service,&pins,2);
        check_pin_boundaries(&service,&pins,1);check_pin_boundaries(&service,&pins,2);
        check_pin_wire_lengths(&service,&pins,1);check_pin_wire_lengths(&service,&pins,2);
        check_pin2_experiment_rejections();
        check_up_permissions(&service,&pins,1); check_up_permissions(&service,&pins,2);
        check_blobs(&service,&pins,1); check_blobs(&service,&pins,2);
        check_enterprise(&service,&pins,1); check_enterprise(&service,&pins,2);
        check_pcmr(&service,&pins,1); check_pcmr(&service,&pins,2);
        check_payment(&service,&pins,1); check_payment(&service,&pins,2);
        check_removed_complexity(&service,&pins,1); check_removed_complexity(&service,&pins,2);
        check_pin_policy(&service,&pins); rp2350_crypto_free(&crypto); return 0;
    }
    static AuthCredential deleted;
    assert(storage.enumerate(storage.context,0,&deleted)==AUTH_OK);
    reads=writes=erases=entropy_calls=0;
    double deletion_start=(double)clock()/CLOCKS_PER_SEC;
    assert(auth_credentials_delete(&service,deleted.credential_id,deleted.rp_id_hash)==AUTH_OK);
    unsigned delete_pages=writes;
    printf("DELETE at 32 credentials: reads=%u, page programs=%u, sector erases=%u, entropy calls=%u, CPU seconds=%.6f, remaining=%zu\n",
        reads,writes,erases,entropy_calls,(double)clock()/CLOCKS_PER_SEC-deletion_start,provider.cache.metadata_count);
    if(bench_only) { rp2350_crypto_free(&crypto); return 0; }
    memcpy(media,saved,sizeof(media));
    assert(cold_boot()==AUTH_OK);
    AuthPinStorage pins=rp2350_store_provider_pin_internal(&provider); AuthPinRecord pin;
    assert(pins.read(pins.context,&pin)==AUTH_OK); pin.retries=7;
    write_budget=1;
    AuthStatus interrupted=pins.write(pins.context,&pin);
    write_budget=-1;
    AuthStatus recovered=cold_boot();
    printf("TORN WRITE: failed PIN write status=%u; cold boot status=%u; live=%u; expected prior credentials=32\n",interrupted,recovered,provider.live);
    assert(interrupted!=AUTH_OK && recovered==AUTH_OK && provider.live && provider.cache.metadata_count==32);
    memcpy(media,saved,sizeof(media));
    assert(cold_boot()==AUTH_OK);
    /* Recovery wipes workspace; choose inactive arena by authenticating a fresh boot. */
    static Rp2350StoreBootResult boot;
    static Rp2350StoreBootWorkspace boot_workspace;
    assert(rp2350_store_boot_internal(&boot,&flash,&config,&boot_workspace)==AUTH_OK);
    uint32_t inactive=boot.selection.selector.arena ? RP2350_STORE_ARENA_A : RP2350_STORE_ARENA_B;
    media[inactive+256]=0;
    locked=true; trial_mode=true;
    reads=writes=erases=0;
    AuthStatus trial=cold_boot();
    assert(trial==AUTH_OK && provider.read_only && writes==0 && erases==0);
    assert(rp2350_crypto_activate_internal(&crypto)==AUTH_OK);
    locked=false;
    AuthStatus confirmed=rp2350_store_provider_finish_trial_internal(&provider);
    assert(confirmed==AUTH_OK && !provider.read_only && provider.live && erases==1);
    trial_mode=false;
    AuthStatus stable=cold_boot();
    printf("TRIAL DIRTY INACTIVE BANK: read-only recovery=%u, confirmation cleanup=%u, normal recovery=%u\n",trial,confirmed,stable);
    assert(stable==AUTH_OK);
    /* Cut every page boundary of a real delete, checkpoint and selector
     * switch. Recovery may retain or delete the target depending on whether
     * its transaction committed; the other 31 must always remain available. */
    for(unsigned cut=0;cut<=delete_pages;cut++) {
        memcpy(media,saved,sizeof(media));
        assert(cold_boot()==AUTH_OK);
        assert(storage.enumerate(storage.context,0,&deleted)==AUTH_OK);
        write_budget=(int)cut;
        AuthStatus deletion=auth_credentials_delete(&service,deleted.credential_id,deleted.rp_id_hash);
        write_budget=-1;
        AuthStatus resumed=cold_boot();
        if(resumed!=AUTH_OK) printf("FAILED DELETE CUT %u: recovery=%u\n",cut,resumed);
        assert(resumed==AUTH_OK && provider.live);
        assert(provider.cache.metadata_count==31 || provider.cache.metadata_count==32);
        if(deletion==AUTH_OK) assert(provider.cache.metadata_count==31);
    }
    printf("DELETE/CHECKPOINT/SELECTOR power cuts: all %u program-page boundaries recovered\n",delete_pages+1);
    /* Prefix and interleaved-bit patterns exercise real NOR 1-to-0 partial
     * programming, including a torn header and the final single commit bit. */
    const int prefixes[]={1,63,255,256,256,256};
    const unsigned keeps[]={0,0,0,0,0x55,0xaa};
    for(unsigned pattern=0;pattern<sizeof(prefixes)/sizeof(prefixes[0]);pattern++) {
        for(unsigned cut=0;cut<delete_pages;cut++) {
            memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
            assert(storage.enumerate(storage.context,0,&deleted)==AUTH_OK);
            write_budget=(int)cut; partial_prefix=prefixes[pattern]; partial_keep=keeps[pattern];
            (void)auth_credentials_delete(&service,deleted.credential_id,deleted.rp_id_hash);
            write_budget=-1; partial_prefix=-1;
            AuthStatus resumed=cold_boot();
            if(resumed!=AUTH_OK) printf("FAILED PARTIAL pattern=%u cut=%u recovery=%u\n",pattern,cut,resumed);
            assert(resumed==AUTH_OK && provider.live && (provider.cache.metadata_count==31 || provider.cache.metadata_count==32));
        }
        printf("Partial NOR pattern %u: all %u interrupted page programs recovered\n",pattern,delete_pages);
    }
    for(int cut=0;cut<=2;cut++) {
        memcpy(media,saved,sizeof(media));
        assert(cold_boot()==AUTH_OK);
        pins=rp2350_store_provider_pin_internal(&provider);
        assert(pins.read(pins.context,&pin)==AUTH_OK);
        pin.retries=7;
        write_budget=cut;
        (void)pins.write(pins.context,&pin);
        write_budget=-1;
        assert(cold_boot()==AUTH_OK && provider.cache.metadata_count==32);
        assert(pins.read(pins.context,&pin)==AUTH_OK);
        assert(pin.retries==(cut<2 ? 8U : 7U));
    }
    assert(rp2350_store_boot_internal(&boot,&flash,&config,&boot_workspace)==AUTH_OK);
    uint32_t commit_at=boot.selection.arena_base+provider.journal_end-256U;
    media[commit_at-32U]^=1U;
    assert(cold_boot()==AUTH_BAD_DATA && !provider.live);
    puts("PIN cuts: attempt retained only after commit; corrupted committed MAC fails closed");
    /* Exhaust both selector sectors, then interrupt recycling of a stale
     * populated sector. A healthy retained selector must mount its full arena
     * before repairing the damaged sector. Never mount an erased old arena. */
    memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
    rp2350_store_provider_close_internal(&provider);
    static Rp2350StoreCompactionWorkspace maintenance_workspace;
    Rp2350StoreMaintenance receipt2;
    for(unsigned i=0;i<14;i++) assert(rp2350_store_compact_internal(&receipt2,&flash,&config,&maintenance_workspace)==AUTH_OK);
    static uint8_t recycle_saved[RP2350_STORE_PARTITION_SIZE];
    memcpy(recycle_saved,media,sizeof(media));
    const int erased_prefixes[]={1,63,255,2048,4095,4096};
    for(size_t i=0;i<sizeof(erased_prefixes)/sizeof(erased_prefixes[0]);i++) {
        memcpy(media,recycle_saved,sizeof(media));
        erase_budget=0; erase_prefix=erased_prefixes[i];
        assert(rp2350_store_compact_internal(&receipt2,&flash,&config,&maintenance_workspace)!=AUTH_OK);
        erase_budget=-1; erase_prefix=-1;
        assert(cold_boot()==AUTH_OK && provider.cache.metadata_count==32);
        rp2350_store_provider_close_internal(&provider);
    }
    memcpy(media,recycle_saved,sizeof(media));
    media[4096U+7U*512U+224U]^=1U;
    assert(cold_boot()!=AUTH_OK && !provider.live);
    puts("Selector recycling: partial stale-sector erases recover; corrupted latest authority cannot mount erased old state");
    memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
    assert(storage.enumerate(storage.context,0,&deleted)==AUTH_OK);
    assert(auth_credentials_delete(&service,deleted.credential_id,deleted.rp_id_hash)==AUTH_OK);
    memcpy(recycle_saved,media,sizeof(media));
    static AuthCredential replacement,created;
    uint8_t created_public[65]; memset(&replacement,0,sizeof(replacement));
    memcpy(replacement.rp_id,"audit.invalid",13); replacement.rp_id_length=13;
    memset(replacement.user_id,0x90,32); replacement.user_id_length=32;
    replacement.algorithm=AUTH_COSE_ALG_EDDSA; replacement.cred_protect=3;
    assert(hash(NULL,replacement.rp_id,13,replacement.rp_id_hash)==AUTH_OK);
    writes=0;
    assert(auth_credentials_create_resident(&service,&replacement,&created,created_public)==AUTH_OK);
    unsigned creation_pages=writes;
    for(unsigned pattern=0;pattern<sizeof(prefixes)/sizeof(prefixes[0]);pattern++) {
        for(unsigned cut=0;cut<=creation_pages;cut++) {
            memcpy(media,recycle_saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
            write_budget=(int)cut; partial_prefix=prefixes[pattern]; partial_keep=keeps[pattern];
            AuthStatus creation=auth_credentials_create_resident(&service,&replacement,&created,created_public);
            write_budget=-1; partial_prefix=-1;
            assert(cold_boot()==AUTH_OK && (provider.cache.metadata_count==31 || provider.cache.metadata_count==32));
            if(creation==AUTH_OK) { assert(provider.cache.metadata_count==32); check_signature(&c,&created,created_public); }
        }
    }
    printf("Creation/capacity reuse: all %u page boundaries across six partial-program patterns recover\n",creation_pages+1);
    memcpy(media,saved,sizeof(media)); assert(cold_boot()==AUTH_OK);
    assert(pins.read(pins.context,&pin)==AUTH_OK); pin.force_change=false;
    assert(pins.write(pins.context,&pin)==AUTH_OK);
    check_min_pin_length(&service,&pins,1); check_min_pin_length(&service,&pins,2);
        check_long_touch_policy(&service,&pins,1); check_long_touch_policy(&service,&pins,2);
        check_pin_boundaries(&service,&pins,1);check_pin_boundaries(&service,&pins,2);
        check_pin_wire_lengths(&service,&pins,1);check_pin_wire_lengths(&service,&pins,2);
        check_pin2_experiment_rejections();
    check_up_permissions(&service,&pins,1); check_up_permissions(&service,&pins,2);
    check_blobs(&service,&pins,1);
    check_blobs(&service,&pins,2);
    check_enterprise(&service,&pins,1); check_enterprise(&service,&pins,2);
    check_pcmr(&service,&pins,1); check_pcmr(&service,&pins,2);
    check_payment(&service,&pins,1); check_payment(&service,&pins,2);
    check_removed_complexity(&service,&pins,1); check_removed_complexity(&service,&pins,2);
    check_pin_policy(&service,&pins);
    rp2350_crypto_free(&crypto);
}
