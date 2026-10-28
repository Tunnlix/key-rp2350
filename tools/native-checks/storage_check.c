#include "storage_provision_internal.h"
#include "storage_provider_internal.h"
#include "storage_key_record_internal.h"
#include "application.h"
#include "ctap/ctap_large_blobs.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/cbor_writer.h"
#include "mbedtls/ecdsa.h"
#include "monocypher-ed25519.h"
#include <assert.h>
#include <stdio.h>
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
            memcpy(request.credential_id,credential.credential_id,AUTH_CREDENTIAL_ID_SIZE);
            memcpy(request.rp_id_hash,credential.rp_id_hash,32); memcpy(request.client_data_hash,message,32);
            request.extension_status=path==4 ? CTAP_STATUS_INVALID_OPTION : CTAP_STATUS_OK;
            assert(ctap_get_assertion_finish_at(service,&ga_workspace,&request,reply,sizeof(reply),&reply_size,1002)==
                (path==4 ? CTAP_STATUS_INVALID_OPTION : CTAP_STATUS_OK));
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
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    printf("Native sizes: application=%zu, provider workspace=%zu, reset workspace=%zu, replay state=%zu bytes\n",
        sizeof(Rp2350Application),sizeof(Rp2350StoreProviderWorkspace),sizeof(Rp2350StoreResetFlowWorkspace),sizeof(Rp2350StoreReplayState));
    memset(media,0xff,sizeof(media)); initialize_crypto();
    config=(Rp2350StoreBootConfig){.policy={.profile=1},.resolve=resolve,.hash=hash,.key_inspect=inspect};
    bool bench_only=argc==2 && strcmp(argv[1],"--bench")==0;
    bool policy_only=argc==2 && strcmp(argv[1],"--policy")==0;
    if(argc==2 && !bench_only && !policy_only) {
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
        check_up_permissions(&service,&pins,1); check_up_permissions(&service,&pins,2);
        check_blobs(&service,&pins,1); check_blobs(&service,&pins,2);
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
    check_up_permissions(&service,&pins,1); check_up_permissions(&service,&pins,2);
    check_blobs(&service,&pins,1);
    check_blobs(&service,&pins,2);
    check_pin_policy(&service,&pins);
    rp2350_crypto_free(&crypto);
}
