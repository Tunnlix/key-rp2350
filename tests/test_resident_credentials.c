#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"
#include "ctap/ctap_entities.h"

/* Bounded mock providers test ownership, atomic failures, privacy and channels.
 * Cryptographic primitive correctness belongs to the injected provider. */
typedef struct {
    AuthCredential records[2]; bool used[2], keys[3];
    unsigned random_counter, generated, destroyed, signed_count;
    bool hmac_fails, put_fails, erase_fails, update_fails, read_fails, enumerate_fails, sign_fails, destroy_fails;
    bool state_random_fails, generate_fails;
    uint8_t store_state[16];
} Pool;
static AuthStatus random_bytes(void *ctx, uint8_t *out, size_t n)
{ Pool *p = ctx; memset(out, (int)++p->random_counter, n);
  return p->state_random_fails && n == 16U ? AUTH_CRYPTO_ERROR : AUTH_OK; }
static AuthStatus hash(void *ctx, const uint8_t *in, size_t n, uint8_t out[32])
{ (void)ctx; memset(out, 0x42, 32U); for (size_t i = 0U; i < n; ++i) out[i % 32U] ^= in[i]; return AUTH_OK; }
static AuthStatus public_key(void *ctx, const AuthKeyHandle *key, uint8_t out[65])
{ Pool *p = ctx; if (key->bytes[0] < 1U || key->bytes[0] > 3U || !p->keys[key->bytes[0]-1U]) return AUTH_NOT_FOUND;
  memset(out, 2, 65U); out[0] = 4U; return AUTH_OK; }
static AuthStatus generate(void *ctx, AuthKeyHandle *key, uint8_t out[65])
{ Pool *p = ctx; if (p->generate_fails) return AUTH_CRYPTO_ERROR;
  for (size_t i = 0U; i < 3U; ++i) if (!p->keys[i]) {
    p->keys[i] = true; ++p->generated; memset(key->bytes, (int)i+1, 32U); return public_key(ctx, key, out); }
  return AUTH_CAPACITY; }
static AuthStatus sign(void *ctx, const AuthKeyHandle *key, const uint8_t digest[32], uint8_t out[72], size_t *length)
{ Pool *p = ctx; (void)digest; uint8_t public_bytes[65]; if (public_key(ctx, key, public_bytes) != AUTH_OK) return AUTH_NOT_FOUND;
  ++p->signed_count; if (p->sign_fails) return AUTH_CRYPTO_ERROR;
  memcpy(out, (uint8_t[]){0x30,6,2,1,1,2,1,1}, 8U); *length = 8U; return AUTH_OK; }
static AuthStatus destroy(void *ctx, const AuthKeyHandle *key)
{ Pool *p = ctx; if (p->destroy_fails) return AUTH_IO_ERROR;
  for (size_t i = 0U; i < 2U; ++i) assert(!p->used[i] || memcmp(p->records[i].key.bytes, key->bytes, 32U) != 0);
  assert(key->bytes[0] >= 1U && key->bytes[0] <= 3U && p->keys[key->bytes[0]-1U]);
  p->keys[key->bytes[0]-1U] = false; ++p->destroyed; return AUTH_OK; }
static int slot(Pool *p, const uint8_t id[32])
{ for (size_t i = 0U; i < 2U; ++i) if (p->used[i] && memcmp(p->records[i].credential_id, id, 32U) == 0) return (int)i; return -1; }
static AuthStatus read_record(void *ctx, const uint8_t id[32], AuthCredential *out)
{ Pool *p = ctx; if (p->read_fails) return AUTH_IO_ERROR; int i = slot(p,id); if (i < 0) return AUTH_NOT_FOUND; *out=p->records[i]; return AUTH_OK; }
static AuthStatus insert(void *ctx, const AuthCredential *in)
{ Pool *p = ctx; for (size_t i=0U;i<2U;++i) if (!p->used[i]) { p->used[i]=true;p->records[i]=*in;return AUTH_OK; } return AUTH_CAPACITY; }
static AuthStatus erase(void *ctx, const uint8_t id[32])
{ Pool *p=ctx; if(p->erase_fails)return AUTH_IO_ERROR;int i=slot(p,id);if(i<0)return AUTH_NOT_FOUND;p->used[i]=false;return AUTH_OK; }
static AuthStatus find(void *ctx,const uint8_t rp[32],bool discoverable,size_t index,AuthCredential *out)
{ Pool *p=ctx;for(size_t i=0U;i<2U;++i)if(p->used[i]&&memcmp(p->records[i].rp_id_hash,rp,32U)==0&&
  (!discoverable||p->records[i].discoverable)&&index--==0U){*out=p->records[i];return AUTH_OK;}return AUTH_NOT_FOUND; }
static AuthStatus count(void *ctx,size_t *out)
{ Pool *p=ctx;*out=(p->used[0]?1U:0U)+(p->used[1]?1U:0U);return AUTH_OK; }
static AuthStatus counter(void *ctx,const uint8_t id[32],uint32_t old,uint32_t next)
{ Pool *p=ctx;int i=slot(p,id);if(i<0)return AUTH_NOT_FOUND;assert(p->records[i].signature_count==old&&next==old+1U);
  p->records[i].signature_count=next;return AUTH_OK; }
static AuthStatus enumerate(void *ctx,size_t index,AuthCredential *out)
{ Pool *p=ctx;if(p->enumerate_fails)return AUTH_IO_ERROR;for(size_t i=0U;i<2U;++i)if(p->used[i]&&index--==0U){*out=p->records[i];return AUTH_OK;}return AUTH_NOT_FOUND; }
static AuthStatus put(void *ctx,const uint8_t *old_id,const AuthCredential *in,const uint8_t state[16])
{ Pool *p=ctx;if(p->put_fails)return AUTH_IO_ERROR;AuthStatus status;
  if(old_id){int i=slot(p,old_id);if(i<0)return AUTH_NOT_FOUND;p->records[i]=*in;status=AUTH_OK;}else status=insert(ctx,in);
  if(status==AUTH_OK){memcpy(p->store_state,state,16U);}return status; }
static AuthStatus erase_resident(void *ctx,const uint8_t id[32],const uint8_t state[16])
{ Pool *p=ctx;AuthStatus status=erase(ctx,id);if(status==AUTH_OK){memcpy(p->store_state,state,16U);}return status; }
static AuthStatus update(void *ctx,const AuthCredential *in,const uint8_t state[16])
{ Pool *p=ctx;if(p->update_fails)return AUTH_IO_ERROR;int i=slot(p,in->credential_id);if(i<0)return AUTH_NOT_FOUND;
  assert(memcmp(in->key.bytes,p->records[i].key.bytes,32U)==0 &&
    in->cred_protect==p->records[i].cred_protect && in->signature_count==p->records[i].signature_count &&
    in->creation_order==p->records[i].creation_order);
  memcpy(p->records[i].user_name,in->user_name,64U);p->records[i].user_name_length=in->user_name_length;
  memcpy(p->records[i].user_display_name,in->user_display_name,64U);p->records[i].user_display_name_length=in->user_display_name_length;
  memcpy(p->store_state,state,16U);return AUTH_OK; }
static AuthStatus agreement_key(void *ctx,uint8_t out[65])
{ (void)ctx;memset(out,1,65U);out[0]=4U;return AUTH_OK; }
static AuthStatus ecdh(void *ctx,const uint8_t peer[65],uint8_t out[32])
{ (void)ctx;(void)peer;memset(out,0x55,32U);return AUTH_OK; }
static AuthStatus hmac(void *ctx,const uint8_t *key,size_t key_len,const uint8_t *in,size_t n,uint8_t out[32])
{ (void)ctx;(void)key;(void)key_len;(void)in;(void)n;memset(out,0x3C,32U);return AUTH_OK; }
static AuthStatus aes(void *ctx,bool enc,const uint8_t key[32],const uint8_t iv[16],const uint8_t *in,size_t n,uint8_t *out)
{ (void)ctx;(void)enc;(void)key;(void)iv;memcpy(out,in,n);return AUTH_OK; }
static AuthStatus supported(void *ctx,const AuthKeyHandle *key,bool *out)
{ (void)ctx;(void)key;*out=true;return AUTH_OK; }
static AuthStatus credential_mac(void *ctx,const AuthKeyHandle *key,bool uv,const uint8_t salt[32],uint8_t out[32])
{ Pool *p=ctx;(void)key;(void)uv;(void)salt;if(p->hmac_fails)return AUTH_CRYPTO_ERROR;memset(out,0x11,32U);return AUTH_OK; }
static AuthStatus regenerate(void *ctx){(void)ctx;return AUTH_OK;}
static AuthStatus pin_read(void *ctx,AuthPinRecord *out)
{ (void)ctx;*out=(AuthPinRecord){0};out->set=true;out->code_points=4U;out->retries=8U;return AUTH_OK; }
static AuthStatus pin_write(void *ctx,const AuthPinRecord *in){(void)ctx;(void)in;return AUTH_OK;}
typedef struct{Pool pool;AuthCredentialService service;CtapClientPin pin;CtaphidCtapBackend backend;CtaphidDevice device;} Fixture;
static bool send(void *ctx,const uint8_t report[64],uint64_t token){(void)ctx;(void)report;(void)token;return true;}
static bool receive(void *ctx,const uint8_t report[64])
{ Fixture *f=ctx;return ctaphid_device_receive_report(&f->device,report,64U,0U)==CTAPHID_DEVICE_OK; }
static bool reset(void *ctx){(void)ctx;return true;}
static void setup(Fixture *f)
{
    memset(f,0,sizeof *f);AuthCrypto crypto={&f->pool,random_bytes,hash,generate,public_key,sign,destroy};
    AuthStorage storage={&f->pool,2U,read_record,insert,erase,find,count,counter,enumerate,put,erase_resident,update};
    assert(auth_credentials_init(&f->service,&crypto,&storage));
    AuthSecretCrypto secrets={&f->pool,agreement_key,ecdh,hmac,aes,supported,credential_mac,regenerate};
    assert(auth_credentials_configure_secrets(&f->service,&secrets));AuthPinStorage ps={&f->pool,pin_read,pin_write};
    assert(ctap_client_pin_init(&f->pin,&f->service,&ps));
    CtapGetInfoProfile profile={0};profile.max_message_size=1024U;profile.user_presence=true;
    assert(ctaphid_ctap_backend_init(&f->backend,&profile));
    assert(ctaphid_ctap_backend_configure_credentials(&f->backend,&f->service));
    assert(ctaphid_ctap_backend_configure_reset(&f->backend,0U,reset,f));
    assert(ctaphid_ctap_backend_configure_pin(&f->backend,&f->pin)&&f->backend.profile.resident_credentials);
    CtaphidDeviceConfig config={0};config.submit_report=send;config.start_cbor=ctaphid_ctap_backend_start;
    config.abort_cbor=ctaphid_ctap_backend_abort;config.cbor_context=&f->backend;config.resync_channel=ctaphid_ctap_backend_resync;
    assert(ctaphid_device_init(&f->device,&config)==CTAPHID_DEVICE_OK);
    uint32_t cid;assert(ctaphid_channels_allocate(&f->device.channels,&cid)==CTAPHID_CHANNEL_OK&&cid==1U);
    assert(ctaphid_channels_allocate(&f->device.channels,&cid)==CTAPHID_CHANNEL_OK&&cid==2U);
}
static AuthCredential metadata(const char *rp,uint8_t user,uint8_t policy)
{ AuthCredential c={0};c.rp_id_length=(uint16_t)strlen(rp);memcpy(c.rp_id,rp,c.rp_id_length);
  assert(hash(NULL,c.rp_id,c.rp_id_length,c.rp_id_hash)==AUTH_OK);c.user_id[0]=user;c.user_id_length=1U;
  memcpy(c.user_name,"Alice",5U);c.user_name_length=5U;c.cred_protect=policy;return c; }
static AuthCredential create(Fixture *f,const char *rp,uint8_t user,uint8_t policy)
{ AuthCredential m=metadata(rp,user,policy),c;uint8_t pub[65];assert(auth_credentials_create_resident(&f->service,&m,&c,pub)==AUTH_OK);return c; }
static void token(Fixture *f,uint8_t permissions,const char *rp)
{ f->pin.token_active=true;f->pin.token_used=false;f->pin.permissions=permissions;f->pin.issued_at_ms=0U;++f->pin.token_generation;
  f->pin.token_rp_bound=rp!=NULL;if(rp)hash(NULL,(const uint8_t *)rp,strlen(rp),f->pin.token_rp_hash);memset(f->pin.token,0xA5,32U); }
static size_t discovery(uint8_t *out,bool authorized)
{ CborWriter w;cbor_writer_init(&w,out,256U);uint8_t hash_bytes[32]={0},mac[32];memset(mac,0x3C,32U);
  assert(cbor_write_map(&w,authorized?4U:2U)&&cbor_write_uint(&w,1U)&&cbor_write_text(&w,"example.com")&&
    cbor_write_uint(&w,2U)&&cbor_write_bytes(&w,hash_bytes,32U));
  if(authorized){assert(cbor_write_uint(&w,6U)&&cbor_write_bytes(&w,mac,32U)&&cbor_write_uint(&w,7U)&&cbor_write_uint(&w,2U));}return w.length; }
static void assert_lookup_scratch_cleared(const AuthCredentialService *service)
{
    const unsigned char *bytes = (const unsigned char *)&service->lookup_scratch;
    for (size_t i = 0U; i < sizeof service->lookup_scratch; ++i) assert(bytes[i] == 0U);
    assert(!service->lookup_busy);
}

static void test_atomic_lifecycle_failures(void)
{
    Fixture f;setup(&f);AuthCredential first=create(&f,"example.com",1U,1U);(void)create(&f,"example.com",2U,2U);
    AuthCredential m=metadata("example.com",1U,3U),out;uint8_t pub[65];memset(&out,0xEE,sizeof out);
    f.pool.put_fails=true;assert(auth_credentials_create_resident(&f.service,&m,&out,pub)==AUTH_IO_ERROR);
    assert(out.credential_id[0]==0xEEU&&f.pool.records[0].credential_id[0]==first.credential_id[0]&&f.pool.destroyed==1U);
    f.pool.put_fails=false;AuthCredential replaced;assert(auth_credentials_create_resident(&f.service,&m,&replaced,pub)==AUTH_OK);
    assert(memcmp(replaced.credential_id,first.credential_id,32U)!=0&&f.pool.destroyed==2U&&replaced.creation_order==3U);
    m=metadata("example.com",3U,1U);unsigned generated=f.pool.generated;
    m.user_name[0]=0xC0U;m.user_name_length=1U;
    assert(auth_credentials_create_resident(&f.service,&m,&out,pub)==AUTH_INVALID_ARGUMENT&&f.pool.generated==generated);
    m=metadata("example.com",3U,1U);
    assert(auth_credentials_create_resident(&f.service,&m,&out,pub)==AUTH_CAPACITY&&f.pool.generated==generated);
    f.pool.erase_fails=true;assert(auth_credentials_delete(&f.service,replaced.credential_id,replaced.rp_id_hash)==AUTH_IO_ERROR);
    assert(f.pool.destroyed==2U&&f.pool.used[0]);f.pool.erase_fails=false;
    f.pool.update_fails=true;replaced.user_name[0]='B';assert(auth_credentials_update_user(&f.service,&replaced)==AUTH_IO_ERROR);
    assert_lookup_scratch_cleared(&f.service);
    assert(f.pool.records[0].user_name[0]=='A');f.pool.update_fails=false;
    replaced.cred_protect=1U;replaced.signature_count=77U;replaced.creation_order=99U;replaced.key.bytes[0]=0x99U;
    assert(auth_credentials_update_user(&f.service,&replaced)==AUTH_OK&&f.pool.records[0].user_name[0]=='B');
    assert_lookup_scratch_cleared(&f.service);
    assert(auth_credentials_enumerate(&f.service, 0U, &out) == AUTH_OK);
    assert_lookup_scratch_cleared(&f.service);
    f.pool.enumerate_fails=true;m=metadata("example.com",1U,1U);
    assert(auth_credentials_create_resident(&f.service,&m,&out,pub)==AUTH_IO_ERROR&&f.pool.generated==generated);
    AuthCredential saved = out;
    assert(auth_credentials_enumerate(&f.service, 0U, &out) == AUTH_IO_ERROR);
    assert(memcmp(&saved, &out, sizeof out) == 0);
    assert_lookup_scratch_cleared(&f.service);
}
static void test_registration_failure_preserves_replaced_credential(void)
{
    for (unsigned failure = 0U; failure < 3U; ++failure) {
        Fixture f; setup(&f);
        AuthCredential original = create(&f, "example.com", 1U, 1U);
        (void)create(&f, "example.com", 2U, 1U); /* Replacement at capacity. */
        CtapMakeCredential request = {0};
        request.discoverable = true; request.metadata = metadata("example.com", 1U, 1U);
        memcpy(request.rp_id_hash, original.rp_id_hash, 32U);
        request.hmac_secret_requested = true; request.hmac_secret_mc.requested = true;
        request.hmac_secret_mc.salt_enc_length = 48U; request.hmac_secret_mc.salt_auth_length = 32U;
        memset(request.hmac_secret_mc.salt_auth, 0x3C, 32U);
        f.pool.sign_fails = failure == 0U;
        f.pool.hmac_fails = failure == 1U;
        f.pool.put_fails = failure == 2U;
        uint8_t output[512], saved[512], aaguid[16] = {0}; size_t length = 999U;
        memset(output, 0xEE, sizeof output); memcpy(saved, output, sizeof output);
        uint64_t revision = f.service.metadata_revision;
        CtapMakeCredentialWorkspace workspace = {0};
        assert(ctap_make_credential_finish(&f.service, &workspace, &request, aaguid, output, sizeof output, &length) == CTAP_STATUS_OTHER);
        { assert(!workspace.busy);
        const unsigned char *scratch_bytes = (const unsigned char *)&workspace.scratch;
        for (size_t i = 0U; i < sizeof workspace.scratch; ++i) assert(scratch_bytes[i] == 0U); }
        assert(length == 999U && memcmp(output, saved, sizeof output) == 0);
        AuthCredential retained;
        assert(auth_credentials_get(&f.service, original.credential_id, original.rp_id_hash, &retained) == AUTH_OK);
        assert(memcmp(&retained, &original, sizeof retained) == 0);
        assert(f.service.metadata_revision == revision && f.pool.destroyed == 1U);
        assert(f.pool.keys[original.key.bytes[0] - 1U]);
        f.pool.sign_fails = f.pool.hmac_fails = f.pool.put_fails = false;
        assert(ctap_make_credential_finish(&f.service, &workspace, &request, aaguid, output, sizeof output, &length) == CTAP_STATUS_OK);
        { assert(!workspace.busy);
        const unsigned char *scratch_bytes = (const unsigned char *)&workspace.scratch;
        for (size_t i = 0U; i < sizeof workspace.scratch; ++i) assert(scratch_bytes[i] == 0U); }
        assert(auth_credentials_get(&f.service, original.credential_id, original.rp_id_hash, &retained) == AUTH_NOT_FOUND);
    }
}

static void test_discovery_privacy_and_sequence_failures(void)
{
    Fixture f;setup(&f);AuthCredential first=create(&f,"example.com",1U,1U);AuthCredential second=create(&f,"example.com",2U,3U);
    uint8_t input[256],out[1024];size_t n=discovery(input,false),length;CtapGetAssertionWorkspace ga_workspace = {0}; CtapGetAssertion prepared;
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace,&f.pin,0U,input,n,&prepared)==0U&&prepared.credential_count==1U);
    assert(memcmp(prepared.credential_id,first.credential_id,32U)==0);
    assert(ctap_get_assertion_finish_at(&f.service,&prepared,out,sizeof out,&length,1U)==0U);
    CborValue map,user,name;assert(cbor_read_document(out,length,&map)&&cbor_map_uint(&map,4U,&user));
    assert(!cbor_map_text(&user,"name",&name)&&!cbor_map_uint(&map,5U,&name));
    token(&f,2U,"example.com");n=discovery(input,true);
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace,&f.pin,0U,input,n,&prepared)==0U&&prepared.credential_count==2U);
    assert(memcmp(prepared.credential_id,second.credential_id,32U)==0);
    assert(!ga_workspace.busy);
    const unsigned char *scratch = (const unsigned char *)&ga_workspace.scratch;
    for (size_t i = 0U; i < sizeof ga_workspace.scratch; ++i) assert(scratch[i] == 0U);
    assert(ctap_get_assertion_finish_at(&f.service,&prepared,out,sizeof out,&length,1U)==0U&&!f.pin.token_active);
    CtapAssertionSequence sequence;ctap_assertion_sequence_begin(&sequence,&prepared,UINT32_MAX-99U);
    assert(ctap_get_next_assertion(&f.service,&sequence,out,sizeof out,&length,(UINT32_MAX-99U)+30000U)==0U);
    assert(!sequence.active&&f.pool.signed_count==3U);
    ctap_assertion_sequence_begin(&sequence,&prepared,0U);unsigned signatures=f.pool.signed_count;
    assert(ctap_get_next_assertion(&f.service,&sequence,out,sizeof out,&length,30001U)==0x30U&&f.pool.signed_count==signatures);
    ctap_assertion_sequence_begin(&sequence,&prepared,0U);f.pool.sign_fails=true;
    assert(ctap_get_next_assertion(&f.service,&sequence,out,sizeof out,&length,1U)==0x7FU&&!sequence.active);
    f.pool.sign_fails=false;ctap_assertion_sequence_begin(&sequence,&prepared,0U);
    assert(auth_credentials_delete(&f.service,first.credential_id,first.rp_id_hash)==AUTH_OK);
    assert(ctap_get_next_assertion(&f.service,&sequence,out,sizeof out,&length,1U)==0x30U);
}
static void test_backend_channel_resync_and_cancel(void)
{
    for(unsigned mode=0U;mode<5U;++mode){Fixture f;setup(&f);(void)create(&f,"example.com",1U,1U);(void)create(&f,"example.com",2U,1U);
      token(&f,2U,"example.com");uint8_t bytes[257];bytes[0]=2U;size_t n=1U+discovery(bytes+1U,true);
      assert(ctaphid_send_response(1U,0x10U,bytes,n,receive,&f)==CTAPHID_RESPONSE_OK);
      assert(ctaphid_device_poll(&f.device,0U)==CTAPHID_DEVICE_OK);
      assert(ctaphid_ctap_backend_poll(&f.backend,&f.device,0U)==CTAPHID_DEVICE_OK);
      if(mode==2U){uint8_t cancel[64]={0,0,0,1,0x91};assert(ctaphid_device_receive_report(&f.device,cancel,64U,1U)==CTAPHID_DEVICE_OK);
        assert(!f.backend.assertion_sequence.active&&f.pool.signed_count==0U);continue;}
      assert(ctaphid_ctap_backend_signal_presence(&f.backend,f.backend.operation_id,true,1U));
      assert(ctaphid_ctap_backend_poll(&f.backend,&f.device,1U)==CTAPHID_DEVICE_OK);
      assert(ctaphid_device_poll(&f.device,1U)==CTAPHID_DEVICE_OK&&f.backend.assertion_sequence.active);
      if(mode>=3U){
        const uint8_t nonce[8]={0};
        for(uint32_t cid=3U;cid<=48U;++cid){
          assert(ctaphid_send_response(UINT32_MAX,0x06U,nonce,sizeof nonce,receive,&f)==CTAPHID_RESPONSE_OK);
          assert(ctaphid_device_poll(&f.device,2U)==CTAPHID_DEVICE_OK);
          assert(ctaphid_channels_is_allocated(&f.device.channels,cid));
          assert(f.backend.assertion_sequence.active);
        }
        /* Only the original CID can use its authenticated snapshot. */
        uint8_t next[]={8U};assert(ctaphid_send_response(mode==3U?48U:1U,0x10U,next,1U,receive,&f)==CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device,3U)==CTAPHID_DEVICE_OK);
        assert(ctaphid_ctap_backend_poll(&f.backend,&f.device,3U)==CTAPHID_DEVICE_OK);
        assert(f.backend.response[0]==(mode==3U?0x30U:0U)&&!f.backend.assertion_sequence.active);
        assert(f.pool.signed_count==(mode==3U?1U:2U));
        continue;
      }
      if(mode==0U){uint8_t init[64]={0,0,0,1,0x86,0,8};assert(ctaphid_device_receive_report(&f.device,init,64U,2U)==CTAPHID_DEVICE_OK);
        assert(ctaphid_device_poll(&f.device,2U)==CTAPHID_DEVICE_OK&&!f.backend.assertion_sequence.active);}
      else{uint8_t next[]={8U};assert(ctaphid_send_response(2U,0x10U,next,1U,receive,&f)==CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device,2U)==CTAPHID_DEVICE_OK);assert(ctaphid_ctap_backend_poll(&f.backend,&f.device,2U)==CTAPHID_DEVICE_OK);
        assert(f.backend.response[0]==0x30U&&!f.backend.assertion_sequence.active&&f.pool.signed_count==1U);}
    }
}
static size_t management_request(uint8_t *out, uint8_t command, const uint8_t *id)
{
    uint8_t mac[32]; memset(mac, 0x3C, 32U); CborWriter w; cbor_writer_init(&w, out, 256U);
    assert(cbor_write_map(&w, command == 3U ? 1U : (id != NULL ? 4U : 3U)) &&
        cbor_write_uint(&w, 1U) && cbor_write_uint(&w, command));
    if (id != NULL) assert(cbor_write_uint(&w, 2U) && cbor_write_map(&w, 1U) &&
        cbor_write_uint(&w, 2U) && ctap_credential_descriptor_write(&w, id));
    if (command != 3U) assert(cbor_write_uint(&w, 3U) && cbor_write_uint(&w, 2U) &&
        cbor_write_uint(&w, 4U) && cbor_write_bytes(&w, mac, 32U));
    return w.length;
}
static void test_management_failures_and_channel_binding(void)
{
    Fixture f; setup(&f); AuthCredential a = create(&f, "example.com", 1U, 1U);
    (void)create(&f, "other.example", 2U, 1U); token(&f, 4U, NULL);
    CtapCredentialManagement state = {0}; uint8_t request[256], output[1024]; size_t length;
    size_t n = management_request(request, 1U, NULL);
    assert(ctap_credential_management_execute(&f.service, &f.pin, &state, request, n, output, sizeof output, &length, 0U) == 0U);
    CborValue map, value; assert(cbor_read_document(output, length, &map) && cbor_map_uint(&map, 1U, &value) && value.value == 2U);
    assert(cbor_map_uint(&map, 2U, &value) && value.value == 0U);
    n = management_request(request, 2U, NULL);
    assert(ctap_credential_management_execute(&f.service, &f.pin, &state, request, n, output, sizeof output, &length, 0U) == 0U && state.kind == 2U);
    n = management_request(request, 3U, NULL);
    assert(ctap_credential_management_execute(&f.service, &f.pin, &state, request, n, output, sizeof output, &length, 30001U) == 0x30U);
    token(&f, 4U, NULL); n = management_request(request, 6U, a.credential_id); f.pool.erase_fails = true;
    assert(ctap_credential_management_execute(&f.service, &f.pin, &state, request, n, output, sizeof output, &length, 0U) == 0x7FU);
    assert(f.pool.used[0] && f.pool.destroyed == 0U); f.pool.erase_fails = false;
    token(&f, 4U, "other.example");
    assert(ctap_credential_management_execute(&f.service, &f.pin, &state, request, n, output, sizeof output, &length, 0U) == 0x33U);
    assert(f.pool.used[0] && f.pool.destroyed == 0U);
    token(&f, 4U, NULL); n = management_request(request, 2U, NULL); uint8_t bytes[257]; bytes[0] = 0x0AU; memcpy(bytes + 1U, request, n);
    assert(ctaphid_send_response(1U, 0x10U, bytes, n + 1U, receive, &f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 0U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK && f.backend.management.kind == 2U);
    const uint8_t nonce[8] = {0};
    for (uint32_t cid = 3U; cid <= 48U; ++cid) {
        assert(ctaphid_send_response(UINT32_MAX, 0x06U, nonce, sizeof nonce, receive, &f) == CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(f.backend.management.kind == 2U && f.backend.management_cid == 1U);
    }
    n = management_request(bytes + 1U, 3U, NULL);
    assert(ctaphid_send_response(48U, 0x10U, bytes, n + 1U, receive, &f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f.device, 1U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 1U) == CTAPHID_DEVICE_OK && f.backend.response[0] == 0x30U);
    assert(ctaphid_device_poll(&f.device, 1U) == CTAPHID_DEVICE_OK);
    n = management_request(bytes + 1U, 6U, a.credential_id);
    assert(ctaphid_send_response(1U, 0x10U, bytes, n + 1U, receive, &f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f.device, 2U) == CTAPHID_DEVICE_OK);
    uint8_t cancel[64] = {0,0,0,1,0x91};
    assert(ctaphid_device_receive_report(&f.device, cancel, sizeof cancel, 2U) == CTAPHID_DEVICE_OK);
    assert(f.pool.used[0] && f.pool.destroyed == 0U && !f.backend.awaiting_management);
}
static void assert_management_scratch_cleared(const CtapCredentialManagement *state)
{
    const unsigned char *bytes = (const unsigned char *)&state->scratch;
    for (size_t i = 0U; i < sizeof state->scratch; ++i) assert(bytes[i] == 0U);
}

static void test_management_authentication_precedes_unknown_credential(void)
{
    Fixture f; setup(&f);
    AuthCredential original = create(&f, "example.com", 1U, 1U);
    CtapCredentialManagement state = {0};
    for (uint8_t command = 6U; command <= 7U; ++command) {
        for (unsigned descriptor = 0U; descriptor < 3U; ++descriptor) {
            for (unsigned authenticated = 0U; authenticated < 2U; ++authenticated) {
                token(&f, CTAP_PIN_PERMISSION_CM, NULL);
                uint8_t request[256], output[32], saved[32], id[32] = {0}, mac[32];
                memset(mac, authenticated ? 0x3C : 0, sizeof mac);
                CborWriter w; cbor_writer_init(&w, request, sizeof request);
                assert(cbor_write_map(&w, 4U) && cbor_write_uint(&w, 1U) && cbor_write_uint(&w, command) &&
                    cbor_write_uint(&w, 2U) && cbor_write_map(&w, command == 7U ? 2U : 1U) &&
                    cbor_write_uint(&w, 2U) && cbor_write_map(&w, 2U) &&
                    cbor_write_text(&w, "id") && cbor_write_bytes(&w, id, descriptor == 0U ? 31U : 32U) &&
                    cbor_write_text(&w, "type") && cbor_write_text(&w, descriptor == 1U ? "foreign" : "public-key"));
                if (command == 7U) assert(cbor_write_uint(&w, 3U) && cbor_write_map(&w, 1U) &&
                    cbor_write_text(&w, "id") && cbor_write_bytes(&w, original.user_id, original.user_id_length));
                assert(cbor_write_uint(&w, 3U) && cbor_write_uint(&w, 2U) &&
                    cbor_write_uint(&w, 4U) && cbor_write_bytes(&w, mac, sizeof mac));
                memset(output, 0xEE, sizeof output); memcpy(saved, output, sizeof output);
                size_t length = 999U; uint64_t revision = f.service.metadata_revision;
                assert(ctap_credential_management_execute(&f.service, &f.pin, &state, request, w.length,
                    output, sizeof output, &length, 0U) ==
                    (authenticated ? CTAP_STATUS_NO_CREDENTIALS : CTAP_STATUS_PIN_AUTH_INVALID));
                assert(length == 999U && memcmp(output, saved, sizeof output) == 0);
                assert(f.service.metadata_revision == revision && f.pool.destroyed == 0U);
                assert(memcmp(&f.pool.records[0], &original, sizeof original) == 0);
                assert_management_scratch_cleared(&state);
            }
        }
    }
}

static void test_management_workspace_lifetime(void)
{
    Fixture f; setup(&f);
    (void)create(&f, "example.com", 1U, 1U);
    (void)create(&f, "other.example", 2U, 1U);
    token(&f, CTAP_PIN_PERMISSION_CM, NULL);
    CtapCredentialManagement first = {0}, second = {0};
    uint8_t request[256], output[1024]; size_t length = 0U;
    size_t n = management_request(request, 2U, NULL);
    assert(ctap_credential_management_execute(&f.service, &f.pin, &first, request, n,
        output, sizeof output, &length, 0U) == CTAP_STATUS_OK);
    assert(first.kind == 2U && first.next == 1U && first.count == 2U);
    assert_management_scratch_cleared(&first);

    /* A separate instance can fail without destroying the first snapshot. */
    memset(output, 0xEE, sizeof output); length = 99U;
    assert(ctap_credential_management_execute(&f.service, &f.pin, &second, request, n,
        output, 1U, &length, 0U) == CTAP_STATUS_OTHER);
    assert(second.kind == 0U && first.kind == 2U && first.next == 1U);
    assert(length == 99U);
    for (size_t i = 0U; i < sizeof output; ++i) assert(output[i] == 0xEEU);
    assert_management_scratch_cleared(&second);

    n = management_request(request, 3U, NULL);
    assert(ctap_credential_management_execute(&f.service, &f.pin, &first, request, n,
        output, sizeof output, &length, 1U) == CTAP_STATUS_OK);
    assert(first.kind == 0U);
    assert_management_scratch_cleared(&first);

    n = management_request(request, 2U, NULL); f.pool.read_fails = true;
    assert(ctap_credential_management_execute(&f.service, &f.pin, &first, request, n,
        output, sizeof output, &length, 2U) == CTAP_STATUS_OTHER);
    assert_management_scratch_cleared(&first);
    memset(&first.scratch, 0xA5, sizeof first.scratch);
    assert(ctap_credential_management_execute(NULL, &f.pin, &first, request, n,
        output, sizeof output, &length, 3U) == CTAP_STATUS_OTHER);
    assert_management_scratch_cleared(&first);
}

static void assert_creation_scratch_cleared(const AuthCredentialService *service)
{
    const unsigned char *bytes = (const unsigned char *)&service->creation_scratch;
    for (size_t i = 0U; i < sizeof service->creation_scratch; ++i) assert(bytes[i] == 0U);
    assert(!service->creation_busy);
}

typedef struct {
    Fixture *owner, *other;
    unsigned calls;
} PrepareContext;

static AuthStatus prepare_with_nested_creation(void *context, const AuthCredential *staged,
    const uint8_t public_key_bytes[65])
{
    PrepareContext *test = context;
    AuthCredential saved = *staged, output;
    uint8_t key[65]; memset(&output, 0xEE, sizeof output); memset(key, 0xEE, sizeof key);
    assert(test->owner->service.creation_busy && public_key_bytes[0] == 4U);
    assert(auth_credentials_create_resident(&test->owner->service, &saved, &output, key) == AUTH_INVALID_ARGUMENT);
    assert(auth_credentials_create_protected(&test->owner->service, saved.rp_id_hash,
        saved.user_id, saved.user_id_length, false, 1U, &output, key) == AUTH_INVALID_ARGUMENT);
    assert(memcmp(staged, &saved, sizeof saved) == 0 && test->owner->service.creation_busy);
    assert(output.credential_id[0] == 0xEEU && key[0] == 0xEEU);
    assert(auth_credentials_get(&test->owner->service, test->owner->pool.records[0].credential_id,
        saved.rp_id_hash, &output) == AUTH_OK);
    assert(!test->owner->service.lookup_busy && test->owner->service.creation_busy);
    assert(memcmp(staged, &saved, sizeof saved) == 0);
    /* Independent services own independent workspaces. */
    assert(auth_credentials_create_resident(&test->other->service, &saved, &output, key) == AUTH_OK);
    assert_creation_scratch_cleared(&test->other->service);
    assert(memcmp(staged, &saved, sizeof saved) == 0);
    ++test->calls;
    return AUTH_CRYPTO_ERROR;
}

static void test_resident_workspace_lifetime(void)
{
    Fixture f, other; setup(&f); setup(&other);
    AuthCredential original = create(&f, "example.com", 1U, 1U);
    assert_creation_scratch_cleared(&f.service);
    AuthCredential m = metadata("example.com", 1U, 2U), output, saved;
    uint8_t key[65], saved_key[65];
    memset(&output, 0xEE, sizeof output); saved = output;
    memset(key, 0xEE, sizeof key); memcpy(saved_key, key, sizeof key);
    uint64_t revision = f.service.metadata_revision;
    for (unsigned failure = 0U; failure < 4U; ++failure) {
        f.pool.enumerate_fails = failure == 0U;
        f.pool.state_random_fails = failure == 1U;
        f.pool.generate_fails = failure == 2U;
        f.pool.put_fails = failure == 3U;
        assert(auth_credentials_create_resident(&f.service, &m, &output, key) != AUTH_OK);
        assert_creation_scratch_cleared(&f.service);
        assert(memcmp(&output, &saved, sizeof saved) == 0 && memcmp(key, saved_key, sizeof key) == 0);
        assert(memcmp(&f.pool.records[0], &original, sizeof original) == 0);
        assert(f.service.metadata_revision == revision);
    }
    f.pool.put_fails = false;
    PrepareContext context = {&f, &other, 0U};
    assert(auth_credentials_create_resident_prepared(&f.service, &m, prepare_with_nested_creation,
        &context, &output, key) == AUTH_CRYPTO_ERROR);
    assert(context.calls == 1U && f.service.metadata_revision == revision);
    assert(memcmp(&f.pool.records[0], &original, sizeof original) == 0);
    assert(memcmp(&output, &saved, sizeof saved) == 0 && memcmp(key, saved_key, sizeof key) == 0);
    assert_creation_scratch_cleared(&f.service);
    assert(auth_credentials_create_resident(&f.service, &m, &output, key) == AUTH_OK);
    assert(output.cred_protect == 2U && f.service.metadata_revision == revision + 1U);
    assert_creation_scratch_cleared(&f.service);
}

int main(void)
{ test_atomic_lifecycle_failures();test_registration_failure_preserves_replaced_credential();test_discovery_privacy_and_sequence_failures();test_backend_channel_resync_and_cancel();test_management_failures_and_channel_binding();
  test_management_authentication_precedes_unknown_credential();
  test_management_workspace_lifetime();
  test_resident_workspace_lifetime();
  puts("Resident tests passed (atomic replacement/failures, privacy, ordering, counters, timeout/wrap, CID/INIT/CANCEL).");return 0; }
