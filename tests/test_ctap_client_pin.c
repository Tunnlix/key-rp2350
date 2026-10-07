#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap_client_pin.h"
#include "ctap/cbor_writer.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"
#include "auth_test_provider.h"

/* Transparent primitives test policy and persistence ordering; final providers
 * require independent cryptographic validation. */
typedef struct {
    AuthPinRecord record;
    size_t reads, writes, decrypts, agreements, regenerated;
    size_t fail_write;
    bool read_fails, bad_record, bad_peer, agreement_fails, mac_fails;
    bool decrypt_fails, regenerate_fails, hash_fails, enforce_decrement;
    uint8_t expected_retries, mac_message[112];
    size_t mac_length;
    Store *credential_store;
    bool random_fails, encrypt_fails, verify_fails;
} PinMock;
static AuthStatus pin_random(void *ctx, uint8_t *out, size_t length)
{ PinMock *m = ctx; if (m->random_fails) return AUTH_CRYPTO_ERROR; memset(out, 0xA5, length); return AUTH_OK; }
static AuthStatus pin_generate(void *ctx, AuthKeyHandle *key, uint8_t out[65])
{ return generate(((PinMock *)ctx)->credential_store, key, out); }
static AuthStatus pin_public(void *ctx, const AuthKeyHandle *key, uint8_t out[65])
{ return public_key(((PinMock *)ctx)->credential_store, key, out); }
static AuthStatus pin_sign(void *ctx, const AuthKeyHandle *key, const uint8_t digest[32], uint8_t out[72], size_t *length)
{ return sign(((PinMock *)ctx)->credential_store, key, digest, out, length); }
static AuthStatus pin_destroy(void *ctx, const AuthKeyHandle *key)
{ return destroy(((PinMock *)ctx)->credential_store, key); }
static AuthStatus pin_read(void *ctx, AuthPinRecord *out)
{
    PinMock *m = ctx; ++m->reads;
    if (m->read_fails) return AUTH_IO_ERROR;
    *out = m->record;
    if (m->bad_record) out->retries = 9U;
    return AUTH_OK;
}
static AuthStatus pin_write(void *ctx, const AuthPinRecord *in)
{
    PinMock *m = ctx; ++m->writes; assert(auth_pin_record_valid(in));
    if (m->fail_write == m->writes) return AUTH_IO_ERROR;
    m->record = *in; return AUTH_OK;
}
static AuthStatus pin_hash(void *ctx, const uint8_t *data, size_t length, uint8_t out[32])
{
    PinMock *m = ctx;
    if (m->hash_fails) return AUTH_CRYPTO_ERROR;
    memset(out, 0, 32U);
    for (size_t i = 0U; i < length; ++i) out[i % 32U] ^= data[i];
    return AUTH_OK;
}
static AuthStatus agreement_public(void *ctx, uint8_t key[65])
{ PinMock *m = ctx; memset(key, (int)(1U + m->regenerated), 65U); key[0] = 4U; return AUTH_OK; }
static AuthStatus agreement(void *ctx, const uint8_t peer[65], uint8_t z[32])
{
    PinMock *m = ctx; ++m->agreements; assert(peer[0] == 4U);
    if (m->bad_peer) return AUTH_BAD_DATA;
    if (m->agreement_fails) return AUTH_CRYPTO_ERROR;
    memset(z, 0x55, 32U); return AUTH_OK;
}
static AuthStatus mac(void *ctx, const uint8_t *key, size_t key_length,
    const uint8_t *data, size_t length, uint8_t out[32])
{
    PinMock *m = ctx; (void)key; assert(key_length == 32U);
    if (m->mac_fails || (m->verify_fails && length >= 80U)) return AUTH_CRYPTO_ERROR;
    if (length >= 80U) { assert(length <= sizeof m->mac_message); memcpy(m->mac_message, data, length); m->mac_length = length; }
    memset(out, 0x3C, 32U); return AUTH_OK;
}
static AuthStatus aes(void *ctx, bool encrypt, const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *in, size_t length, uint8_t *out)
{
    PinMock *m = ctx; (void)key; (void)iv;
    assert(length == 16U || length == 32U || length == 64U);
    if (encrypt) { if (m->encrypt_fails) return AUTH_CRYPTO_ERROR; memcpy(out, in, length); return AUTH_OK; }
    ++m->decrypts;
    if (length == 16U && m->enforce_decrement) assert(m->record.retries == m->expected_retries);
    if (m->decrypt_fails) return AUTH_CRYPTO_ERROR;
    memcpy(out, in, length); return AUTH_OK;
}
static AuthStatus supported(void *ctx, const AuthKeyHandle *key, bool *out)
{ (void)ctx; (void)key; *out = true; return AUTH_OK; }
static AuthStatus credential_mac(void *ctx, const AuthKeyHandle *key, bool uv, const uint8_t salt[32], uint8_t out[32])
{ (void)ctx; (void)key; (void)uv; (void)salt; (void)out; assert(false); return AUTH_UNSUPPORTED; }
static AuthStatus regenerate(void *ctx)
{ PinMock *m = ctx; ++m->regenerated; return m->regenerate_fails ? AUTH_CRYPTO_ERROR : AUTH_OK; }
static void setup(CtapClientPin *pin, AuthCredentialService *service, Store *store, PinMock *m)
{
    memset(m, 0, sizeof *m); m->record.retries = 8U; service_init(service, store);
    m->credential_store = store;
    service->crypto.context = m; service->crypto.sha256 = pin_hash;
    service->crypto.random = pin_random; service->crypto.generate_p256 = pin_generate;
    service->crypto.public_key = pin_public; service->crypto.sign_p256_digest = pin_sign; service->crypto.destroy_key = pin_destroy;
    AuthSecretCrypto secrets = {m, agreement_public, agreement, mac, aes, supported, credential_mac, regenerate};
    assert(auth_credentials_configure_secrets(service, &secrets));
    AuthPinStorage storage = {m, pin_read, pin_write};
    assert(ctap_client_pin_init(pin, service, &storage));
}
static CtapClientPinRequest request(uint8_t command, const uint8_t *text, size_t size, const AuthPinRecord *old)
{
    CtapClientPinRequest r = {0}; r.subcommand = command; r.peer[0] = 4U;
    memset(r.auth, 0x3C, 32U); r.auth_length = 32U;
    assert(size <= 64U); memcpy(r.new_pin_enc + 16U, text, size);
    if (old != NULL) memcpy(r.pin_hash_enc + 16U, old->hash, 16U);
    return r;
}
static uint8_t execute(CtapClientPin *pin, const CtapClientPinRequest *r)
{
    uint8_t output[128]; memset(output, 0xEE, sizeof output); size_t length = 999U;
    uint8_t status = ctap_client_pin_execute(pin, r, output, sizeof output, &length, 0U);
    if (status != 0U) assert(length == 999U && output[0] == 0xEEU);
    else if (r->subcommand >= 3U) assert(length == 0U && output[0] == 0xEEU);
    return status;
}
static void seed(CtapClientPin *pin)
{
    CtapClientPinRequest r = request(3U, (const uint8_t *)"1234", 4U, NULL);
    assert(execute(pin, &r) == 0U);
}
static size_t encode(const CtapClientPinRequest *r, uint8_t *output)
{
    CborWriter w; cbor_writer_init(&w, output, 512U);
    assert(cbor_write_map(&w, r->subcommand == 9U ? 5U + (r->rp_present ? 1U : 0U) : (r->subcommand == 4U ? 6U : 5U)) && cbor_write_uint(&w, 1U) && cbor_write_uint(&w, 2U) &&
        cbor_write_uint(&w, 2U) && cbor_write_uint(&w, r->subcommand) && cbor_write_uint(&w, 3U) && cbor_write_map(&w, 5U) &&
        cbor_write_int(&w, 1) && cbor_write_int(&w, 2) && cbor_write_int(&w, 3) && cbor_write_int(&w, -25) &&
        cbor_write_int(&w, -1) && cbor_write_int(&w, 1) && cbor_write_int(&w, -2) && cbor_write_bytes(&w, r->peer + 1U, 32U) &&
        cbor_write_int(&w, -3) && cbor_write_bytes(&w, r->peer + 33U, 32U));
    if (r->subcommand == 9U) {
        assert(cbor_write_uint(&w, 6U) && cbor_write_bytes(&w, r->pin_hash_enc, 32U) &&
            cbor_write_uint(&w, 9U) && cbor_write_uint(&w, r->permissions));
        if (r->rp_present) assert(cbor_write_uint(&w, 10U) && cbor_write_text(&w, "example.com"));
        return w.length;
    }
    assert(cbor_write_uint(&w, 4U) && cbor_write_bytes(&w, r->auth, r->auth_length) &&
        cbor_write_uint(&w, 5U) && cbor_write_bytes(&w, r->new_pin_enc, 80U));
    if (r->subcommand == 4U) assert(cbor_write_uint(&w, 6U) && cbor_write_bytes(&w, r->pin_hash_enc, 32U));
    return w.length;
}
static void test_validation_and_pin_policy(void)
{
    const struct { uint8_t bytes[8]; size_t size; uint8_t status; } cases[] = {
        {{0xA0},1U,0x14}, {{0xA1,2,0x61,'3'},4U,0x11}, {{0xA1,2,2},3U,0x14},
        {{0xA2,1,1,2,2},5U,2}, {{0xA2,1,2,2,3},5U,0x14}, {{0xA1,2,9},3U,0x14},
        {{0xA2,2,1,2,1},5U,0x12}
    };
    CtapClientPinRequest prepared;
    for (size_t i = 0U; i < sizeof cases / sizeof cases[0]; ++i)
        assert(ctap_client_pin_prepare(cases[i].bytes, cases[i].size, &prepared) == cases[i].status);
    const uint8_t retries[] = {0xA1,2,1};
    assert(ctap_client_pin_prepare(retries, sizeof retries, &prepared) == 0U && prepared.subcommand == 1U);
    Store store = {0}; PinMock m; AuthCredentialService service; CtapClientPin pin;
    setup(&pin, &service, &store, &m);
    const uint8_t invalid[][8] = {{'1','2','3'}, {0xC3,0xA9,0xC3,0xA9}, {0xC0,0x80,'1','2'}, {'1',0,'2','3','4'}};
    const size_t sizes[] = {3U,4U,4U,5U};
    for (size_t i = 0U; i < 4U; ++i) {
        CtapClientPinRequest r = request(3U, invalid[i], sizes[i], NULL);
        assert(execute(&pin, &r) == 0x37U && m.writes == 0U);
    }
    uint8_t too_long[64]; memset(too_long, 'a', sizeof too_long);
    CtapClientPinRequest r = request(3U, too_long, 64U, NULL);
    assert(execute(&pin, &r) == 0x37U);
    r = request(3U, (const uint8_t *)"1234", 4U, NULL); r.auth[0] ^= 1U;
    assert(execute(&pin, &r) == 0x33U && m.decrypts == 5U && m.writes == 0U);
    uint8_t input[512]; size_t size = encode(&r, input);
    assert(ctap_client_pin_prepare(input, size, &prepared) == 0U);
    r.auth_length = 31U; size = encode(&r, input);
    assert(ctap_client_pin_prepare(input, size, &prepared) == 0x33U);
    const uint8_t unicode[] = {0xF0,0x9F,0x98,0x80,0xC3,0xA9,'1','2'};
    r = request(3U, unicode, sizeof unicode, NULL);
    assert(execute(&pin, &r) == 0U && m.record.code_points == 4U && m.record.retries == 8U);
    assert(execute(&pin, &r) == 0x33U && m.writes == 1U);
    assert(store.generated == 0U && store.signatures == 0U);
}
static void test_retries_and_power_cycle(void)
{
    Store store = {0}; PinMock m; AuthCredentialService service; CtapClientPin pin;
    setup(&pin, &service, &store, &m); seed(&pin);
    CtapClientPinRequest wrong = request(4U, (const uint8_t *)"5678", 4U, NULL);
    for (unsigned cycle = 0U; cycle < 3U; ++cycle) {
        for (unsigned i = 0U; i < 3U && m.record.retries != 0U; ++i) {
            m.enforce_decrement = true; m.expected_retries = m.record.retries - 1U;
            uint8_t expected = m.expected_retries == 0U ? 0x32U : (i == 2U ? 0x34U : 0x31U);
            assert(execute(&pin, &wrong) == expected);
        }
        uint8_t remaining = m.record.retries; size_t writes = m.writes, attempts = m.agreements;
        assert(execute(&pin, &wrong) == (remaining == 0U ? 0x32U : 0x34U));
        assert(m.writes == writes && m.agreements == attempts);
        uint8_t out[16]; size_t length;
        CtapClientPinRequest retries = {0}; retries.subcommand = 1U;
        assert(ctap_client_pin_execute(&pin, &retries, out, sizeof out, &length, 0U) == 0U);
        CborValue map, count, blocked;
        assert(cbor_read_document(out, length, &map) && cbor_map_uint(&map, 3U, &count) && count.value == remaining);
        assert(cbor_map_uint(&map, 4U, &blocked) && blocked.encoded[0] == (pin.consecutive_failures >= 3U ? 0xF5U : 0xF4U));
        assert(ctap_client_pin_init(&pin, &service, &pin.storage)); /* Simulated true power-on; durable count stays. */
        assert(m.record.retries == remaining && pin.consecutive_failures == 0U);
    }
    assert(m.record.retries == 0U && m.regenerated == 8U);
    CtapClientPinRequest correct = request(4U, (const uint8_t *)"5678", 4U, &m.record);
    assert(execute(&pin, &correct) == 0x32U);
    m.record = (AuthPinRecord){0}; m.record.retries = 8U; ctap_client_pin_reset_state(&pin);
    seed(&pin); assert(m.record.set);
}
/* CTAP 2.3 §§6.5.5.5–6 and 6.5.5.7.2 define the wire errors for
 * decapsulation and verification, including provider failures. */
static void test_client_pin_crypto_error_mapping(void)
{
    const uint8_t commands[] = {3U, 4U, 9U};
    for (size_t c = 0U; c < sizeof commands; ++c) {
        for (unsigned failure = 0U; failure < (commands[c] == 9U ? 3U : 4U); ++failure) {
            Store store = {0}; PinMock m; AuthCredentialService service; CtapClientPin pin;
            setup(&pin, &service, &store, &m);
            if (commands[c] != 3U) seed(&pin);
            CtapClientPinRequest r = request(commands[c], (const uint8_t *)"5678", 4U, &m.record);
            r.permissions = CTAP_PIN_PERMISSION_MC; r.rp_present = true;
            memcpy(r.rp_id, "example.com", 11U); r.rp_length = 11U;
            AuthPinRecord saved = m.record; size_t writes = m.writes, decrypts = m.decrypts;
            uint64_t generation = pin.token_generation;
            m.bad_peer = failure == 0U; m.agreement_fails = failure == 1U;
            m.mac_fails = failure == 2U; m.verify_fails = failure == 3U;
            assert(execute(&pin, &r) == (failure == 3U ? CTAP_STATUS_PIN_AUTH_INVALID : CTAP_STATUS_INVALID_PARAMETER));
            assert(memcmp(&saved, &m.record, sizeof saved) == 0 && m.writes == writes && m.decrypts == decrypts);
            assert(pin.token_generation == generation && !pin.token_active && pin.consecutive_failures == 0U);
        }
    }
}

static void test_change_and_failure_ordering(void)
{
    Store store = {0}; PinMock m; AuthCredentialService service; CtapClientPin pin;
    setup(&pin, &service, &store, &m);
    CtapClientPinRequest r = request(4U, (const uint8_t *)"5678", 4U, NULL);
    assert(execute(&pin, &r) == 0x35U);
    seed(&pin);
    assert(execute(&pin, &r) == 0x31U && m.record.retries == 7U);
    r = request(4U, (const uint8_t *)"5678", 4U, &m.record);
    m.enforce_decrement = true; m.expected_retries = 6U;
    assert(execute(&pin, &r) == 0U && m.record.retries == 8U && pin.consecutive_failures == 0U);
    assert(m.mac_length == 112U && memcmp(m.mac_message, r.new_pin_enc, 80U) == 0 &&
        memcmp(m.mac_message + 80U, r.pin_hash_enc, 32U) == 0 && m.record.hash[0] == '5');
    r = request(4U, (const uint8_t *)"123", 3U, &m.record); m.expected_retries = 7U;
    assert(execute(&pin, &r) == 0x37U && m.record.retries == 8U && m.record.hash[0] == '5');
    for (size_t fail = 1U; fail <= 3U; ++fail) {
        setup(&pin, &service, &store, &m); seed(&pin);
        r = request(4U, (const uint8_t *)"5678", 4U, &m.record);
        m.fail_write = m.writes + fail;
        assert(execute(&pin, &r) == 0x7FU && pin.faulted && m.record.hash[0] == '1');
        assert(m.record.retries == (fail == 1U || fail == 3U ? 8U : 7U));
        assert(execute(&pin, &r) == 0x7FU);
    }
    setup(&pin, &service, &store, &m); seed(&pin); m.regenerate_fails = true;
    r = request(4U, (const uint8_t *)"5678", 4U, NULL);
    assert(execute(&pin, &r) == 0x7FU && pin.faulted && m.record.retries == 7U);
    setup(&pin, &service, &store, &m); m.bad_record = true;
    assert(execute(&pin, &r) == 0x7FU && pin.faulted && m.writes == 0U);
    setup(&pin, &service, &store, &m); m.read_fails = true;
    assert(execute(&pin, &r) == 0x7FU && pin.faulted);
    setup(&pin, &service, &store, &m); m.decrypt_fails = true;
    r = request(3U, (const uint8_t *)"5678", 4U, NULL);
    assert(execute(&pin, &r) == 0x33U && m.writes == 0U);
    setup(&pin, &service, &store, &m); m.bad_peer = true;
    assert(execute(&pin, &r) == 2U && m.writes == 0U);
    setup(&pin, &service, &store, &m); m.mac_fails = true;
    assert(execute(&pin, &r) == CTAP_STATUS_INVALID_PARAMETER && m.writes == 0U);
    setup(&pin, &service, &store, &m); m.hash_fails = true;
    assert(execute(&pin, &r) == 0x7FU && m.writes == 0U);
}
typedef struct {
    Store store; PinMock mock; AuthCredentialService service; CtapClientPin pin;
    CtaphidDevice device; CtaphidCtapBackend backend; bool reset_fails;
} Fixture;
static bool send_report(void *ctx, const uint8_t report[64], uint64_t token)
{ (void)ctx; (void)report; (void)token; return true; }
static bool receive_report(void *ctx, const uint8_t report[64])
{ Fixture *f = ctx; return ctaphid_device_receive_report(&f->device, report, 64U, 0U) == CTAPHID_DEVICE_OK; }
static bool reset_storage(void *ctx)
{
    Fixture *f = ctx;
    if (f->reset_fails) return false;
    f->mock.record = (AuthPinRecord){0}; f->mock.record.retries = 8U;
    return regenerate(&f->mock) == AUTH_OK;
}
static void fixture_init(Fixture *f)
{
    memset(f, 0, sizeof *f); setup(&f->pin, &f->service, &f->store, &f->mock);
    CtapGetInfoProfile profile = {0}; profile.max_message_size = 1024U; profile.user_presence = true;
    assert(ctaphid_ctap_backend_init(&f->backend, &profile));
    assert(!ctaphid_ctap_backend_configure_pin(&f->backend, &f->pin));
    assert(ctaphid_ctap_backend_configure_credentials(&f->backend, &f->service));
    assert(ctaphid_ctap_backend_configure_reset(&f->backend, 0U, reset_storage, f));
    assert(ctaphid_ctap_backend_configure_pin(&f->backend, &f->pin));
    assert(!ctaphid_ctap_backend_configure_pin(&f->backend, &f->pin));
    CtaphidDeviceConfig config = {0}; config.submit_report = send_report;
    config.start_cbor = ctaphid_ctap_backend_start; config.abort_cbor = ctaphid_ctap_backend_abort; config.cbor_context = &f->backend;
    assert(ctaphid_device_init(&f->device, &config) == CTAPHID_DEVICE_OK);
    uint32_t cid; assert(ctaphid_channels_allocate(&f->device.channels, &cid) == CTAPHID_CHANNEL_OK && cid == 1U);
}
static void start_pin(Fixture *f)
{
    CtapClientPinRequest r = request(3U, (const uint8_t *)"1234", 4U, NULL);
    uint8_t bytes[513]; bytes[0] = CTAP_COMMAND_CLIENT_PIN; size_t length = 1U + encode(&r, bytes + 1U);
    assert(ctaphid_send_response(1U, 0x10U, bytes, length, receive_report, f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f->device, 0U) == CTAPHID_DEVICE_OK);
    assert(f->backend.awaiting_pin && f->mock.writes == 0U && f->mock.agreements == 0U);
}
static void test_backend_abort_reset_and_advertising(void)
{
    Fixture f; fixture_init(&f); start_pin(&f);
    uint8_t cancel[64] = {0,0,0,1,0x91};
    assert(ctaphid_device_receive_report(&f.device, cancel, sizeof cancel, 1U) == CTAPHID_DEVICE_OK);
    assert(!f.backend.awaiting_pin && f.backend.pin_request.subcommand == 0U && f.mock.writes == 0U);
    assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 1U) == CTAPHID_DEVICE_OK && !f.mock.record.set);
    fixture_init(&f); start_pin(&f);
    uint8_t init[64] = {0,0,0,1,0x86,0,8};
    f.pin.consecutive_failures = 2U;
    assert(ctaphid_device_receive_report(&f.device, init, sizeof init, 1U) == CTAPHID_DEVICE_OK);
    assert(!f.backend.awaiting_pin && f.mock.writes == 0U && f.pin.consecutive_failures == 2U);
    fixture_init(&f); start_pin(&f);
    assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 0U) == CTAPHID_DEVICE_OK);
    assert(f.mock.record.set && f.mock.writes == 1U && f.backend.response[0] == 0U);
    uint8_t out[256]; size_t length;
    assert(ctap_get_info_encode(&f.backend.profile, out, sizeof out, &length));
    CborValue map, options, ignored;
    assert(cbor_read_document(out, length, &map) && cbor_map_uint(&map, 4U, &options));
    assert(cbor_map_text(&options, "clientPin", &ignored) && ignored.encoded[0] == 0xF4U);
    assert(cbor_map_text(&options, "pinUvAuthToken", &ignored) && ignored.encoded[0] == 0xF5U);
    assert(!cbor_map_text(&options, "uv", &ignored));
    for (unsigned failure = 0U; failure < 2U; ++failure) {
        fixture_init(&f); seed(&f.pin); f.pin.consecutive_failures = 3U; f.pin.faulted = true;
        f.reset_fails = failure != 0U;
        const uint8_t command[] = {CTAP_COMMAND_RESET};
        assert(ctaphid_send_response(1U, 0x10U, command, sizeof command, receive_report, &f) == CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, true, 1U));
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 1U) == CTAPHID_DEVICE_OK);
        assert(f.mock.record.set == (failure != 0U) && f.pin.faulted == (failure != 0U));
        assert(f.pin.consecutive_failures == (failure ? 3U : 0U));
    }
}

static CtapClientPinRequest token_request(const AuthPinRecord *record, uint8_t permissions)
{
    CtapClientPinRequest r = request(9U, (const uint8_t *)"", 0U, record);
    r.permissions = permissions; r.rp_present = true; r.rp_length = 11U;
    memcpy(r.rp_id, "example.com", r.rp_length); return r;
}
static void issue(Fixture *f, uint8_t permissions, uint32_t now)
{
    CtapClientPinRequest r = token_request(&f->mock.record, permissions);
    uint8_t out[80]; size_t length;
    assert(ctap_client_pin_execute(&f->pin, &r, out, sizeof out, &length, now) == 0U);
    CborValue map, encrypted;
    assert(cbor_read_document(out, length, &map) && cbor_map_uint(&map, 2U, &encrypted) && encrypted.value == 48U);
    assert(f->pin.token_active && f->pin.permissions == permissions && f->mock.record.retries == 8U);
}
/* §6.5.5.7.2: unavailable permissions fail before PIN attempts; undefined
 * bits are ignored. Exercise the CBOR path, not just prepared C requests. */
static void test_token_permission_combinations(void)
{
    for (unsigned cm = 0U; cm < 2U; ++cm) {
        for (unsigned rp = 0U; rp < 2U; ++rp) {
            for (unsigned bits = 0U; bits < 256U; ++bits) {
                Fixture f; fixture_init(&f); seed(&f.pin); issue(&f, 1U, 0U);
                f.pin.credential_management = cm != 0U;
                CtapClientPinRequest r = token_request(&f.mock.record, (uint8_t)bits), parsed;
                r.rp_present = rp != 0U;
                uint8_t input[512], output[80]; memset(output, 0xEE, sizeof output);
                size_t n = encode(&r, input), length = 777U, writes = f.mock.writes;
                uint64_t generation = f.pin.token_generation;
                uint8_t expected = bits == 0U ? CTAP_STATUS_INVALID_PARAMETER :
                    ((bits & 3U) && !rp) ? CTAP_STATUS_MISSING_PARAMETER :
                    (bits & 0x78U) ? CTAP_STATUS_UNAUTHORIZED_PERMISSION :
                    ((bits & 4U) && !cm) ? CTAP_STATUS_UNAUTHORIZED_PERMISSION : CTAP_STATUS_OK;
                uint8_t status = ctap_client_pin_prepare(input, n, &parsed);
                if (status == CTAP_STATUS_OK)
                    status = ctap_client_pin_execute(&f.pin, &parsed, output, sizeof output, &length, 1U);
                assert(status == expected);
                if (status != CTAP_STATUS_OK) {
                    assert(f.mock.writes == writes && generation == f.pin.token_generation);
                    assert(f.pin.token_active && f.pin.permissions == 1U && output[0] == 0xEEU && length == 777U);
                } else {
                    assert(f.pin.permissions == (bits & 7U) && f.pin.token_rp_bound == (rp != 0U));
                    assert(f.pin.token_generation == generation + 1U && !f.pin.token_used && f.pin.issued_at_ms == 1U);
                    assert(f.mock.record.retries == 8U && length != 777U);
                }
            }
        }
    }
}

static size_t make_request(uint8_t out[512], bool auth, uint8_t policy, const uint8_t *excluded)
{
    CborWriter w; cbor_writer_init(&w, out, 512U); uint8_t hash_bytes[32] = {0x42}, mac_bytes[32]; memset(mac_bytes, 0x3C, 32U);
    assert(cbor_write_map(&w, 4U + (auth ? 2U : 0U) + (policy ? 1U : 0U) + (excluded ? 1U : 0U)) &&
        cbor_write_uint(&w, 1U) && cbor_write_bytes(&w, hash_bytes, 32U) &&
        cbor_write_uint(&w, 2U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "id") && cbor_write_text(&w, "example.com") &&
        cbor_write_uint(&w, 3U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "id") && cbor_write_bytes(&w, NULL, 0U) &&
        cbor_write_uint(&w, 4U) && cbor_write_array(&w, 1U) && cbor_write_map(&w, 2U) &&
        cbor_write_text(&w, "alg") && cbor_write_int(&w, -7) && cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key"));
    if (excluded) assert(cbor_write_uint(&w, 5U) && cbor_write_array(&w, 1U) && cbor_write_map(&w, 2U) &&
        cbor_write_text(&w, "id") && cbor_write_bytes(&w, excluded, 32U) &&
        cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key"));
    if (policy) assert(cbor_write_uint(&w, 6U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "credProtect") && cbor_write_uint(&w, policy));
    if (auth) assert(cbor_write_uint(&w, 8U) && cbor_write_bytes(&w, mac_bytes, 32U) && cbor_write_uint(&w, 9U) && cbor_write_uint(&w, 2U));
    return w.length;
}
static size_t assertion_request_extended(uint8_t out[512], const uint8_t id[32], bool auth, bool up, bool malformed_tail, bool bad_extension)
{
    CborWriter w; cbor_writer_init(&w, out, 512U); uint8_t hash_bytes[32] = {0x42}, mac_bytes[32]; memset(mac_bytes, 0x3C, 32U);
    assert(cbor_write_map(&w, (auth ? 6U : 4U) + (bad_extension ? 1U : 0U)) && cbor_write_uint(&w, 1U) && cbor_write_text(&w, "example.com") &&
        cbor_write_uint(&w, 2U) && cbor_write_bytes(&w, hash_bytes, 32U) && cbor_write_uint(&w, 3U) &&
        cbor_write_array(&w, malformed_tail ? 2U : 1U) && cbor_write_map(&w, 2U) &&
        cbor_write_text(&w, "id") && cbor_write_bytes(&w, id, 32U) && cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key"));
    if (malformed_tail) assert(cbor_write_map(&w, 2U) && cbor_write_text(&w, "id") && cbor_write_uint(&w, 1U) &&
        cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key"));
    if (bad_extension) assert(cbor_write_uint(&w, 4U) && cbor_write_map(&w, 1U) &&
        cbor_write_text(&w, "hmac-secret") && cbor_write_map(&w, 0U));
    assert(cbor_write_uint(&w, 5U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "up") && cbor_write_bool(&w, up));
    if (auth) assert(cbor_write_uint(&w, 6U) && cbor_write_bytes(&w, mac_bytes, 32U) && cbor_write_uint(&w, 7U) && cbor_write_uint(&w, 2U));
    return w.length;
}
static size_t assertion_request(uint8_t out[512], const uint8_t id[32], bool auth, bool up, bool malformed_tail)
{ return assertion_request_extended(out, id, auth, up, malformed_tail, false); }

static void test_assertion_extension_error_precedence(void)
{
    Fixture f; fixture_init(&f); seed(&f.pin);
    uint8_t input[512], output[512], aaguid[16] = {0}; size_t length;
    CtapMakeCredential mc; CtapMakeCredentialWorkspace mc_workspace = {0};
    CtapGetAssertion ga; CtapGetAssertionWorkspace ga_workspace = {0};
    size_t n = make_request(input, false, 1U, NULL);
    assert(ctap_make_credential_prepare_with_pin(&f.service, &mc_workspace, &f.pin, 0U, input, n, &mc) == 0U);
    assert(ctap_make_credential_finish_at(&f.service, &mc_workspace, &mc, aaguid, output, sizeof output, &length, 0U) == 0U);
    for (unsigned mode = 0U; mode < 4U; ++mode) {
        issue(&f, mode == 0U ? CTAP_PIN_PERMISSION_MC : CTAP_PIN_PERMISSION_GA, 0U);
        uint8_t id[32]; memcpy(id, f.store.record.credential_id, sizeof id);
        if (mode == 1U) id[0] ^= 1U;
        n = assertion_request_extended(input, id, true, mode != 3U, false, true);
        memset(output, 0xEE, sizeof output); length = 999U;
        uint8_t status = ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 0U, input, n, &ga);
        if (mode < 2U) assert(status == (mode == 0U ? CTAP_STATUS_PIN_AUTH_INVALID : CTAP_STATUS_NO_CREDENTIALS));
        else {
            assert(status == CTAP_STATUS_OK);
            assert(ctap_get_assertion_finish_at(&f.service, &ga_workspace, &ga, output, sizeof output, &length, 1U) == CTAP_STATUS_MISSING_PARAMETER);
            assert(f.pin.token_active == (mode == 3U));
        }
        assert(f.store.record.signature_count == 0U && f.store.signatures == 1U);
        assert(length == 999U && output[0] == 0xEEU);
    }
}

/* §§6.1.2/6.2.2: token verification errors must precede credential effects,
 * both during preparation and when rechecking after the presence wait. */
static void test_registration_extension_error_precedence(void)
{
    Fixture f; fixture_init(&f); seed(&f.pin);
    uint8_t input[512], output[512], aaguid[16] = {0}; size_t length;
    CtapMakeCredential mc; CtapMakeCredentialWorkspace workspace = {0};
    size_t n = make_request(input, false, 1U, NULL);
    assert(ctap_make_credential_prepare_with_pin(&f.service, &workspace, &f.pin, 0U, input, n, &mc) == 0U);
    assert(ctap_make_credential_finish_at(&f.service, &workspace, &mc, aaguid, output, sizeof output, &length, 0U) == 0U);
    for (unsigned mode = 0U; mode < 3U; ++mode) {
        issue(&f, mode == 0U ? CTAP_PIN_PERMISSION_GA : CTAP_PIN_PERMISSION_MC, 0U);
        n = make_request(input, true, 4U, mode < 2U ? f.store.record.credential_id : NULL);
        memset(output, 0xEE, sizeof output); length = 999U;
        uint8_t status = ctap_make_credential_prepare_with_pin(&f.service, &workspace, &f.pin, 0U, input, n, &mc);
        if (mode == 0U) assert(status == CTAP_STATUS_PIN_AUTH_INVALID && !f.pin.token_used);
        else {
            assert(status == CTAP_STATUS_OK);
            assert(ctap_make_credential_finish_at(&f.service, &workspace, &mc, aaguid, output, sizeof output, &length, 1U) ==
                (mode == 1U ? CTAP_STATUS_CREDENTIAL_EXCLUDED : CTAP_STATUS_INVALID_PARAMETER));
            assert(!f.pin.token_active);
        }
        assert(f.store.generated == 1U && f.store.signatures == 1U && length == 999U && output[0] == 0xEEU);
    }
}

static void test_credential_token_verification_errors(void)
{
    for (unsigned assertion = 0U; assertion < 2U; ++assertion) {
        Fixture f; fixture_init(&f); seed(&f.pin);
        uint8_t input[512], output[512], aaguid[16] = {0}; size_t length = 777U;
        CtapMakeCredential mc = {0}; CtapMakeCredentialWorkspace mc_workspace = {0};
        CtapGetAssertion ga = {0}; CtapGetAssertionWorkspace ga_workspace = {0};
        size_t n = make_request(input, false, 1U, NULL);
        if (assertion) {
            assert(ctap_make_credential_prepare_with_pin(&f.service, &mc_workspace, &f.pin, 0U, input, n, &mc) == 0U);
            assert(ctap_make_credential_finish_at(&f.service, &mc_workspace, &mc, aaguid, output, sizeof output, &length, 0U) == 0U);
            n = assertion_request(input, f.store.record.credential_id, true, true, false);
        } else n = make_request(input, true, 1U, NULL);
        issue(&f, assertion ? CTAP_PIN_PERMISSION_GA : CTAP_PIN_PERMISSION_MC, 0U);
        size_t generated = f.store.generated, signatures = f.store.signatures;
        uint32_t counter = f.store.record.signature_count;
        memset(output, 0xEE, sizeof output); length = 777U;
        for (unsigned finishing = 0U; finishing < 2U; ++finishing) {
            f.mock.mac_fails = finishing == 0U;
            uint8_t status = assertion ?
                ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 0U, input, n, &ga) :
                ctap_make_credential_prepare_with_pin(&f.service, &mc_workspace, &f.pin, 0U, input, n, &mc);
            if (finishing) {
                assert(status == CTAP_STATUS_OK);
                f.mock.mac_fails = true;
                status = assertion ?
                    ctap_get_assertion_finish_at(&f.service, &ga_workspace, &ga, output, sizeof output, &length, 1U) :
                    ctap_make_credential_finish_at(&f.service, &mc_workspace, &mc, aaguid, output, sizeof output, &length, 1U);
            }
            assert(status == CTAP_STATUS_PIN_AUTH_INVALID);
            assert(f.store.generated == generated && f.store.signatures == signatures && f.store.record.signature_count == counter);
            assert(output[0] == 0xEEU && length == 777U && f.pin.token_active);
            assert(f.pin.token_used == (finishing != 0U));
        }
    }
}

static void test_tokens_policy_and_provider_failures(void)
{
    Fixture f; fixture_init(&f); seed(&f.pin); issue(&f, 1U, 0U);
    uint8_t input[512], output[512], aaguid[16] = {0}; size_t length, n = make_request(input, true, 3U, NULL);
    CtapMakeCredentialWorkspace workspace = {0}; CtapMakeCredential mc;
    assert(ctap_make_credential_prepare_with_pin(&f.service, &workspace, &f.pin, 0U, input, n, &mc) == 0U && mc.user_verified);
    assert(ctap_make_credential_finish_at(&f.service, &workspace, &mc, aaguid, output, sizeof output, &length, 1U) == 0U);
    CborValue map, data, extension, policy;
    assert(cbor_read_document(output, length, &map) && cbor_map_uint(&map, 2U, &data) && data.data[32] == 0xC5U);
    assert(cbor_read_document(data.data + 164U, (size_t)data.value - 164U, &extension) &&
        cbor_map_text(&extension, "credProtect", &policy) && policy.value == 3U);
    assert(f.store.record.cred_protect == 3U && f.store.signatures == 1U && !f.pin.token_active);
    assert(ctap_make_credential_prepare_with_pin(&f.service, &workspace, &f.pin, 2U, input, n, &mc) == 0x33U);
    CtapGetAssertionWorkspace ga_workspace = {0}; CtapGetAssertion ga;
    n = assertion_request(input, f.store.record.credential_id, false, true, false);
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 0U, input, n, &ga) == 0x2EU);
    issue(&f, 1U, 0U); n = assertion_request(input, f.store.record.credential_id, true, true, false);
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 0U, input, n, &ga) == 0x33U);
    issue(&f, 2U, 0U);
    n = assertion_request(input, f.store.record.credential_id, true, false, true);
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 0U, input, n, &ga) == 0x11U && !f.pin.token_used);
    n = assertion_request(input, f.store.record.credential_id, true, false, false);
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 0U, input, n, &ga) == 0U && ga.user_verified);
    assert(ctap_get_assertion_finish_at(&f.service, &ga_workspace, &ga, output, sizeof output, &length, 1U) == 0U && f.pin.token_active);
    assert(cbor_read_document(output, length, &map) && cbor_map_uint(&map, 2U, &data) && data.data[32] == 4U);
    issue(&f, 2U, 2U); /* A previously prepared request cannot switch to a new generation. */
    assert(ctap_get_assertion_finish_at(&f.service, &ga_workspace, &ga, output, sizeof output, &length, 2U) == 0x33U);
    n = assertion_request(input, f.store.record.credential_id, true, true, false);
    assert(ctap_get_assertion_prepare_with_pin(&f.service, &ga_workspace, &f.pin, 2U, input, n, &ga) == 0U);
    f.store.counter_fails = true;
    assert(ctap_get_assertion_finish_at(&f.service, &ga_workspace, &ga, output, sizeof output, &length, 3U) == 0x7FU && !f.pin.token_active);
    f.store.counter_fails = false; assert(f.store.record.signature_count == 1U && f.store.signatures == 2U);
    n = make_request(input, false, 1U, f.store.record.credential_id);
    assert(ctap_make_credential_prepare_with_pin(&f.service, &workspace, &f.pin, 0U, input, n, &mc) == 0U && !mc.credential_excluded);
    issue(&f, 1U, 0U); n = make_request(input, true, 1U, f.store.record.credential_id);
    assert(ctap_make_credential_prepare_with_pin(&f.service, &workspace, &f.pin, 0U, input, n, &mc) == 0U && mc.credential_excluded);
    for (unsigned failure = 0U; failure < 3U; ++failure) {
        fixture_init(&f); seed(&f.pin); issue(&f, 1U, 0U);
        CtapClientPinRequest r = token_request(&f.mock.record, 1U); size_t unchanged = 777U;
        f.mock.random_fails = failure == 0U; f.mock.encrypt_fails = failure == 1U;
        assert(ctap_client_pin_execute(&f.pin, &r, output, failure == 2U ? 1U : sizeof output, &unchanged, 1U) == 0x7FU);
        assert(!f.pin.token_active && unchanged == 777U && f.mock.record.retries == 8U);
    }
}
static void test_token_time_wrap_and_waiting_abort(void)
{
    Fixture f; fixture_init(&f); seed(&f.pin);
    uint32_t start = UINT32_MAX - 99U; issue(&f, 1U, start);
    ctap_client_pin_poll(&f.pin, start + 29999U); assert(f.pin.token_active);
    ctap_client_pin_poll(&f.pin, start + 30000U); assert(!f.pin.token_active);
    issue(&f, 1U, start);
    CtapPinAuth auth = {.present = true}; memset(auth.mac, 0x3C, sizeof auth.mac);
    uint8_t rp_hash[32], client_hash[32] = {0};
    assert(pin_hash(&f.mock, (const uint8_t *)"example.com", 11U, rp_hash) == AUTH_OK);
    auth.mac[0] ^= 1U;
    assert(ctap_client_pin_authorize(&f.pin, &auth, rp_hash, client_hash, 1U, start + 29999U, true) == CTAP_STATUS_PIN_AUTH_INVALID);
    assert(!f.pin.token_used);
    auth.mac[0] ^= 1U;
    assert(ctap_client_pin_authorize(&f.pin, &auth, rp_hash, client_hash, 1U, start + 29999U, true) == CTAP_STATUS_OK);
    ctap_client_pin_poll(&f.pin, start + 599999U); assert(f.pin.token_active);
    ctap_client_pin_poll(&f.pin, start + 600000U); assert(!f.pin.token_active);
    for (unsigned mode = 0U; mode < 3U; ++mode) {
        fixture_init(&f); seed(&f.pin); issue(&f, 1U, 0U);
        uint8_t input[513]; input[0] = CTAP_COMMAND_MAKE_CREDENTIAL;
        size_t n = 1U + make_request(input + 1U, true, 3U, NULL);
        assert(ctaphid_send_response(1U, 0x10U, input, n, receive_report, &f) == CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK);
        /* No token usage/crypto before main-loop polling or after stale ownership. */
        assert(f.backend.awaiting_credential_prepare && !f.pin.token_used && f.store.generated == 0U);
        if (mode == 0U) {
            uint8_t cancel[64] = {0,0,0,1,0x91};
            assert(ctaphid_device_receive_report(&f.device, cancel, sizeof cancel, 1U) == CTAPHID_DEVICE_OK);
            assert(!f.backend.awaiting_credential_prepare && f.pin.token_active && !f.pin.token_used);
            assert(f.backend.credential_request_length == 0U && f.backend.credential_request[0] == 0U);
        } else if (mode == 1U) {
            assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 30000U) == CTAPHID_DEVICE_OK);
            assert(f.backend.response[0] == 0x33U && f.store.generated == 0U); /* Initial deadline at actual poll clock. */
        } else {
            f.backend.presence_timeout_ms = 700000U;
            assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 0U) == CTAPHID_DEVICE_OK && f.pin.token_used);
            assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, true, 600000U));
            assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 600000U) == CTAPHID_DEVICE_OK);
            assert(f.backend.response[0] == 0x33U && f.store.generated == 0U);
        }
    }
    for (unsigned set = 0U; set < 2U; ++set) {
        fixture_init(&f); if (set) seed(&f.pin);
        const uint8_t probe[] = {CTAP_COMMAND_MAKE_CREDENTIAL, 0xA1, 8U, 0x40};
        assert(ctaphid_send_response(1U, 0x10U, probe, sizeof probe, receive_report, &f) == CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(f.backend.awaiting_presence && f.store.generated == 0U);
        assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, true, 1U));
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 1U) == CTAPHID_DEVICE_OK);
        assert(f.backend.response[0] == (set ? 0x31U : 0x35U) && f.store.generated == 0U);
    }
}
static void test_get_info_reads_pin_state_and_fails_closed(void)
{
    for (unsigned state = 0U; state < 3U; ++state) {
        Fixture f; fixture_init(&f); if (state != 0U) seed(&f.pin);
        f.mock.bad_record = state == 2U;
        const uint8_t info[] = {CTAP_COMMAND_GET_INFO};
        assert(ctaphid_send_response(1U, 0x10U, info, sizeof info, receive_report, &f) == CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 0U) == CTAPHID_DEVICE_OK);
        assert(f.backend.response[0] == (state == 2U ? 0x7FU : 0U));
        if (state == 2U) { assert(f.pin.faulted && !f.pin.token_active); continue; }
        assert(f.backend.profile.pin_set == (state == 1U));
        uint8_t out[256]; size_t length; CborValue map, options, value;
        assert(ctap_get_info_encode(&f.backend.profile, out, sizeof out, &length));
        assert(cbor_read_document(out, length, &map) && cbor_map_uint(&map, 4U, &options));
        assert(cbor_map_text(&options, "clientPin", &value) && value.encoded[0] == (state == 1U ? 0xF5U : 0xF4U));
        assert(cbor_map_text(&options, "pinUvAuthToken", &value) && value.encoded[0] == 0xF5U);
        assert(!cbor_map_text(&options, "uv", &value));
    }
}
int main(void)
{
    test_validation_and_pin_policy(); test_retries_and_power_cycle(); test_change_and_failure_ordering();
    test_client_pin_crypto_error_mapping();
    test_backend_abort_reset_and_advertising();
    test_assertion_extension_error_precedence();
    test_registration_extension_error_precedence();
    test_credential_token_verification_errors();
    test_token_permission_combinations();
    test_tokens_policy_and_provider_failures(); test_token_time_wrap_and_waiting_abort();
    test_get_info_reads_pin_state_and_fails_closed();
    puts("ClientPIN tests passed (tokens, permissions, credProtect, UV, expiry/wrap, failures, CANCEL/INIT and Reset).");
    return 0;
}
