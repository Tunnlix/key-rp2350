#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap_client_pin.h"
#include "ctap/cbor_writer.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"
#include "auth_test_provider.h"

/* Transparent primitives test policy and persistence ordering. Genuine
 * protocol 2 cryptography is verified separately by the Python client tests. */
typedef struct {
    AuthPinRecord record;
    size_t reads, writes, decrypts, agreements, regenerated;
    size_t fail_write;
    bool read_fails, bad_record, bad_peer, agreement_fails, mac_fails;
    bool decrypt_fails, regenerate_fails, hash_fails, enforce_decrement;
    uint8_t expected_retries, mac_message[112];
    size_t mac_length;
} PinMock;
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
    if (m->mac_fails) return AUTH_CRYPTO_ERROR;
    if (length >= 80U) { assert(length <= sizeof m->mac_message); memcpy(m->mac_message, data, length); m->mac_length = length; }
    memset(out, 0x3C, 32U); return AUTH_OK;
}
static AuthStatus aes(void *ctx, bool encrypt, const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *in, size_t length, uint8_t *out)
{
    PinMock *m = ctx; (void)key; (void)iv; assert(!encrypt && (length == 16U || length == 64U)); ++m->decrypts;
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
    service->crypto.context = m; service->crypto.sha256 = pin_hash;
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
    uint8_t status = ctap_client_pin_execute(pin, r, output, sizeof output, &length);
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
    assert(cbor_write_map(&w, r->subcommand == 4U ? 6U : 5U) && cbor_write_uint(&w, 1U) && cbor_write_uint(&w, 2U) &&
        cbor_write_uint(&w, 2U) && cbor_write_uint(&w, r->subcommand) && cbor_write_uint(&w, 3U) && cbor_write_map(&w, 5U) &&
        cbor_write_int(&w, 1) && cbor_write_int(&w, 2) && cbor_write_int(&w, 3) && cbor_write_int(&w, -25) &&
        cbor_write_int(&w, -1) && cbor_write_int(&w, 1) && cbor_write_int(&w, -2) && cbor_write_bytes(&w, r->peer + 1U, 32U) &&
        cbor_write_int(&w, -3) && cbor_write_bytes(&w, r->peer + 33U, 32U) &&
        cbor_write_uint(&w, 4U) && cbor_write_bytes(&w, r->auth, r->auth_length) &&
        cbor_write_uint(&w, 5U) && cbor_write_bytes(&w, r->new_pin_enc, 80U));
    if (r->subcommand == 4U) assert(cbor_write_uint(&w, 6U) && cbor_write_bytes(&w, r->pin_hash_enc, 32U));
    return w.length;
}
static void test_validation_and_pin_policy(void)
{
    const struct { uint8_t bytes[8]; size_t size; uint8_t status; } cases[] = {
        {{0xA0},1U,0x14}, {{0xA1,2,0x61,'3'},4U,0x11}, {{0xA1,2,2},3U,0x14},
        {{0xA2,1,1,2,2},5U,2}, {{0xA2,1,2,2,3},5U,0x14}, {{0xA1,2,9},3U,0x3E},
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
        assert(ctap_client_pin_execute(&pin, &retries, out, sizeof out, &length) == 0U);
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
    assert(execute(&pin, &r) == 0x7FU && m.writes == 0U);
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
    assert(!cbor_map_text(&options, "clientPin", &ignored) && !cbor_map_text(&options, "pinUvAuthToken", &ignored) &&
        !cbor_map_text(&options, "uv", &ignored));
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
int main(void)
{
    test_validation_and_pin_policy(); test_retries_and_power_cycle(); test_change_and_failure_ordering();
    test_backend_abort_reset_and_advertising();
    puts("ClientPIN tests passed (PIN policy, durable retries, blocking, failures, CANCEL/INIT and Reset).");
    return 0;
}
