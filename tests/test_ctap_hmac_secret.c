#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap_hmac_secret.h"
#include "ctap/ctap_make_credential.h"
#include "ctap/ctap_get_assertion.h"
#include "ctap/cbor_writer.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"
#include "auth_test_provider.h"

/* Deterministic primitive mocks verify orchestration, not cryptographic math.
 * Validate the injected provider's real ECDH/HMAC/AES separately on the target. */
typedef struct {
    bool bad_peer, agreement_fails, hmac_fails, decrypt_fails, encrypt_fails, credential_fails, legacy;
    size_t agreements, macs, decrypts, encrypts, evaluations;
    bool evaluated_with_uv;
} SecretMock;
static AuthStatus agreement_public(void *context, uint8_t key[65])
{ (void)context; memset(key, 1, 65U); key[0] = 4U; return AUTH_OK; }
static AuthStatus ecdh(void *context, const uint8_t key[65], uint8_t z[32])
{
    SecretMock *mock = context; ++mock->agreements; assert(key[0] == 4U);
    if (mock->bad_peer) return AUTH_BAD_DATA;
    if (mock->agreement_fails) return AUTH_IO_ERROR;
    memset(z, 0x55, 32U); return AUTH_OK;
}
static AuthStatus hmac(void *context, const uint8_t *key, size_t key_length,
    const uint8_t *input, size_t length, uint8_t output[32])
{
    SecretMock *mock = context; ++mock->macs;
    assert(key_length == 32U);
    switch (mock->macs) {
    case 1U: assert(memcmp(key, (uint8_t[32]){0}, 32U) == 0 && length == 32U && input[0] == 0x55U); break;
    case 2U: assert(key[0] == 0x3CU && length == 15U && memcmp(input, "CTAP2 HMAC key\x01", 15U) == 0); break;
    case 3U: assert(key[0] == 0x3CU && length == 14U && memcmp(input, "CTAP2 AES key\x01", 14U) == 0); break;
    case 4U: assert(key[0] == 0x3CU && (length == 48U || length == 80U)); break;
    default: assert(false);
    }
    if (mock->hmac_fails) return AUTH_CRYPTO_ERROR;
    memset(output, 0x3C, 32U); return AUTH_OK;
}
static AuthStatus aes(void *context, bool encrypt, const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *input, size_t length, uint8_t *output)
{
    SecretMock *mock = context;
    assert(key[0] == 0x3CU && (length == 32U || length == 64U));
    if (encrypt) { ++mock->encrypts; assert(iv[0] == 0xA5U); if (mock->encrypt_fails) return AUTH_CRYPTO_ERROR; }
    else { ++mock->decrypts; if (mock->decrypt_fails) return AUTH_CRYPTO_ERROR; }
    memcpy(output, input, length); return AUTH_OK; /* Transparent mock cipher. */
}
static AuthStatus secret_available(void *context, const AuthKeyHandle *key, bool *available)
{ SecretMock *mock = context; assert(auth_key_handle_valid(key)); *available = !mock->legacy; return AUTH_OK; }
static AuthStatus credential_hmac(void *context, const AuthKeyHandle *key, bool uv,
    const uint8_t salt[32], uint8_t output[32])
{
    SecretMock *mock = context; ++mock->evaluations; assert(auth_key_handle_valid(key)); mock->evaluated_with_uv = uv;
    if (mock->legacy) return AUTH_NOT_FOUND;
    if (mock->credential_fails) return AUTH_IO_ERROR;
    for (size_t i = 0U; i < 32U; ++i) output[i] = salt[i] ^ (uv ? 0x22U : 0x11U);
    return AUTH_OK;
}
static void configure(AuthCredentialService *service, Store *store, SecretMock *mock)
{
    service_init(service, store);
    AuthSecretCrypto crypto = {mock, agreement_public, ecdh, hmac, aes, secret_available, credential_hmac, NULL};
    AuthSecretCrypto invalid = crypto; invalid.ecdh = NULL;
    assert(!auth_credentials_configure_secrets(service, &invalid));
    assert(auth_credentials_configure_secrets(service, &crypto));
    assert(!auth_credentials_configure_secrets(service, &crypto));
}
static AuthCredential seed(AuthCredentialService *service)
{
    uint8_t rp[32], key[65]; memset(rp, 0x42, 32U);
    AuthCredential credential;
    assert(auth_credentials_create(service, rp, NULL, 0U, false, &credential, key) == AUTH_OK);
    return credential;
}
static CtapHmacSecret input(bool two)
{
    CtapHmacSecret request = {0}; request.requested = true; request.peer_public[0] = 4U;
    request.salt_enc_length = two ? 80U : 48U; request.salt_auth_length = 32U;
    memset(request.salt_auth, 0x3C, 32U);
    memset(request.salt_enc + 16U, 1, 32U);
    if (two) memset(request.salt_enc + 48U, 2, 32U);
    return request;
}
static void test_protocol_two_kdf_and_uv_separation(void)
{
    Store store = {0}; SecretMock mock = {0}; AuthCredentialService service;
    configure(&service, &store, &mock); AuthCredential credential = seed(&service);
    CtapHmacSecret request = input(true); uint8_t output[80]; size_t length;
    assert(ctap_hmac_secret_evaluate(&service, &credential, &request, false, output, &length) == 0U);
    assert(length == 80U && mock.macs == 4U && mock.evaluations == 2U && !mock.evaluated_with_uv);
    assert(output[0] == 0xA5U && output[16] == (1U ^ 0x11U) && output[48] == (2U ^ 0x11U));
    mock = (SecretMock){0}; request = input(false);
    assert(ctap_hmac_secret_evaluate(&service, &credential, &request, true, output, &length) == 0U);
    assert(length == 48U && mock.evaluated_with_uv && output[16] == (1U ^ 0x22U));
}
static void test_failure_output_and_legacy_handling(void)
{
    Store store = {0}; SecretMock mock = {0}; AuthCredentialService service;
    configure(&service, &store, &mock); AuthCredential credential = seed(&service);
    CtapHmacSecret request = input(false);
    for (unsigned failure = 0U; failure < 7U; ++failure) {
        mock = (SecretMock){0}; request = input(false);
        uint8_t expected = 0x7FU;
        switch (failure) {
        case 0U: request.salt_auth[0] ^= 1U; expected = 0x33U; break;
        case 1U: mock.bad_peer = true; expected = 2U; break;
        case 2U: mock.agreement_fails = true; break;
        case 3U: mock.hmac_fails = true; break;
        case 4U: mock.decrypt_fails = true; expected = 2U; break;
        case 5U: mock.credential_fails = true; break;
        case 6U: mock.encrypt_fails = true; break;
        }
        uint8_t output[80]; memset(output, 0xEE, sizeof output); size_t length = 999U;
        assert(ctap_hmac_secret_evaluate(&service, &credential, &request, false, output, &length) == expected);
        assert(output[0] == 0xEEU && length == 999U);
        if (failure < 4U) assert(mock.decrypts == 0U && mock.evaluations == 0U);
    }
    mock = (SecretMock){0}; mock.legacy = true; request = input(false);
    uint8_t output[80]; memset(output, 0xEE, sizeof output); size_t length = 999U;
    assert(ctap_hmac_secret_evaluate(&service, &credential, &request, false, output, &length) == 0U);
    assert(length == 0U && mock.encrypts == 0U && output[0] == 0xEEU);
}
static size_t assertion_request(uint8_t bytes[512], bool up)
{
    CtapHmacSecret extension = input(true);
    uint8_t digest[32] = {0}, id[32], coord[32]; memset(id, 0xA5, 32U); memset(coord, 1, 32U);
    CborWriter w; cbor_writer_init(&w, bytes, 512U);
    assert(cbor_write_map(&w, 5U) && cbor_write_uint(&w, 1U) && cbor_write_text(&w, "example.com") &&
        cbor_write_uint(&w, 2U) && cbor_write_bytes(&w, digest, 32U) &&
        cbor_write_uint(&w, 3U) && cbor_write_array(&w, 1U) && cbor_write_map(&w, 2U) &&
        cbor_write_text(&w, "id") && cbor_write_bytes(&w, id, 32U) &&
        cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key") &&
        cbor_write_uint(&w, 4U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "hmac-secret") && cbor_write_map(&w, 4U) &&
        cbor_write_uint(&w, 1U) && cbor_write_map(&w, 5U) &&
        cbor_write_int(&w, 1) && cbor_write_int(&w, 2) && cbor_write_int(&w, 3) && cbor_write_int(&w, -25) &&
        cbor_write_int(&w, -1) && cbor_write_int(&w, 1) &&
        cbor_write_int(&w, -2) && cbor_write_bytes(&w, coord, 32U) &&
        cbor_write_int(&w, -3) && cbor_write_bytes(&w, coord, 32U) &&
        cbor_write_uint(&w, 2U) && cbor_write_bytes(&w, extension.salt_enc, 80U) &&
        cbor_write_uint(&w, 3U) && cbor_write_bytes(&w, extension.salt_auth, 32U) &&
        cbor_write_uint(&w, 4U) && cbor_write_uint(&w, 2U) &&
        cbor_write_uint(&w, 5U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "up") && cbor_write_bool(&w, up));
    return w.length;
}
static void test_assertion_extension_is_signed_and_bad_mac_does_not_increment(void)
{
    Store store = {0}; SecretMock mock = {0}; AuthCredentialService service;
    configure(&service, &store, &mock); (void)seed(&service);
    uint8_t request[512], response[288]; size_t length;
    size_t request_length = assertion_request(request, true); CtapGetAssertionWorkspace ga_workspace = {0}; CtapGetAssertion prepared;
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, request, request_length, &prepared) == 0U);
    assert(mock.agreements == 0U && mock.evaluations == 0U && store.signatures == 0U);
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, response, sizeof response, &length) == 0U);
    { const unsigned char *bytes = (const unsigned char *)&ga_workspace.scratch;
      assert(!ga_workspace.busy);
      for (size_t i = 0U; i < sizeof ga_workspace.scratch; ++i) assert(bytes[i] == 0U); }
    assert(store.counter_at_sign == 1U && store.hashed_data[32] == 0x81U && store.hashed_length == 164U);
    CborValue map, data, extensions, encrypted;
    assert(cbor_read_document(response, length, &map) && cbor_map_uint(&map, 2U, &data) && data.value == 132U);
    assert(cbor_read_document(data.data + 37U, (size_t)data.value - 37U, &extensions));
    assert(cbor_map_text(&extensions, "hmac-secret", &encrypted) && encrypted.value == 80U);
    mock = (SecretMock){0}; prepared.hmac_secret.salt_auth[0] ^= 1U;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, response, sizeof response, &length) == 0x33U);
    { const unsigned char *bytes = (const unsigned char *)&ga_workspace.scratch;
      assert(!ga_workspace.busy);
      for (size_t i = 0U; i < sizeof ga_workspace.scratch; ++i) assert(bytes[i] == 0U); }
    assert(store.record.signature_count == 1U && store.signatures == 1U);
    request_length = assertion_request(request, false);
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, request, request_length, &prepared) == 0x2BU);
}
static void test_registration_extension_output_and_availability(void)
{
    for (unsigned legacy = 0U; legacy < 2U; ++legacy) {
        Store store = {0}; SecretMock mock = {0}; AuthCredentialService service;
        configure(&service, &store, &mock); mock.legacy = legacy != 0U;
        CtapMakeCredential prepared = {0}; prepared.hmac_secret_requested = true;
        memset(prepared.rp_id_hash, 0x42, 32U);
        uint8_t response[384], aaguid[16] = {0}; size_t length;
        CtapMakeCredentialWorkspace workspace = {0};
        assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, response, sizeof response, &length) == 0U);
        assert(store.hashed_length == 210U && store.hashed_data[32] == 0xC1U);
        CborValue map, data, extension, supported;
        assert(cbor_read_document(response, length, &map) && cbor_map_uint(&map, 2U, &data) && data.value == 178U);
        assert(cbor_read_document(data.data + 164U, 14U, &extension) && cbor_map_text(&extension, "hmac-secret", &supported));
        assert(supported.encoded[0] == (legacy ? 0xF4U : 0xF5U));
    }
}
typedef struct { Store store; SecretMock mock; AuthCredentialService service; CtaphidDevice device; CtaphidCtapBackend backend; } Fixture;
static bool send(void *context, const uint8_t report[64], uint64_t token)
{ (void)context; (void)report; (void)token; return true; }
static bool receive(void *context, const uint8_t report[64])
{ Fixture *f = context; return ctaphid_device_receive_report(&f->device, report, 64U, 0U) == CTAPHID_DEVICE_OK; }
static void setup(Fixture *f)
{
    memset(f, 0, sizeof *f); configure(&f->service, &f->store, &f->mock); (void)seed(&f->service);
    CtapGetInfoProfile profile = {0}; profile.max_message_size = 1024U; profile.user_presence = true;
    assert(ctaphid_ctap_backend_init(&f->backend, &profile));
    assert(ctaphid_ctap_backend_configure_credentials(&f->backend, &f->service) && f->backend.profile.hmac_secret);
    CtaphidDeviceConfig config = {0}; config.submit_report = send;
    config.start_cbor = ctaphid_ctap_backend_start; config.abort_cbor = ctaphid_ctap_backend_abort; config.cbor_context = &f->backend;
    assert(ctaphid_device_init(&f->device, &config) == CTAPHID_DEVICE_OK);
    uint32_t cid; assert(ctaphid_channels_allocate(&f->device.channels, &cid) == CTAPHID_CHANNEL_OK);
    uint8_t bytes[513]; bytes[0] = 2U; size_t length = 1U + assertion_request(bytes + 1U, true);
    assert(ctaphid_send_response(cid, 0x10U, bytes, length, receive, f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f->device, 0U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&f->backend, &f->device, 0U) == CTAPHID_DEVICE_OK);
}
static void test_no_extension_crypto_before_consent_or_after_abort(void)
{
    Fixture f; setup(&f);
    assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 30000U) == CTAPHID_DEVICE_OK);
    assert(f.backend.response[0] == 0x27U && f.mock.agreements == 0U && f.mock.evaluations == 0U && f.store.signatures == 0U);
    setup(&f); uint8_t cancel[64] = {0, 0, 0, 1, 0x91};
    assert(ctaphid_device_receive_report(&f.device, cancel, sizeof cancel, 1U) == CTAPHID_DEVICE_OK);
    assert(!f.backend.pending && !f.backend.get_assertion.hmac_secret.requested && f.mock.agreements == 0U);
    setup(&f); uint8_t init[64] = {0, 0, 0, 1, 0x86, 0, 8};
    assert(ctaphid_device_receive_report(&f.device, init, sizeof init, 1U) == CTAPHID_DEVICE_OK);
    assert(!f.backend.pending && !f.backend.get_assertion.hmac_secret.requested && f.mock.evaluations == 0U);
}
int main(void)
{
    test_protocol_two_kdf_and_uv_separation();
    test_failure_output_and_legacy_handling();
    test_assertion_extension_is_signed_and_bad_mac_does_not_increment();
    test_registration_extension_output_and_availability();
    test_no_extension_crypto_before_consent_or_after_abort();
    puts("hmac-secret tests passed (protocol 2 KDF, auth, UV separation, signed outputs, failure/abort behavior).");
    return 0;
}
