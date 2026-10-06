/* Test-only ABI for Python primitive callbacks. No product OS provider or HID
 * simulation: python-fido2 sends canonical CTAP CBOR directly to portable C.
 * Persistent record is simulated in memory; Windows vault tests use the real
 * subprocess peer. Kept with the optional Python tooling. */
#include "ctap/ctap_client_pin.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/ctap_make_credential.h"
#include "ctap/ctap_get_assertion.h"
#include <string.h>
#ifdef _WIN32
#define PIN_TEST_API __declspec(dllexport)
#else
#define PIN_TEST_API
#endif

typedef int (*Primitive)(unsigned, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
static Primitive primitive;
static AuthCredentialService service;
static CtapClientPin pin;
static AuthPinRecord record;
static uint32_t now_ms;
static AuthCredential records[8];
static bool used[8];

static AuthStatus random_bytes(void *ctx, uint8_t *out, size_t n)
{ (void)ctx; return (AuthStatus)primitive(0U, NULL, 0U, NULL, 0U, out, n); }

static AuthStatus hash(void *ctx, const uint8_t *in, size_t n, uint8_t out[32])
{ (void)ctx; return (AuthStatus)primitive(1U, in, n, NULL, 0U, out, 32U); }
static AuthStatus public_key(void *ctx, uint8_t out[65])
{ (void)ctx; return (AuthStatus)primitive(2U, NULL, 0U, NULL, 0U, out, 65U); }
static AuthStatus ecdh(void *ctx, const uint8_t in[65], uint8_t out[32])
{ (void)ctx; return (AuthStatus)primitive(3U, in, 65U, NULL, 0U, out, 32U); }
static AuthStatus hmac(void *ctx, const uint8_t *key, size_t key_n, const uint8_t *in, size_t n, uint8_t out[32])
{ (void)ctx; return (AuthStatus)primitive(4U, key, key_n, in, n, out, 32U); }
static AuthStatus aes(void *ctx, bool encrypt, const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *in, size_t n, uint8_t *out)
{
    (void)ctx;
    if (n > 64U) return AUTH_INVALID_ARGUMENT;
    uint8_t cipher[80]; memcpy(cipher, iv, 16U); memcpy(cipher + 16U, in, n);
    return (AuthStatus)primitive(encrypt ? 14U : 5U, key, 32U, cipher, n + 16U, out, n);
}
static AuthStatus regenerate(void *ctx)
{ (void)ctx; return (AuthStatus)primitive(6U, NULL, 0U, NULL, 0U, NULL, 0U); }
static AuthStatus supported(void *ctx, const AuthKeyHandle *key, bool *out)
{
    (void)ctx; uint8_t value;
    AuthStatus status = (AuthStatus)primitive(11U, key->bytes, 32U, NULL, 0U, &value, 1U);
    if (status == AUTH_OK) *out = value != 0U;
    return status;
}
static AuthStatus credential_hmac(void *ctx, const AuthKeyHandle *key, bool uv, const uint8_t salt[32], uint8_t out[32])
{
    (void)ctx; uint8_t input[33]; input[0] = uv ? 1U : 0U; memcpy(input + 1U, salt, 32U);
    return (AuthStatus)primitive(12U, key->bytes, 32U, input, sizeof input, out, 32U);
}
static AuthStatus generate_key(void *ctx, AuthKeyHandle *key, uint8_t out[65])
{
    (void)ctx; uint8_t generated[97];
    AuthStatus status = (AuthStatus)primitive(7U, NULL, 0U, NULL, 0U, generated, sizeof generated);
    if (status == AUTH_OK) { memcpy(key->bytes, generated, 32U); memcpy(out, generated + 32U, 65U); }
    return status;
}
static AuthStatus credential_public(void *ctx, const AuthKeyHandle *key, uint8_t out[65])
{ (void)ctx; return (AuthStatus)primitive(8U, key->bytes, 32U, NULL, 0U, out, 65U); }
static AuthStatus sign(void *ctx, const AuthKeyHandle *key, const uint8_t digest[32], uint8_t out[72], size_t *length)
{
    (void)ctx; uint8_t signed_result[73];
    AuthStatus status = (AuthStatus)primitive(9U, key->bytes, 32U, digest, 32U, signed_result, sizeof signed_result);
    if (status != AUTH_OK) return status;
    if (signed_result[0] > 72U) return AUTH_BAD_DATA;
    memcpy(out, signed_result + 1U, signed_result[0]); *length = signed_result[0]; return AUTH_OK;
}
static AuthStatus destroy(void *ctx, const AuthKeyHandle *key)
{ (void)ctx; return (AuthStatus)primitive(10U, key->bytes, 32U, NULL, 0U, NULL, 0U); }
static AuthStatus read_credential(void *ctx, const uint8_t id[32], AuthCredential *out)
{
    (void)ctx;
    for (size_t i = 0U; i < 8U; ++i) if (used[i] && memcmp(id, records[i].credential_id, 32U) == 0) { *out = records[i]; return AUTH_OK; }
    return AUTH_NOT_FOUND;
}
static AuthStatus insert(void *ctx, const AuthCredential *in)
{
    (void)ctx;
    for (size_t i = 0U; i < 8U; ++i) if (!used[i]) { records[i] = *in; used[i] = true; return AUTH_OK; }
    return AUTH_CAPACITY;
}
static AuthStatus erase(void *ctx, const uint8_t id[32])
{
    (void)ctx;
    for (size_t i = 0U; i < 8U; ++i) if (used[i] && memcmp(id, records[i].credential_id, 32U) == 0) { used[i] = false; return AUTH_OK; }
    return AUTH_NOT_FOUND;
}
static AuthStatus find_rp(void *ctx, const uint8_t rp[32], bool discoverable, size_t index, AuthCredential *out)
{
    (void)ctx;
    for (size_t i = 0U; i < 8U; ++i) if (used[i] && memcmp(rp, records[i].rp_id_hash, 32U) == 0 &&
        (!discoverable || records[i].discoverable) && index-- == 0U) { *out = records[i]; return AUTH_OK; }
    return AUTH_NOT_FOUND;
}
static AuthStatus count(void *ctx, size_t *out)
{ (void)ctx; *out = 0U; for (size_t i = 0U; i < 8U; ++i) if (used[i]) ++*out; return AUTH_OK; }
static AuthStatus counter(void *ctx, const uint8_t id[32], uint32_t expected, uint32_t next)
{
    (void)ctx;
    for (size_t i = 0U; i < 8U; ++i) if (used[i] && memcmp(id, records[i].credential_id, 32U) == 0) {
        if (records[i].signature_count != expected || expected == UINT32_MAX || next != expected + 1U) return AUTH_BAD_DATA;
        records[i].signature_count = next; return AUTH_OK;
    }
    return AUTH_NOT_FOUND;
}
static AuthStatus read_pin(void *ctx, AuthPinRecord *out)
{ (void)ctx; *out = record; return AUTH_OK; }
static AuthStatus write_pin(void *ctx, const AuthPinRecord *in)
{ (void)ctx; record = *in; return AUTH_OK; }
PIN_TEST_API int pin_test_power_on(void)
{
    AuthPinStorage storage = {NULL, read_pin, write_pin};
    return regenerate(NULL) == AUTH_OK && ctap_client_pin_init(&pin, &service, &storage);
}
PIN_TEST_API int pin_test_init(Primitive callback)
{
    primitive = callback; memset(&service, 0, sizeof service);
    service.crypto = (AuthCrypto){NULL, random_bytes, hash, generate_key, credential_public, sign, destroy};
    service.storage = (AuthStorage){NULL, 8U, read_credential, insert, erase, find_rp, count, counter};
    service.secrets = (AuthSecretCrypto){NULL, public_key, ecdh, hmac, aes, supported, credential_hmac, regenerate};
    record = (AuthPinRecord){0}; record.retries = 8U;
    memset(used, 0, sizeof used); auth_secure_zero(records, sizeof records); now_ms = 0U;
    return pin_test_power_on();
}
PIN_TEST_API int pin_test_reset(void)
{
    if (regenerate(NULL) != AUTH_OK) return 0;
    if (primitive(13U, NULL, 0U, NULL, 0U, NULL, 0U) != AUTH_OK) return 0;
    memset(used, 0, sizeof used); auth_secure_zero(records, sizeof records);
    auth_secure_zero(&record, sizeof record); record.retries = 8U;
    ctap_client_pin_reset_state(&pin); return !pin.faulted;
}
PIN_TEST_API size_t pin_test_call(const uint8_t *input, size_t n, uint8_t output[513])
{
    if (n == 0U) { output[0] = CTAP_STATUS_INVALID_LENGTH; return 1U; }
    size_t length = 0U;
    if (input[0] == CTAP_COMMAND_CLIENT_PIN) {
        CtapClientPinRequest request;
        uint8_t status = ctap_client_pin_prepare(input + 1U, n - 1U, &request);
        if (status == CTAP_STATUS_OK) status = ctap_client_pin_execute(&pin, &request, output + 1U, 512U, &length, now_ms);
        auth_secure_zero(&request, sizeof request); output[0] = status;
        return status == CTAP_STATUS_OK ? 1U + length : 1U;
    }
    if (input[0] == CTAP_COMMAND_MAKE_CREDENTIAL || input[0] == CTAP_COMMAND_GET_ASSERTION) {
        uint8_t status;
        if (input[0] == CTAP_COMMAND_MAKE_CREDENTIAL) {
            CtapMakeCredential prepared; uint8_t aaguid[16] = {0};
            status = ctap_make_credential_prepare_with_pin(&service, &pin, now_ms, input + 1U, n - 1U, &prepared);
            if (status == CTAP_STATUS_OK) status = ctap_make_credential_finish_at(&service, &prepared, aaguid, output + 1U, 512U, &length, now_ms);
        } else {
            CtapGetAssertion prepared;
            status = ctap_get_assertion_prepare_with_pin(&service, &pin, now_ms, input + 1U, n - 1U, &prepared);
            if (status == CTAP_STATUS_OK) status = ctap_get_assertion_finish_at(&service, &prepared, output + 1U, 512U, &length, now_ms);
        }
        output[0] = status; return status == CTAP_STATUS_OK ? 1U + length : 1U;
    }
    CtapGetInfoProfile profile = {0}; profile.max_message_size = 1024U; profile.user_presence = true;
    profile.hmac_secret = profile.make_credential = profile.pin_uv_auth = true;
    if (ctap_client_pin_status(&pin, &profile.pin_set) != CTAP_STATUS_OK) { output[0] = CTAP_STATUS_OTHER; return 1U; }
    if (ctap_execute(&profile, input, n, output, 513U, &length) != CTAP_EXECUTION_RESPONSE_READY) {
        output[0] = CTAP_STATUS_OTHER; return 1U;
    }
    return length;
}
PIN_TEST_API void pin_test_advance_time(uint32_t elapsed)
{ now_ms += elapsed; ctap_client_pin_poll(&pin, now_ms); }
