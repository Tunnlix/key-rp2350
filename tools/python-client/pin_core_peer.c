/* Test-only ABI for Python primitive callbacks. No product OS provider or HID
 * simulation: python-fido2 sends canonical CTAP CBOR directly to portable C.
 * Persistent record is simulated in memory; Windows vault tests use the real
 * subprocess peer. Kept with the optional Python tooling. */
#include "ctap/ctap_client_pin.h"
#include "ctap/ctap_pin_protocol.h"
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
    if (encrypt || n > 64U) return AUTH_INVALID_ARGUMENT;
    uint8_t cipher[80]; memcpy(cipher, iv, 16U); memcpy(cipher + 16U, in, n);
    return (AuthStatus)primitive(5U, key, 32U, cipher, n + 16U, out, n);
}
static AuthStatus regenerate(void *ctx)
{ (void)ctx; return (AuthStatus)primitive(6U, NULL, 0U, NULL, 0U, NULL, 0U); }
static AuthStatus supported(void *ctx, const AuthKeyHandle *key, bool *out)
{ (void)ctx; (void)key; (void)out; return AUTH_UNSUPPORTED; }
static AuthStatus credential_hmac(void *ctx, const AuthKeyHandle *key, bool uv, const uint8_t salt[32], uint8_t out[32])
{ (void)ctx; (void)key; (void)uv; (void)salt; (void)out; return AUTH_UNSUPPORTED; }
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
    service.crypto.sha256 = hash;
    service.secrets = (AuthSecretCrypto){NULL, public_key, ecdh, hmac, aes, supported, credential_hmac, regenerate};
    record = (AuthPinRecord){0}; record.retries = 8U;
    return pin_test_power_on();
}
PIN_TEST_API int pin_test_reset(void)
{
    if (regenerate(NULL) != AUTH_OK) return 0;
    auth_secure_zero(&record, sizeof record); record.retries = 8U;
    ctap_client_pin_reset_state(&pin); return 1;
}
PIN_TEST_API size_t pin_test_call(const uint8_t *input, size_t n, uint8_t output[513])
{
    if (n == 0U) { output[0] = CTAP_STATUS_INVALID_LENGTH; return 1U; }
    size_t length = 0U;
    if (input[0] == CTAP_COMMAND_CLIENT_PIN) {
        CtapClientPinRequest request;
        uint8_t status = ctap_client_pin_prepare(input + 1U, n - 1U, &request);
        if (status == CTAP_STATUS_OK) status = ctap_client_pin_execute(&pin, &request, output + 1U, 512U, &length);
        auth_secure_zero(&request, sizeof request); output[0] = status;
        return status == CTAP_STATUS_OK ? 1U + length : 1U;
    }
    CtapGetInfoProfile profile = {0}; profile.max_message_size = 1024U; profile.user_presence = true; profile.hmac_secret = true;
    if (ctap_execute(&profile, input, n, output, 513U, &length) != CTAP_EXECUTION_RESPONSE_READY) {
        output[0] = CTAP_STATUS_OTHER; return 1U;
    }
    return length;
}
