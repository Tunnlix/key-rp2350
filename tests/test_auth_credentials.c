#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "authenticator/auth_credentials.h"
#include "authenticator/auth_es256.h"

/* Fake primitive callbacks test orchestration only; real ECDSA is verified by
 * Known-answer primitive validation belongs to the injected crypto provider. */
typedef struct {
    AuthCredential record;
    bool exists, erase_fails, zero_random;
    AuthStatus insert_status, destroy_status, counter_status, read_status, random_status, generate_status;
    size_t generated, destroyed, signed_count, random_calls;
    AuthCredentialService *reenter_service;
    bool reentered;
} Mock;

static AuthStatus random_data(void *context, uint8_t *output, size_t length)
{ Mock *mock = context; ++mock->random_calls; memset(output, mock->zero_random ? 0 : 0xA5, length); return mock->random_status; }
static AuthStatus hash(void *context, const uint8_t *input, size_t length, uint8_t output[32])
{ (void)context; (void)input; (void)length; memset(output, 1, 32U); return AUTH_OK; }
static AuthStatus generate(void *context, AuthKeyHandle *key, uint8_t output[65])
{ Mock *mock = context; ++mock->generated;
  if (mock->generate_status != AUTH_OK) return mock->generate_status;
  memset(key->bytes, 0x5A, 32U); memset(output, 0, 65U); output[0] = 4U; return AUTH_OK; }
static AuthStatus public_key(void *context, const AuthKeyHandle *key, uint8_t output[65])
{ (void)context; (void)key; memset(output, 0, 65U); output[0] = 4U; return AUTH_OK; }
static AuthStatus sign(void *context, const AuthKeyHandle *key, const uint8_t digest[32], uint8_t output[72], size_t *length)
{ Mock *mock = context; (void)key; (void)digest; ++mock->signed_count; output[0] = 0x30U; *length = 1U; return AUTH_OK; }
static AuthStatus destroy(void *context, const AuthKeyHandle *key)
{ Mock *mock = context; assert(key->bytes[0] == 0x5AU); assert(!mock->exists); ++mock->destroyed; return mock->destroy_status; }
static AuthStatus read_record(void *context, const uint8_t id[32], AuthCredential *output)
{ Mock *mock = context;
  if (mock->reenter_service != NULL) {
      AuthCredential nested; memset(&nested, 0xEE, sizeof nested);
      uint8_t key[65]; memset(key, 0xEE, sizeof key);
      assert(auth_credentials_get(mock->reenter_service, id, mock->record.rp_id_hash, &nested) == AUTH_INVALID_ARGUMENT);
      assert(auth_credentials_create(mock->reenter_service, mock->record.rp_id_hash, NULL, 0U,
          false, &nested, key) == AUTH_INVALID_ARGUMENT);
      assert(nested.credential_id[0] == 0xEEU && key[0] == 0xEEU && mock->reenter_service->lookup_busy);
      mock->reentered = true;
  }
  if (mock->read_status != AUTH_OK) { memset(output, 0xA5, sizeof *output); return mock->read_status; }
  if (!mock->exists || memcmp(mock->record.credential_id, id, 32U) != 0) return AUTH_NOT_FOUND;
  *output = mock->record; return AUTH_OK; }
static AuthStatus insert(void *context, const AuthCredential *record)
{ Mock *mock = context; if (mock->insert_status != AUTH_OK) return mock->insert_status; mock->record = *record; mock->exists = true; return AUTH_OK; }
static AuthStatus erase(void *context, const uint8_t id[32])
{ Mock *mock = context; (void)id; if (mock->erase_fails) return AUTH_IO_ERROR; mock->exists = false; return AUTH_OK; }
static AuthStatus find(void *context, const uint8_t rp[32], bool discoverable, size_t index, AuthCredential *record)
{ Mock *mock = context; (void)rp; (void)discoverable; if (!mock->exists || index != 0U) return AUTH_NOT_FOUND; *record = mock->record; return AUTH_OK; }
static AuthStatus count(void *context, size_t *output)
{ Mock *mock = context; *output = mock->exists ? 1U : 0U; return AUTH_OK; }
static AuthStatus update(void *context, const uint8_t id[32], uint32_t expected, uint32_t next)
{ Mock *mock = context; (void)id; assert(mock->record.signature_count == expected); if (mock->counter_status == AUTH_OK) mock->record.signature_count = next; return mock->counter_status; }

static AuthCredentialService setup(Mock *mock)
{
    AuthCrypto crypto = {mock, random_data, hash, generate, public_key, sign, destroy};
    AuthStorage storage = {mock, 2U, read_record, insert, erase, find, count, update, NULL, NULL, NULL, NULL};
    AuthCredentialService service;
    assert(auth_credentials_init(&service, &crypto, &storage));
    return service;
}

static void assert_creation_scratch_cleared(const AuthCredentialService *service)
{
    const unsigned char *bytes = (const unsigned char *)&service->creation_scratch;
    for (size_t i = 0U; i < sizeof service->creation_scratch; ++i) assert(bytes[i] == 0U);
    assert(!service->creation_busy);
}

static void test_creation_workspace_failures(void)
{
    const uint8_t rp[32] = {1U};
    for (unsigned failure = 0U; failure < 5U; ++failure) {
        Mock mock = {0}; AuthCredentialService service = setup(&mock);
        AuthCredential output, saved; uint8_t key[65], saved_key[65];
        memset(&output, 0xEE, sizeof output); saved = output;
        memset(key, 0xEE, sizeof key); memcpy(saved_key, key, sizeof key);
        mock.random_status = failure == 0U ? AUTH_CRYPTO_ERROR : AUTH_OK;
        mock.read_status = failure == 1U ? AUTH_IO_ERROR : AUTH_OK;
        mock.generate_status = failure == 2U ? AUTH_CRYPTO_ERROR : AUTH_OK;
        mock.insert_status = failure >= 3U ? AUTH_CAPACITY : AUTH_OK;
        mock.destroy_status = failure == 4U ? AUTH_CRYPTO_ERROR : AUTH_OK;
        const AuthStatus expected[] = {AUTH_CRYPTO_ERROR, AUTH_IO_ERROR, AUTH_CRYPTO_ERROR, AUTH_CAPACITY, AUTH_IO_ERROR};
        assert(auth_credentials_create_protected(&service, rp, NULL, 0U, false, 2U,
            &output, key) == expected[failure]);
        assert_creation_scratch_cleared(&service);
        assert(memcmp(&output, &saved, sizeof output) == 0 && memcmp(key, saved_key, sizeof key) == 0);
        assert(service.metadata_revision == 0U && !mock.exists);
        assert(mock.generated == (failure >= 2U ? 1U : 0U));
        assert(mock.destroyed == (failure >= 3U ? 1U : 0U));
        mock.random_status = mock.read_status = mock.generate_status = mock.insert_status = mock.destroy_status = AUTH_OK;
        assert(auth_credentials_create_protected(&service, rp, NULL, 0U, false, 2U, &output, key) == AUTH_OK);
        assert_creation_scratch_cleared(&service);
        assert(output.cred_protect == 2U && output.user_id_length == 0U && service.metadata_revision == 1U);
    }
}

static void test_creation_failure_and_collision(void)
{
    Mock mock = {0};
    AuthCredentialService service = setup(&mock);
    const uint8_t rp[32] = {1U}, user[3] = {1U, 2U, 3U};
    uint8_t public_key[65];
    AuthCredential output, saved;
    memset(&output, 0xEE, sizeof output); saved = output;
    mock.insert_status = AUTH_IO_ERROR;
    assert(auth_credentials_create(&service, rp, user, sizeof user, false, &output, public_key) == AUTH_IO_ERROR);
    assert(mock.generated == 1U && mock.destroyed == 1U && !mock.exists);
    assert(memcmp(&output, &saved, sizeof output) == 0);
    mock.insert_status = AUTH_OK;
    assert(auth_credentials_create(&service, rp, user, sizeof user, true, &output, public_key) == AUTH_INVALID_ARGUMENT);
    assert(auth_credentials_create(&service, rp, user, sizeof user, false, &output, public_key) == AUTH_OK);
    assert(auth_credential_valid(&output));
    assert(output.user_id_length == 3U && output.signature_count == 0U && !output.discoverable);
    size_t generated = mock.generated;
    size_t random_calls = mock.random_calls;
    assert(auth_credentials_create(&service, rp, user, sizeof user, false, &saved, public_key) == AUTH_CRYPTO_ERROR);
    assert(mock.generated == generated); /* Eight ID collisions never create a key. */
    assert(mock.random_calls == random_calls + 8U);
    assert_creation_scratch_cleared(&service);
    mock.exists = false; mock.zero_random = true;
    assert(auth_credentials_create(&service, rp, user, sizeof user, false, &saved, public_key) == AUTH_CRYPTO_ERROR);
    assert(mock.generated == generated);
    assert_creation_scratch_cleared(&service);
}

static void assert_lookup_cleared(const AuthCredentialService *service)
{
    const unsigned char *bytes = (const unsigned char *)&service->lookup_scratch;
    for (size_t i = 0U; i < sizeof service->lookup_scratch; ++i) assert(bytes[i] == 0U);
    assert(!service->lookup_busy);
}

static void test_lookup_workspace(void)
{
    Mock mock = {0}; AuthCredentialService service = setup(&mock);
    const uint8_t rp[32] = {1U}, wrong[32] = {2U}; uint8_t key[65];
    AuthCredential original, output, saved;
    assert(auth_credentials_create(&service, rp, NULL, 0U, false, &original, key) == AUTH_OK);
    memset(&output, 0xEE, sizeof output); saved = output;
    mock.read_status = AUTH_IO_ERROR;
    assert(auth_credentials_get(&service, original.credential_id, rp, &output) == AUTH_IO_ERROR);
    assert_lookup_cleared(&service);
    assert(memcmp(&output, &saved, sizeof output) == 0);
    mock.read_status = AUTH_OK;
    assert(auth_credentials_get(&service, original.credential_id, wrong, &output) == AUTH_NOT_FOUND);
    assert_lookup_cleared(&service);
    assert(memcmp(&output, &saved, sizeof output) == 0);
    mock.record.cred_protect = 0U;
    assert(auth_credentials_get(&service, original.credential_id, rp, &output) == AUTH_BAD_DATA);
    assert_lookup_cleared(&service);
    assert(memcmp(&output, &saved, sizeof output) == 0);
    mock.record = original; mock.reenter_service = &service;
    assert(auth_credentials_get(&service, original.credential_id, rp, &output) == AUTH_OK);
    assert(mock.reentered && memcmp(&output, &original, sizeof output) == 0);
    assert_lookup_cleared(&service);
}

static void test_rp_binding_counter_and_deletion(void)
{
    Mock mock = {0};
    AuthCredentialService service = setup(&mock);
    const uint8_t rp[32] = {1U}, wrong[32] = {2U}, user[1] = {1U};
    uint8_t public_key[65], digest[32] = {0}, signature[72];
    AuthCredential credential;
    assert(auth_credentials_create(&service, rp, user, 1U, false, &credential, public_key) == AUTH_OK);
    size_t length = 999U;
    assert(auth_credentials_sign_digest(&service, credential.credential_id, wrong, digest, signature, &length) == AUTH_NOT_FOUND);
    assert_lookup_cleared(&service);
    assert(mock.signed_count == 0U && length == 999U);
    assert(auth_credentials_sign_digest(&service, credential.credential_id, rp, digest, signature, &length) == AUTH_OK);
    assert_lookup_cleared(&service);
    uint32_t counter = 999U;
    mock.counter_status = AUTH_IO_ERROR;
    assert(auth_credentials_next_counter(&service, credential.credential_id, rp, &counter) == AUTH_IO_ERROR);
    assert_lookup_cleared(&service);
    assert(counter == 999U && mock.record.signature_count == 0U);
    mock.counter_status = AUTH_OK;
    assert(auth_credentials_next_counter(&service, credential.credential_id, rp, &counter) == AUTH_OK && counter == 1U);
    assert_lookup_cleared(&service);
    mock.record.signature_count = UINT32_MAX;
    assert(auth_credentials_next_counter(&service, credential.credential_id, rp, &counter) == AUTH_CAPACITY);
    assert_lookup_cleared(&service);
    mock.erase_fails = true;
    assert(auth_credentials_delete(&service, credential.credential_id, rp) == AUTH_IO_ERROR && mock.destroyed == 0U);
    assert_lookup_cleared(&service);
    mock.erase_fails = false;
    assert(auth_credentials_delete(&service, credential.credential_id, rp) == AUTH_OK && mock.destroyed == 1U);
    assert_lookup_cleared(&service);
}

static void test_der_canonical_integers(void)
{
    uint8_t raw[64] = {0}, output[72];
    raw[31] = 1U; raw[63] = 0x80U;
    const uint8_t expected[] = {0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0, 0x80};
    size_t length;
    assert(auth_es256_signature_to_der(raw, output, sizeof output, &length));
    assert(length == sizeof expected && memcmp(output, expected, length) == 0);
    length = 999U;
    memset(output, 0xEE, sizeof output);
    assert(!auth_es256_signature_to_der(raw, output, sizeof expected - 1U, &length));
    assert(length == 999U && output[0] == 0xEEU);
    raw[31] = 0U;
    assert(!auth_es256_signature_to_der(raw, output, sizeof output, &length));
}

int main(void)
{
    test_creation_failure_and_collision();
    test_creation_workspace_failures();
    test_rp_binding_counter_and_deletion();
    test_lookup_workspace();
    test_der_canonical_integers();
    puts("Portable credential service tests passed (ownership, RP binding, failure cleanup, counters, DER).");
    return 0;
}
