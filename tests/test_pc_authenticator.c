#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "authenticator/auth_credentials.h"
#include "authenticator/auth_es256.h"
#include "../examples/host/pc_authenticator.h"

static void hex(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i) printf("%02x", (unsigned int)bytes[i]);
}

static void print_signed(AuthCredentialService *service, const AuthCredential *credential)
{
    const uint8_t message[] = "portable authenticator test";
    uint8_t digest[32], public_key[65], signature[72];
    size_t signature_length;
    uint32_t counter;
    assert(service->crypto.sha256(service->crypto.context, message, sizeof message - 1U, digest) == AUTH_OK);
    assert(service->crypto.public_key(service->crypto.context, &credential->key, public_key) == AUTH_OK);
    assert(auth_credentials_next_counter(service, credential->credential_id, credential->rp_id_hash, &counter) == AUTH_OK);
    assert(auth_credentials_sign_digest(service, credential->credential_id, credential->rp_id_hash,
        digest, signature, &signature_length) == AUTH_OK);
    printf("{\"id\":\""); hex(credential->credential_id, 32U);
    printf("\",\"key_handle\":\""); hex(credential->key.bytes, 32U);
    printf("\",\"public_key\":\""); hex(public_key, 65U);
    printf("\",\"digest\":\""); hex(digest, 32U);
    printf("\",\"signature\":\""); hex(signature, signature_length);
    printf("\",\"counter\":%u}\n", (unsigned int)counter);
}

static void exercise(PcAuthenticator *pc, AuthCredentialService *service)
{
    const uint8_t expected_empty[32] = {0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,
        0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55};
    uint8_t digest[32];
    assert(service->crypto.sha256(service->crypto.context, NULL, 0U, digest) == AUTH_OK);
    assert(memcmp(digest, expected_empty, 32U) == 0);
    const uint8_t domain[] = "example.com", user[] = "portable-user-id";
    uint8_t rp_hash[32], public_key[65];
    assert(service->crypto.sha256(service->crypto.context, domain, sizeof domain - 1U, rp_hash) == AUTH_OK);
    AuthCredential created, loaded;
    assert(auth_credentials_create(service, rp_hash, user, sizeof user - 1U, true, &created, public_key) == AUTH_OK);
    assert(auth_credentials_get(service, created.credential_id, rp_hash, &loaded) == AUTH_OK);
    assert(memcmp(loaded.user_id, user, sizeof user - 1U) == 0);
    assert(service->storage.insert(service->storage.context, &created) == AUTH_ALREADY_EXISTS);
    assert(service->crypto.destroy_key(service->crypto.context, &created.key) == AUTH_BUSY);
    uint8_t wrong_rp[32] = {0xFF};
    assert(auth_credentials_get(service, created.credential_id, wrong_rp, &loaded) == AUTH_NOT_FOUND);
    assert(service->storage.find_rp(service->storage.context, rp_hash, true, 0U, &loaded) == AUTH_OK);
    assert(service->storage.find_rp(service->storage.context, rp_hash, true, 1U, &loaded) == AUTH_NOT_FOUND);
    uint32_t counter;
    assert(auth_credentials_next_counter(service, created.credential_id, rp_hash, &counter) == AUTH_OK && counter == 1U);
    assert(service->storage.update_counter(service->storage.context, created.credential_id, 0U, 1U) == AUTH_BUSY);
    assert(auth_credentials_delete(service, created.credential_id, rp_hash) == AUTH_OK);
    assert(service->storage.read(service->storage.context, created.credential_id, &loaded) == AUTH_NOT_FOUND);
    assert(service->crypto.public_key(service->crypto.context, &created.key, public_key) == AUTH_NOT_FOUND);
    /* Fill both bounded backends; no output or extra key may be published on FULL. */
    for (size_t i = 0; i < service->storage.capacity; ++i) {
        assert(auth_credentials_create(service, rp_hash, user, sizeof user - 1U, i == 0U, &created, public_key) == AUTH_OK);
    }
    PcAuthenticatorState before = pc_authenticator_state(pc);
    AuthCredential sentinel;
    memset(&sentinel, 0xEE, sizeof sentinel);
    created = sentinel;
    assert(auth_credentials_create(service, rp_hash, user, sizeof user - 1U, false, &created, public_key) == AUTH_CAPACITY);
    assert(memcmp(&created, &sentinel, sizeof created) == 0);
    assert(pc_authenticator_state(pc).key_count == service->storage.capacity);
    assert(pc_authenticator_factory_reset(pc));
    PcAuthenticatorState after = pc_authenticator_state(pc);
    assert(after.credential_count == 0U && after.key_count == 0U && after.generation == before.generation + 1U);
    assert(memcmp(after.device_identifier, before.device_identifier, 16U) != 0);
    assert(memcmp(after.credential_store_state, before.credential_store_state, 16U) != 0);
    puts("{\"exercise\":\"passed\"}");
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    PcAuthenticator *pc = NULL;
    AuthStatus opened = pc_authenticator_open(argv[2], &pc);
    if (opened != AUTH_OK) { printf("{\"open_status\":%d}\n", (int)opened); return 20 + (int)opened; }
    AuthCrypto crypto = pc_authenticator_crypto(pc);
    AuthStorage storage = pc_authenticator_storage(pc);
    AuthCredentialService service;
    assert(auth_credentials_init(&service, &crypto, &storage));
    const uint8_t domain[] = "example.com", user[] = "portable-user-id";
    uint8_t rp_hash[32], public_key[65];
    assert(crypto.sha256(crypto.context, domain, sizeof domain - 1U, rp_hash) == AUTH_OK);
    if (strcmp(argv[1], "create") == 0) {
        AuthCredential created;
        assert(auth_credentials_create(&service, rp_hash, user, sizeof user - 1U, true, &created, public_key) == AUTH_OK);
        print_signed(&service, &created);
    } else if (strcmp(argv[1], "reopen") == 0) {
        AuthCredential found;
        assert(storage.find_rp(storage.context, rp_hash, true, 0U, &found) == AUTH_OK);
        print_signed(&service, &found);
    } else if (strcmp(argv[1], "delete") == 0) {
        AuthCredential found;
        assert(storage.find_rp(storage.context, rp_hash, true, 0U, &found) == AUTH_OK);
        assert(auth_credentials_delete(&service, found.credential_id, rp_hash) == AUTH_OK);
        printf("{\"credential_count\":%zu,\"key_count\":%zu}\n",
            pc_authenticator_state(pc).credential_count, pc_authenticator_state(pc).key_count);
    } else if (strcmp(argv[1], "exercise") == 0) exercise(pc, &service);
    else if (strcmp(argv[1], "lock") == 0) {
        PcAuthenticator *second = NULL;
        assert(pc_authenticator_open(argv[2], &second) == AUTH_BUSY && second == NULL);
        puts("{\"lock\":\"passed\"}");
    } else if (strcmp(argv[1], "status") == 0) {
        PcAuthenticatorState state = pc_authenticator_state(pc);
        printf("{\"credential_count\":%zu,\"key_count\":%zu,\"generation\":%u}\n",
            state.credential_count, state.key_count, (unsigned int)state.generation);
    } else { pc_authenticator_close(pc); return 2; }
    pc_authenticator_close(pc);
    return 0;
}
