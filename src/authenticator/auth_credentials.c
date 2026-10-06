#include "authenticator/auth_credentials.h"

#include <string.h>

bool auth_credentials_init(AuthCredentialService *service,
    const AuthCrypto *crypto, const AuthStorage *storage)
{
    if (service == NULL || crypto == NULL || storage == NULL || storage->capacity == 0U ||
        crypto->random == NULL || crypto->sha256 == NULL || crypto->generate_p256 == NULL ||
        crypto->public_key == NULL || crypto->sign_p256_digest == NULL || crypto->destroy_key == NULL ||
        storage->read == NULL || storage->insert == NULL || storage->erase == NULL ||
        storage->find_rp == NULL || storage->count == NULL || storage->update_counter == NULL) return false;
    service->crypto = *crypto;
    service->storage = *storage;
    return true;
}

AuthStatus auth_credentials_create(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, AuthCredential *credential, uint8_t public_key[65])
{
    if (service == NULL || rp_id_hash == NULL || user_id == NULL || credential == NULL ||
        public_key == NULL || user_id_length == 0U || user_id_length > AUTH_USER_ID_MAX_SIZE) return AUTH_INVALID_ARGUMENT;
    size_t count;
    AuthStatus status = service->storage.count(service->storage.context, &count);
    if (status != AUTH_OK) return status;
    if (count >= service->storage.capacity) return AUTH_CAPACITY;
    AuthCredential created = {0}, existing;
    created.algorithm = AUTH_COSE_ALG_ES256;
    created.discoverable = discoverable;
    created.user_id_length = (uint8_t)user_id_length;
    memcpy(created.user_id, user_id, user_id_length);
    memcpy(created.rp_id_hash, rp_id_hash, 32U);
    /* Bounded collision handling; storage lookup failure never implies free ID. */
    bool unique = false;
    for (unsigned attempt = 0; attempt < 8U; ++attempt) {
        status = service->crypto.random(service->crypto.context, created.credential_id, 32U);
        if (status != AUTH_OK) return status;
        status = service->storage.read(service->storage.context, created.credential_id, &existing);
        if (status == AUTH_NOT_FOUND) {
            uint8_t combined = 0U;
            for (size_t i = 0; i < 32U; ++i) combined |= created.credential_id[i];
            if (combined != 0U) { unique = true; break; }
        } else if (status != AUTH_OK) return status;
    }
    if (!unique) return AUTH_CRYPTO_ERROR;
    uint8_t generated_public[65];
    status = service->crypto.generate_p256(service->crypto.context, &created.key, generated_public);
    if (status != AUTH_OK) return status;
    if (!auth_key_handle_valid(&created.key) || generated_public[0] != 0x04U) {
        (void)service->crypto.destroy_key(service->crypto.context, &created.key);
        return AUTH_BAD_DATA;
    }
    status = service->storage.insert(service->storage.context, &created);
    if (status != AUTH_OK) {
        AuthStatus cleanup = service->crypto.destroy_key(service->crypto.context, &created.key);
        return cleanup == AUTH_OK ? status : AUTH_IO_ERROR;
    }
    *credential = created;
    memcpy(public_key, generated_public, 65U);
    return AUTH_OK;
}

AuthStatus auth_credentials_get(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], AuthCredential *credential)
{
    if (service == NULL || id == NULL || rp_hash == NULL || credential == NULL) return AUTH_INVALID_ARGUMENT;
    AuthCredential found;
    AuthStatus status = service->storage.read(service->storage.context, id, &found);
    if (status != AUTH_OK) return status;
    if (!auth_credential_valid(&found) || memcmp(found.credential_id, id, 32U) != 0) return AUTH_BAD_DATA;
    if (memcmp(found.rp_id_hash, rp_hash, 32U) != 0) return AUTH_NOT_FOUND;
    *credential = found;
    return AUTH_OK;
}

AuthStatus auth_credentials_sign_digest(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], const uint8_t digest[32],
    uint8_t signature[72], size_t *signature_length)
{
    if (digest == NULL || signature == NULL || signature_length == NULL) return AUTH_INVALID_ARGUMENT;
    AuthCredential credential;
    AuthStatus status = auth_credentials_get(service, id, rp_hash, &credential);
    if (status != AUTH_OK) return status;
    return service->crypto.sign_p256_digest(service->crypto.context, &credential.key,
        digest, signature, signature_length);
}

AuthStatus auth_credentials_next_counter(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], uint32_t *counter)
{
    if (counter == NULL) return AUTH_INVALID_ARGUMENT;
    AuthCredential credential;
    AuthStatus status = auth_credentials_get(service, id, rp_hash, &credential);
    if (status != AUTH_OK) return status;
    if (credential.signature_count == UINT32_MAX) return AUTH_CAPACITY;
    uint32_t next = credential.signature_count + 1U;
    status = service->storage.update_counter(service->storage.context, id, credential.signature_count, next);
    if (status == AUTH_OK) *counter = next;
    return status;
}

AuthStatus auth_credentials_delete(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32])
{
    AuthCredential credential;
    AuthStatus status = auth_credentials_get(service, id, rp_hash, &credential);
    if (status != AUTH_OK) return status;
    status = service->storage.erase(service->storage.context, id);
    if (status != AUTH_OK) return status;
    return service->crypto.destroy_key(service->crypto.context, &credential.key);
}
