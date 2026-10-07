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
    memset(&service->secrets, 0, sizeof service->secrets);
    service->metadata_revision = 0U;
    return true;
}

bool auth_credentials_configure_secrets(AuthCredentialService *service,
    const AuthSecretCrypto *secrets)
{
    if (service == NULL || !auth_secret_crypto_valid(secrets) ||
        auth_secret_crypto_valid(&service->secrets)) return false;
    service->secrets = *secrets;
    return true;
}

AuthStatus auth_credentials_create(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, AuthCredential *credential, uint8_t public_key[65])
{
    return auth_credentials_create_protected(service, rp_id_hash, user_id, user_id_length,
        discoverable, 1U, credential, public_key);
}

AuthStatus auth_credentials_create_protected(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, uint8_t cred_protect, AuthCredential *credential, uint8_t public_key[65])
{
    if (service == NULL || rp_id_hash == NULL || (user_id == NULL && user_id_length != 0U) || credential == NULL ||
        public_key == NULL || discoverable || user_id_length > AUTH_USER_ID_MAX_SIZE || cred_protect < 1U || cred_protect > 3U)
        return AUTH_INVALID_ARGUMENT;
    if (service->metadata_revision == UINT64_MAX) return AUTH_CAPACITY;
    size_t count;
    AuthStatus status = service->storage.count(service->storage.context, &count);
    if (status != AUTH_OK) return status;
    if (count >= service->storage.capacity) return AUTH_CAPACITY;
    AuthCredential created = {0}, existing;
    created.algorithm = AUTH_COSE_ALG_ES256;
    created.discoverable = discoverable;
    created.cred_protect = cred_protect;
    created.user_id_length = (uint8_t)user_id_length;
    if (user_id_length != 0U) memcpy(created.user_id, user_id, user_id_length);
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
    ++service->metadata_revision;
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
    if (service->metadata_revision == UINT64_MAX) return AUTH_CAPACITY;
    if (credential.discoverable && service->storage.erase_resident != NULL) {
        uint8_t state[16];
        status = service->crypto.random(service->crypto.context, state, sizeof state);
        if (status == AUTH_OK) status = service->storage.erase_resident(service->storage.context, id, state);
        auth_secure_zero(state, sizeof state);
    } else status = service->storage.erase(service->storage.context, id);
    if (status != AUTH_OK) return status;
    ++service->metadata_revision;
    return service->crypto.destroy_key(service->crypto.context, &credential.key);
}

bool auth_credentials_resident_supported(const AuthCredentialService *service)
{
    return service != NULL && service->storage.capacity > 0U && service->storage.capacity <= AUTH_RESIDENT_MAX_COUNT &&
        service->storage.enumerate != NULL && service->storage.put_resident != NULL &&
        service->storage.erase_resident != NULL && service->storage.update_user != NULL;
}

AuthStatus auth_credentials_enumerate(AuthCredentialService *service, size_t index, AuthCredential *credential)
{
    if (service == NULL || credential == NULL || service->storage.enumerate == NULL) return AUTH_INVALID_ARGUMENT;
    AuthCredential found;
    AuthStatus status = service->storage.enumerate(service->storage.context, index, &found);
    if (status != AUTH_OK) return status;
    if (!auth_credential_valid(&found)) return AUTH_BAD_DATA;
    *credential = found; return AUTH_OK;
}

AuthStatus auth_credentials_create_resident(AuthCredentialService *service,
    const AuthCredential *metadata, AuthCredential *credential, uint8_t public_key[65])
{
    return auth_credentials_create_resident_prepared(service, metadata, NULL, NULL, credential, public_key);
}

AuthStatus auth_credentials_create_resident_prepared(AuthCredentialService *service,
    const AuthCredential *metadata, AuthCredentialPrepare prepare, void *context,
    AuthCredential *credential, uint8_t public_key[65])
{
    if (!auth_credentials_resident_supported(service) || metadata == NULL || credential == NULL || public_key == NULL ||
        metadata->user_id_length > AUTH_USER_ID_MAX_SIZE || metadata->rp_id_length == 0U ||
        metadata->rp_id_length > AUTH_RP_ID_MAX_SIZE || metadata->rp_name_length > AUTH_ENTITY_NAME_MAX_SIZE ||
        metadata->user_name_length > AUTH_ENTITY_NAME_MAX_SIZE || metadata->user_display_name_length > AUTH_ENTITY_NAME_MAX_SIZE ||
        !auth_text_valid(metadata->rp_id, metadata->rp_id_length) || !auth_text_valid(metadata->rp_name, metadata->rp_name_length) ||
        !auth_text_valid(metadata->user_name, metadata->user_name_length) ||
        !auth_text_valid(metadata->user_display_name, metadata->user_display_name_length) ||
        metadata->cred_protect < 1U || metadata->cred_protect > 3U || service->metadata_revision == UINT64_MAX)
        return AUTH_INVALID_ARGUMENT;
    AuthCredential old = {0}, found;
    bool replacing = false; uint64_t newest = 0U;
    size_t total = 0U;
    for (; total < service->storage.capacity; ++total) {
        AuthStatus status = auth_credentials_enumerate(service, total, &found);
        if (status == AUTH_NOT_FOUND) break;
        if (status != AUTH_OK) return status;
        if (found.creation_order > newest) newest = found.creation_order;
        if (found.discoverable && memcmp(found.rp_id_hash, metadata->rp_id_hash, 32U) == 0 &&
            found.user_id_length == metadata->user_id_length && memcmp(found.user_id, metadata->user_id, found.user_id_length) == 0) {
            if (replacing) return AUTH_BAD_DATA;
            old = found; replacing = true;
        }
    }
    if (total == service->storage.capacity && !replacing) return AUTH_CAPACITY;
    if (newest == UINT64_MAX) return AUTH_CAPACITY;
    AuthCredential created = *metadata;
    created.key = (AuthKeyHandle){0}; memset(created.credential_id, 0, 32U);
    created.algorithm = AUTH_COSE_ALG_ES256; created.signature_count = 0U;
    created.discoverable = true; created.creation_order = newest + 1U;
    bool unique = false;
    for (unsigned i = 0U; i < 8U; ++i) {
        AuthStatus status = service->crypto.random(service->crypto.context, created.credential_id, 32U);
        if (status != AUTH_OK) return status;
        uint8_t nonzero = 0U; for (size_t j = 0U; j < 32U; ++j) nonzero |= created.credential_id[j];
        status = service->storage.read(service->storage.context, created.credential_id, &found);
        if (status == AUTH_NOT_FOUND && nonzero != 0U) { unique = true; break; }
        if (status != AUTH_OK && status != AUTH_NOT_FOUND) return status;
    }
    if (!unique) return AUTH_CRYPTO_ERROR;
    uint8_t state[16], generated[65];
    AuthStatus status = service->crypto.random(service->crypto.context, state, sizeof state);
    if (status != AUTH_OK) return status;
    status = service->crypto.generate_p256(service->crypto.context, &created.key, generated);
    if (status != AUTH_OK) return status;
    if (!auth_key_handle_valid(&created.key) || generated[0] != 4U) {
        (void)service->crypto.destroy_key(service->crypto.context, &created.key); return AUTH_BAD_DATA;
    }
    if (prepare != NULL) status = prepare(context, &created, generated);
    if (status == AUTH_OK)
        status = service->storage.put_resident(service->storage.context, replacing ? old.credential_id : NULL, &created, state);
    auth_secure_zero(state, sizeof state);
    if (status != AUTH_OK) {
        AuthStatus cleanup = service->crypto.destroy_key(service->crypto.context, &created.key);
        return cleanup == AUTH_OK ? status : AUTH_IO_ERROR;
    }
    ++service->metadata_revision;
    if (replacing && service->crypto.destroy_key(service->crypto.context, &old.key) != AUTH_OK) return AUTH_IO_ERROR;
    *credential = created; memcpy(public_key, generated, 65U); return AUTH_OK;
}

AuthStatus auth_credentials_update_user(AuthCredentialService *service, const AuthCredential *credential)
{
    if (!auth_credentials_resident_supported(service) || !auth_credential_valid(credential) || !credential->discoverable ||
        service->metadata_revision == UINT64_MAX) return AUTH_INVALID_ARGUMENT;
    AuthCredential old;
    AuthStatus status = auth_credentials_get(service, credential->credential_id, credential->rp_id_hash, &old);
    if (status != AUTH_OK) return status;
    if (!old.discoverable || old.user_id_length != credential->user_id_length ||
        memcmp(old.user_id, credential->user_id, old.user_id_length) != 0) return AUTH_INVALID_ARGUMENT;
    /* Only editable user names cross the mutation boundary. Preserve binding,
     * key, policy, counter and creation order from the current stored record. */
    memcpy(old.user_name, credential->user_name, sizeof old.user_name);
    old.user_name_length = credential->user_name_length;
    memcpy(old.user_display_name, credential->user_display_name, sizeof old.user_display_name);
    old.user_display_name_length = credential->user_display_name_length;
    uint8_t state[16]; status = service->crypto.random(service->crypto.context, state, sizeof state);
    if (status == AUTH_OK) status = service->storage.update_user(service->storage.context, &old, state);
    auth_secure_zero(state, sizeof state);
    if (status == AUTH_OK) ++service->metadata_revision;
    return status;
}
