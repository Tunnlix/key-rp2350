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
    if ((crypto->generate_ed25519 == NULL) != (crypto->sign_ed25519 == NULL)) return false;
    service->crypto = *crypto;
    service->storage = *storage;
    memset(&service->secrets, 0, sizeof service->secrets);
    memset(&service->nonresident, 0, sizeof service->nonresident);
    service->metadata_revision = 0U;
    memset(&service->creation_scratch, 0, sizeof service->creation_scratch);
    service->creation_busy = false;
    memset(&service->lookup_scratch, 0, sizeof service->lookup_scratch);
    service->lookup_busy = false;
    return true;
}

bool auth_credentials_algorithm_supported(const AuthCredentialService *s, int32_t algorithm)
{
    if (s == NULL) return false;
    if (algorithm == AUTH_COSE_ALG_ES256) return true;
    return algorithm == AUTH_COSE_ALG_EDDSA && s->crypto.generate_ed25519 != NULL &&
        s->crypto.sign_ed25519 != NULL && (!auth_credentials_nonresident_supported(s) ||
        s->nonresident.create_ed25519 != NULL);
}

AuthStatus auth_credentials_generate_key(AuthCredentialService *s, int32_t algorithm,
    AuthKeyHandle *key, uint8_t public_key[65])
{
    if (!auth_credentials_algorithm_supported(s, algorithm)) return AUTH_UNSUPPORTED;
    return algorithm == AUTH_COSE_ALG_ES256 ? s->crypto.generate_p256(s->crypto.context, key, public_key) :
        s->crypto.generate_ed25519(s->crypto.context, key, public_key);
}

AuthStatus auth_credentials_sign_key(AuthCredentialService *s, const AuthCredential *credential,
    const uint8_t *message, size_t length, uint8_t signature[72], size_t *n)
{
    if (s == NULL || !auth_credential_valid(credential) || (!message && length) || !signature || !n)
        return AUTH_INVALID_ARGUMENT;
    *n = 0U; auth_secure_zero(signature, 72U);
    AuthStatus status = AUTH_UNSUPPORTED;
    if (credential->algorithm == AUTH_COSE_ALG_ES256) {
        uint8_t digest[32] = {0};
        status = s->crypto.sha256(s->crypto.context, message, length, digest);
        if (status == AUTH_OK) status = s->crypto.sign_p256_digest(s->crypto.context,
            &credential->key, digest, signature, n);
        auth_secure_zero(digest, sizeof digest);
    } else if (s->crypto.sign_ed25519 != NULL) {
        status = s->crypto.sign_ed25519(s->crypto.context, &credential->key, message, length, signature);
        if (status == AUTH_OK) *n = 64U;
    }
    if (status != AUTH_OK || *n == 0U || *n > 72U) {
        auth_secure_zero(signature, 72U); *n = 0U;
        return status == AUTH_OK ? AUTH_BAD_DATA : status;
    }
    return AUTH_OK;
}

bool auth_credentials_nonresident_supported(const AuthCredentialService *s)
{
    return s != NULL && s->nonresident.create != NULL && s->nonresident.read != NULL &&
        s->nonresident.update_counter != NULL && s->nonresident.release != NULL;
}
bool auth_credentials_configure_nonresident(AuthCredentialService *s,const AuthNonresidentProvider *p)
{
    if(s == NULL || p == NULL || s->creation_busy || s->lookup_busy || s->nonresident.create != NULL ||
        p->create == NULL || p->read == NULL || p->update_counter == NULL || p->release == NULL) return false;
    s->nonresident = *p; return true;
}
void auth_credentials_release_nonresident(AuthCredentialService *s)
{
    if(auth_credentials_nonresident_supported(s) && !s->creation_busy && !s->lookup_busy)
        s->nonresident.release(s->nonresident.context);
}

bool auth_credentials_configure_secrets(AuthCredentialService *service,
    const AuthSecretCrypto *secrets)
{
    if (service == NULL || !auth_secret_crypto_valid(secrets) ||
        auth_secret_crypto_valid(&service->secrets)) return false;
    service->secrets = *secrets;
    return true;
}

/* One owner keeps the record live across lookup and its dependent action.
 * Public APIs do not call each other while this workspace is held. */
static bool lookup_begin(AuthCredentialService *service)
{
    if (service == NULL || service->lookup_busy) return false;
    service->lookup_busy = true;
    return true;
}

static AuthStatus lookup_end(AuthCredentialService *service, AuthStatus status)
{
    auth_secure_zero(&service->lookup_scratch, sizeof service->lookup_scratch);
    service->lookup_busy = false;
    return status;
}

/* Requires lookup ownership; only validated RP-bound records reach callers. */
static AuthStatus lookup_record(AuthCredentialService *service,
    const uint8_t *id, size_t id_length, const uint8_t rp_hash[32])
{
    if (!auth_credential_id_length_valid(id_length)) return AUTH_NOT_FOUND;
    AuthCredential *found = &service->lookup_scratch;
    bool sealed = id_length != AUTH_CREDENTIAL_ID_SIZE;
    if(sealed && !auth_credentials_nonresident_supported(service)) return AUTH_NOT_FOUND;
    AuthStatus status = sealed ? service->nonresident.read(service->nonresident.context,id,id_length,rp_hash,found) :
        service->storage.read(service->storage.context, id, found);
    if (status != AUTH_OK) return status;
    if (!auth_credential_valid(found) || (sealed && found->discoverable)) return AUTH_BAD_DATA;
    uint8_t digest[32];
    if(sealed) {
        status = service->crypto.sha256(service->crypto.context,id,id_length,digest);
        if(status != AUTH_OK) { auth_secure_zero(digest,sizeof digest); return status; }
    }
    bool matches = memcmp(found->credential_id,sealed ? digest : id,32U) == 0;
    auth_secure_zero(digest,sizeof digest);
    if(!matches) return AUTH_BAD_DATA;
    if (memcmp(found->rp_id_hash, rp_hash, 32U) != 0) return AUTH_NOT_FOUND;
    return AUTH_OK;
}

AuthStatus auth_credentials_get(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], AuthCredential *credential)
{
    return auth_credentials_get_id(service, id, AUTH_CREDENTIAL_ID_SIZE, rp_hash, credential);
}

AuthStatus auth_credentials_get_id(AuthCredentialService *service,
    const uint8_t *id, size_t id_length, const uint8_t rp_hash[32], AuthCredential *credential)
{
    if (id == NULL || rp_hash == NULL || credential == NULL || !lookup_begin(service)) return AUTH_INVALID_ARGUMENT;
    AuthStatus status = lookup_record(service, id, id_length, rp_hash);
    if (status == AUTH_OK) *credential = service->lookup_scratch;
    return lookup_end(service, status);
}

AuthStatus auth_credentials_sign_message_id(AuthCredentialService *s, const uint8_t *id, size_t id_length,
    const uint8_t rp_hash[32], const uint8_t *message, size_t length, uint8_t signature[72], size_t *n)
{
    if (!id || !rp_hash || (!message && length) || !signature || !n || !lookup_begin(s)) return AUTH_INVALID_ARGUMENT;
    AuthStatus status = lookup_record(s, id, id_length, rp_hash);
    if (status == AUTH_OK) status = auth_credentials_sign_key(s, &s->lookup_scratch, message, length, signature, n);
    return lookup_end(s, status);
}

AuthStatus auth_credentials_sign_digest(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], const uint8_t digest[32],
    uint8_t signature[72], size_t *signature_length)
{
    return auth_credentials_sign_digest_id(service, id, AUTH_CREDENTIAL_ID_SIZE,
        rp_hash, digest, signature, signature_length);
}

AuthStatus auth_credentials_sign_digest_id(AuthCredentialService *service,
    const uint8_t *id, size_t id_length, const uint8_t rp_hash[32], const uint8_t digest[32],
    uint8_t signature[72], size_t *signature_length)
{
    if (id == NULL || rp_hash == NULL || digest == NULL || signature == NULL || signature_length == NULL ||
        !lookup_begin(service)) return AUTH_INVALID_ARGUMENT;
    AuthStatus status = lookup_record(service, id, id_length, rp_hash);
    if (status == AUTH_OK && service->lookup_scratch.algorithm != AUTH_COSE_ALG_ES256) status = AUTH_UNSUPPORTED;
    if (status == AUTH_OK)
        status = service->crypto.sign_p256_digest(service->crypto.context, &service->lookup_scratch.key,
            digest, signature, signature_length);
    return lookup_end(service, status);
}

AuthStatus auth_credentials_next_counter(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], uint32_t *counter)
{
    return auth_credentials_next_counter_id(service, id, AUTH_CREDENTIAL_ID_SIZE, rp_hash, counter);
}

AuthStatus auth_credentials_next_counter_id(AuthCredentialService *service,
    const uint8_t *id, size_t id_length, const uint8_t rp_hash[32], uint32_t *counter)
{
    if (service == NULL || service->creation_busy || id == NULL || rp_hash == NULL || counter == NULL ||
        !lookup_begin(service)) return AUTH_INVALID_ARGUMENT;
    AuthStatus status = lookup_record(service, id, id_length, rp_hash);
    if (status == AUTH_OK) {
        uint32_t previous = service->lookup_scratch.signature_count;
        if (previous == UINT32_MAX) status = AUTH_CAPACITY;
        else {
            uint32_t next = previous + 1U;
            status = id_length == AUTH_CREDENTIAL_ID_SIZE ?
                service->storage.update_counter(service->storage.context, id, previous, next) :
                service->nonresident.update_counter(service->nonresident.context,id,id_length,rp_hash,previous,next);
            if (status == AUTH_OK) *counter = next;
        }
    }
    return lookup_end(service, status);
}

AuthStatus auth_credentials_delete(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32])
{
    if (service == NULL || service->creation_busy || id == NULL || rp_hash == NULL || !lookup_begin(service))
        return AUTH_INVALID_ARGUMENT;
    AuthStatus status = lookup_record(service, id, AUTH_CREDENTIAL_ID_SIZE, rp_hash);
    if (status != AUTH_OK) return lookup_end(service, status);
    if (service->metadata_revision == UINT64_MAX) return lookup_end(service, AUTH_CAPACITY);
    AuthCredential *credential = &service->lookup_scratch;
    if (credential->discoverable && service->storage.erase_resident != NULL) {
        uint8_t state[16];
        status = service->crypto.random(service->crypto.context, state, sizeof state);
        if (status == AUTH_OK) status = service->storage.erase_resident(service->storage.context, id, state);
        auth_secure_zero(state, sizeof state);
    } else status = service->storage.erase(service->storage.context, id);
    if (status == AUTH_OK) {
        ++service->metadata_revision;
        status = service->crypto.destroy_key(service->crypto.context, &credential->key);
    }
    return lookup_end(service, status);
}

bool auth_credentials_resident_supported(const AuthCredentialService *service)
{
    return service != NULL && service->storage.capacity > 0U && service->storage.capacity <= AUTH_RESIDENT_MAX_COUNT &&
        service->storage.enumerate != NULL && service->storage.put_resident != NULL &&
        service->storage.erase_resident != NULL && service->storage.update_user != NULL;
}

AuthStatus auth_credentials_enumerate(AuthCredentialService *service, size_t index, AuthCredential *credential)
{
    if (service == NULL || credential == NULL || service->storage.enumerate == NULL || !lookup_begin(service))
        return AUTH_INVALID_ARGUMENT;
    AuthCredential *found = &service->lookup_scratch;
    AuthStatus status = service->storage.enumerate(service->storage.context, index, found);
    if (status == AUTH_OK) {
        if (!auth_credential_valid(found)) status = AUTH_BAD_DATA;
        else *credential = *found;
    }
    return lookup_end(service, status);
}

AuthStatus auth_credentials_update_user(AuthCredentialService *service, const AuthCredential *credential)
{
    if (!auth_credentials_resident_supported(service) || service->creation_busy ||
        !auth_credential_valid(credential) || !credential->discoverable ||
        service->metadata_revision == UINT64_MAX || !lookup_begin(service)) return AUTH_INVALID_ARGUMENT;
    AuthCredential *old = &service->lookup_scratch;
    AuthStatus status = lookup_record(service, credential->credential_id, AUTH_CREDENTIAL_ID_SIZE, credential->rp_id_hash);
    if (status != AUTH_OK) return lookup_end(service, status);
    if (!old->discoverable || old->user_id_length != credential->user_id_length ||
        memcmp(old->user_id, credential->user_id, old->user_id_length) != 0)
        return lookup_end(service, AUTH_INVALID_ARGUMENT);
    /* Only editable user names cross the mutation boundary. Preserve binding,
     * key, policy, counter and creation order from the current stored record. */
    memcpy(old->user_name, credential->user_name, sizeof old->user_name);
    old->user_name_length = credential->user_name_length;
    memcpy(old->user_display_name, credential->user_display_name, sizeof old->user_display_name);
    old->user_display_name_length = credential->user_display_name_length;
    uint8_t state[16]; status = service->crypto.random(service->crypto.context, state, sizeof state);
    if (status == AUTH_OK) status = service->storage.update_user(service->storage.context, old, state);
    auth_secure_zero(state, sizeof state);
    if (status == AUTH_OK) ++service->metadata_revision;
    return lookup_end(service, status);
}
