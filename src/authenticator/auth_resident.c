#include "authenticator/auth_credentials.h"

#include <string.h>

AuthStatus auth_credentials_create_resident(AuthCredentialService *service,
    const AuthCredential *metadata, AuthCredential *credential, uint8_t public_key[65])
{
    return auth_credentials_create_resident_prepared(service, metadata, NULL, NULL, credential, public_key);
}

static AuthStatus create_resident_prepared(AuthCredentialService *service,
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
    AuthResidentScratch *scratch = &service->resident_scratch;
    AuthCredential *found = &scratch->found;
    bool replacing = false; uint64_t newest = 0U;
    size_t total = 0U;
    for (; total < service->storage.capacity; ++total) {
        AuthStatus status = service->storage.enumerate(service->storage.context, total, found);
        if (status == AUTH_NOT_FOUND) break;
        if (status != AUTH_OK) return status;
        if (!auth_credential_valid(found)) return AUTH_BAD_DATA;
        if (found->creation_order > newest) newest = found->creation_order;
        if (found->discoverable && memcmp(found->rp_id_hash, metadata->rp_id_hash, 32U) == 0 &&
            found->user_id_length == metadata->user_id_length && memcmp(found->user_id, metadata->user_id, found->user_id_length) == 0) {
            if (replacing) return AUTH_BAD_DATA;
            memcpy(scratch->old_id, found->credential_id, sizeof scratch->old_id);
            scratch->old_key = found->key; replacing = true;
        }
    }
    if (total == service->storage.capacity && !replacing) return AUTH_CAPACITY;
    if (newest == UINT64_MAX) return AUTH_CAPACITY;
    AuthCredential *created = &scratch->created;
    *created = *metadata;
    created->key = (AuthKeyHandle){0}; memset(created->credential_id, 0, 32U);
    created->algorithm = AUTH_COSE_ALG_ES256; created->signature_count = 0U;
    created->discoverable = true; created->creation_order = newest + 1U;
    bool unique = false;
    for (unsigned i = 0U; i < 8U; ++i) {
        AuthStatus status = service->crypto.random(service->crypto.context, created->credential_id, 32U);
        if (status != AUTH_OK) return status;
        uint8_t nonzero = 0U; for (size_t j = 0U; j < 32U; ++j) nonzero |= created->credential_id[j];
        status = service->storage.read(service->storage.context, created->credential_id, found);
        if (status == AUTH_NOT_FOUND && nonzero != 0U) { unique = true; break; }
        if (status != AUTH_OK && status != AUTH_NOT_FOUND) return status;
    }
    if (!unique) return AUTH_CRYPTO_ERROR;
    uint8_t *state = scratch->store_state, *generated = scratch->public_key;
    AuthStatus status = service->crypto.random(service->crypto.context, state, sizeof scratch->store_state);
    if (status != AUTH_OK) return status;
    status = service->crypto.generate_p256(service->crypto.context, &created->key, generated);
    if (status != AUTH_OK) return status;
    if (!auth_key_handle_valid(&created->key) || generated[0] != 4U) {
        (void)service->crypto.destroy_key(service->crypto.context, &created->key); return AUTH_BAD_DATA;
    }
    if (prepare != NULL) status = prepare(context, created, generated);
    if (status == AUTH_OK)
        status = service->storage.put_resident(service->storage.context, replacing ? scratch->old_id : NULL, created, state);
    auth_secure_zero(state, sizeof scratch->store_state);
    if (status != AUTH_OK) {
        AuthStatus cleanup = service->crypto.destroy_key(service->crypto.context, &created->key);
        return cleanup == AUTH_OK ? status : AUTH_IO_ERROR;
    }
    ++service->metadata_revision;
    if (replacing && service->crypto.destroy_key(service->crypto.context, &scratch->old_key) != AUTH_OK) return AUTH_IO_ERROR;
    *credential = *created; memcpy(public_key, generated, 65U); return AUTH_OK;
}

AuthStatus auth_credentials_create_resident_prepared(AuthCredentialService *service,
    const AuthCredential *metadata, AuthCredentialPrepare prepare, void *context,
    AuthCredential *credential, uint8_t public_key[65])
{
    if (service == NULL || service->resident_busy) return AUTH_INVALID_ARGUMENT;
    service->resident_busy = true;
    AuthStatus status = create_resident_prepared(service, metadata, prepare, context, credential, public_key);
    /* Includes early RNG/provider failures. Nested calls must not clear the
     * outer operation's staged key or replacement metadata. */
    auth_secure_zero(&service->resident_scratch, sizeof service->resident_scratch);
    service->resident_busy = false;
    return status;
}
