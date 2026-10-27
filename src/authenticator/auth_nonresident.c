#include "authenticator/auth_credentials.h"

#include <string.h>

AuthStatus auth_credentials_create_nonresident_algorithm(AuthCredentialService *s, int32_t algorithm,
    const uint8_t rp[32],uint8_t policy,AuthCredentialPrepareId prepare,void *context,
    AuthCredential *out,uint8_t id[AUTH_CREDENTIAL_ID_MAX_SIZE],size_t *length,uint8_t pub[65])
{
    if(!auth_credentials_nonresident_supported(s) || s->creation_busy || s->lookup_busy || !rp ||
        !out || !id || !length || !pub || policy<1 || policy>3 || !auth_credentials_algorithm_supported(s, algorithm)) return AUTH_INVALID_ARGUMENT;
    s->creation_busy=true;
    AuthCreationScratch *w=&s->creation_scratch;
    auth_secure_zero(w,sizeof(*w));
    AuthStatus status = algorithm == AUTH_COSE_ALG_ES256 ?
        s->nonresident.create(s->nonresident.context,rp,policy,&w->created,w->wire_id,&w->wire_id_length,w->public_key) :
        s->nonresident.create_ed25519(s->nonresident.context,rp,policy,&w->created,w->wire_id,&w->wire_id_length,w->public_key);
    if(status==AUTH_OK && (!auth_credential_id_length_valid(w->wire_id_length) ||
        w->wire_id_length<=AUTH_CREDENTIAL_ID_SIZE || !auth_credential_valid(&w->created) ||
        w->created.discoverable || w->created.cred_protect!=policy || memcmp(w->created.rp_id_hash,rp,32)!=0 ||
        w->created.algorithm!=algorithm || !auth_public_key_valid(algorithm,w->public_key))) status=AUTH_BAD_DATA;
    uint8_t digest[32]={0};
    if(status==AUTH_OK) status=s->crypto.sha256(s->crypto.context,w->wire_id,w->wire_id_length,digest);
    if(status==AUTH_OK && memcmp(digest,w->created.credential_id,32)!=0) status=AUTH_BAD_DATA;
    if(status==AUTH_OK && prepare) status=prepare(context,&w->created,w->wire_id,w->wire_id_length,w->public_key);
    if(status==AUTH_OK) {
        *out=w->created; memcpy(id,w->wire_id,w->wire_id_length); *length=w->wire_id_length; memcpy(pub,w->public_key,65);
    }
    auth_secure_zero(digest,sizeof digest); auth_secure_zero(w,sizeof(*w));
    s->creation_busy=false; auth_credentials_release_nonresident(s);
    return status;
}

AuthStatus auth_credentials_create_nonresident_prepared(AuthCredentialService *s,
    const uint8_t rp[32], uint8_t policy, AuthCredentialPrepareId prepare, void *context,
    AuthCredential *out, uint8_t id[AUTH_CREDENTIAL_ID_MAX_SIZE], size_t *length, uint8_t pub[65])
{
    return auth_credentials_create_nonresident_algorithm(s, AUTH_COSE_ALG_ES256, rp, policy,
        prepare, context, out, id, length, pub);
}

AuthStatus auth_credentials_create(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, AuthCredential *credential, uint8_t public_key[65])
{
    return auth_credentials_create_protected(service, rp_id_hash, user_id, user_id_length,
        discoverable, 1U, credential, public_key);
}

static AuthStatus create_protected(AuthCredentialService *service, int32_t algorithm,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, uint8_t cred_protect, AuthCredential *credential, uint8_t public_key[65])
{
    if (service == NULL || rp_id_hash == NULL || (user_id == NULL && user_id_length != 0U) || credential == NULL ||
        public_key == NULL || discoverable || user_id_length > AUTH_USER_ID_MAX_SIZE || cred_protect < 1U || cred_protect > 3U)
        return AUTH_INVALID_ARGUMENT;
    if (!auth_credentials_algorithm_supported(service, algorithm)) return AUTH_UNSUPPORTED;
    if (service->metadata_revision == UINT64_MAX) return AUTH_CAPACITY;
    size_t count;
    AuthStatus status = service->storage.count(service->storage.context, &count);
    if (status != AUTH_OK) return status;
    if (count >= service->storage.capacity) return AUTH_CAPACITY;
    AuthCredential *created = &service->creation_scratch.created;
    AuthCredential *existing = &service->creation_scratch.found;
    created->algorithm = algorithm;
    created->discoverable = discoverable;
    created->cred_protect = cred_protect;
    created->user_id_length = (uint8_t)user_id_length;
    if (user_id_length != 0U) memcpy(created->user_id, user_id, user_id_length);
    memcpy(created->rp_id_hash, rp_id_hash, 32U);
    /* Bounded collision handling; storage lookup failure never implies free ID. */
    bool unique = false;
    for (unsigned attempt = 0; attempt < 8U; ++attempt) {
        status = service->crypto.random(service->crypto.context, created->credential_id, 32U);
        if (status != AUTH_OK) return status;
        status = service->storage.read(service->storage.context, created->credential_id, existing);
        if (status == AUTH_NOT_FOUND) {
            uint8_t combined = 0U;
            for (size_t i = 0; i < 32U; ++i) combined |= created->credential_id[i];
            if (combined != 0U) { unique = true; break; }
        } else if (status != AUTH_OK) return status;
    }
    if (!unique) return AUTH_CRYPTO_ERROR;
    uint8_t *generated_public = service->creation_scratch.public_key;
    status = auth_credentials_generate_key(service, algorithm, &created->key, generated_public);
    if (status != AUTH_OK) return status;
    if (!auth_key_handle_valid(&created->key) || !auth_public_key_valid(algorithm, generated_public)) {
        (void)service->crypto.destroy_key(service->crypto.context, &created->key);
        return AUTH_BAD_DATA;
    }
    status = service->storage.insert(service->storage.context, created);
    if (status != AUTH_OK) {
        AuthStatus cleanup = service->crypto.destroy_key(service->crypto.context, &created->key);
        return cleanup == AUTH_OK ? status : AUTH_IO_ERROR;
    }
    *credential = *created;
    ++service->metadata_revision;
    memcpy(public_key, generated_public, 65U);
    return AUTH_OK;
}

AuthStatus auth_credentials_create_protected_algorithm(AuthCredentialService *service, int32_t algorithm,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, uint8_t cred_protect, AuthCredential *credential, uint8_t public_key[65])
{
    if (service == NULL || service->creation_busy || service->lookup_busy) return AUTH_INVALID_ARGUMENT;
    service->creation_busy = true;
    /* Resident and non-resident creation share this workspace; nested creation
     * must not overwrite or clear the active operation's staged key. */
    AuthStatus status = create_protected(service, algorithm, rp_id_hash, user_id, user_id_length,
        discoverable, cred_protect, credential, public_key);
    auth_secure_zero(&service->creation_scratch, sizeof service->creation_scratch);
    service->creation_busy = false;
    return status;
}

AuthStatus auth_credentials_create_protected(AuthCredentialService *service,
    const uint8_t rp[32], const uint8_t *user, size_t length, bool discoverable,
    uint8_t policy, AuthCredential *credential, uint8_t public_key[65])
{
    return auth_credentials_create_protected_algorithm(service, AUTH_COSE_ALG_ES256, rp,
        user, length, discoverable, policy, credential, public_key);
}
