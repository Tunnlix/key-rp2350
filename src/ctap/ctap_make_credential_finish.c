#include "ctap/ctap_make_credential.h"
#include "ctap/ctap_attestation.h"

#include <string.h>

uint8_t ctap_make_credential_finish(AuthCredentialService *service,
    CtapMakeCredentialWorkspace *workspace,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length)
{
    if (prepared != NULL && prepared->pin != NULL) {
        if (workspace != NULL && !workspace->busy)
            auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
        return CTAP_STATUS_OTHER;
    }
    return ctap_make_credential_finish_at(service, workspace, prepared, aaguid, output, capacity, length, 0U);
}

typedef struct {
    AuthCredentialService *service;
    const CtapMakeCredential *request;
    const uint8_t *aaguid;
    CtapMakeCredentialWorkspace *workspace;
    size_t length, capacity;
    uint8_t status;
} RegistrationResponse;

static AuthStatus prepare_response_id(void *context, const AuthCredential *credential,
    const uint8_t *id,size_t id_length,const uint8_t public_key[65])
{
    RegistrationResponse *response = context;
    AuthCredentialService *service = response->service;
    const CtapMakeCredential *prepared = response->request;
    bool has_secret = false;
    response->status = CTAP_STATUS_OTHER;
    if (prepared->hmac_secret_requested && (!auth_secret_crypto_valid(&service->secrets) ||
        service->secrets.credential_supported(service->secrets.context, &credential->key, &has_secret) != AUTH_OK))
        return AUTH_CRYPTO_ERROR;
    uint8_t secret_output[CTAP_HMAC_SECRET_MAX_ENCRYPTED_SIZE]; size_t secret_length = 0U;
    if (prepared->hmac_secret_mc.requested) {
        response->status = ctap_hmac_secret_evaluate(service, credential, &prepared->hmac_secret_mc,
            prepared->user_verified, secret_output, &secret_length);
        if (response->status != CTAP_STATUS_OK) return AUTH_CRYPTO_ERROR;
    }
    response->status = CTAP_STATUS_OTHER;
    uint8_t blob_key[32] = {0};
    if (prepared->large_blob_requested && (service->secrets.large_blob_key == NULL ||
        service->secrets.large_blob_key(service->secrets.context, &credential->key, blob_key) != AUTH_OK)) {
        auth_secure_zero(blob_key, sizeof blob_key); return AUTH_CRYPTO_ERROR;
    }
    bool encoded = ctap_attestation_encode_extensions(service, credential, id, id_length, public_key, prepared->client_data_hash, response->aaguid,
        prepared->omit_attestation, prepared->hmac_secret_requested ? &has_secret : NULL,
        prepared->user_verified, prepared->cred_protect_requested, secret_output, secret_length,
        prepared->cred_blob_requested ? &prepared->cred_blob_stored : NULL,
        prepared->large_blob_requested ? blob_key : NULL,
        response->workspace->scratch.finish.encoded, sizeof response->workspace->scratch.finish.encoded, &response->length);
    auth_secure_zero(blob_key, sizeof blob_key);
    if (!encoded) return AUTH_CRYPTO_ERROR;
    if (response->length > response->capacity) return AUTH_CAPACITY;
    response->status = CTAP_STATUS_OK;
    return AUTH_OK;
}
static AuthStatus prepare_response(void *context,const AuthCredential *credential,const uint8_t public_key[65])
{
    return prepare_response_id(context,credential,credential->credential_id,AUTH_CREDENTIAL_ID_SIZE,public_key);
}

static uint8_t finish_at(AuthCredentialService *service,
    CtapMakeCredentialWorkspace *workspace,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (service == NULL || prepared == NULL || aaguid == NULL || output == NULL || length == NULL ||
        capacity < (prepared->hmac_secret_mc.requested ? 512U : 384U))
        return CTAP_STATUS_OTHER;
    if (prepared->auth.probe) return ctap_client_pin_probe(prepared->pin);
    if (prepared->user_verified != prepared->auth.present || (prepared->pin != NULL && prepared->pin->service != service))
        return CTAP_STATUS_OTHER;
    CtapPinAuth auth = prepared->auth;
    if (auth.present && auth.token_generation == 0U) return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t authorized = ctap_client_pin_authorize(prepared->pin, &auth, prepared->rp_id_hash, prepared->client_data_hash,
        CTAP_PIN_PERMISSION_MC, now_ms, false);
    if (authorized != CTAP_STATUS_OK) return authorized;
    if (prepared->credential_excluded) {
        ctap_client_pin_invalidate(prepared->pin);
        return CTAP_STATUS_CREDENTIAL_EXCLUDED;
    }
    ctap_client_pin_invalidate(prepared->pin); /* Fresh UP consumes MC/GA and UV state. */
    if (prepared->extension_status != CTAP_STATUS_OK) return prepared->extension_status;
    if (prepared->hmac_secret_mc.requested) {
        uint8_t validated = ctap_hmac_secret_validate(service, &prepared->hmac_secret_mc);
        if (validated != CTAP_STATUS_OK) return validated;
    }
    AuthCredential *credential = &workspace->scratch.finish.credential;
    uint8_t *public_key = workspace->scratch.finish.public_key;
    AuthStatus status;
    RegistrationResponse response = {service, prepared, aaguid, workspace, 0U, capacity, CTAP_STATUS_OK};
    if (prepared->discoverable) {
        status = auth_credentials_create_resident_prepared(service, &prepared->metadata,
            prepare_response, &response, credential, public_key);
    } else if(auth_credentials_nonresident_supported(service)) {
        status=auth_credentials_create_nonresident_algorithm(service,prepared->algorithm,prepared->rp_id_hash,
            prepared->cred_protect==0U ? 1U : prepared->cred_protect,prepare_response_id,&response,
            credential,workspace->scratch.finish.wire_id,&workspace->scratch.finish.wire_id_length,public_key);
    } else {
        status = auth_credentials_create_protected_algorithm(service, prepared->algorithm, prepared->rp_id_hash,
            prepared->user_id, prepared->user_id_length, false,
            prepared->cred_protect == 0U ? 1U : prepared->cred_protect, credential, public_key);
        if (status == AUTH_OK && prepare_response(&response, credential, public_key) != AUTH_OK) {
            if (auth_credentials_delete(service, credential->credential_id, credential->rp_id_hash) != AUTH_OK)
                return CTAP_STATUS_OTHER;
            return response.status;
        }
    }
    if (status != AUTH_OK) {
        if (status == AUTH_IO_ERROR) return CTAP_STATUS_OTHER;
        if (response.status != CTAP_STATUS_OK) return response.status;
        return status == AUTH_CAPACITY ? CTAP_STATUS_KEY_STORE_FULL : CTAP_STATUS_OTHER;
    }
    memcpy(output, workspace->scratch.finish.encoded, response.length); *length = response.length;
    return CTAP_STATUS_OK;
}

uint8_t ctap_make_credential_finish_at(AuthCredentialService *service,
    CtapMakeCredentialWorkspace *workspace,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (workspace == NULL || workspace->busy) return CTAP_STATUS_OTHER;
    workspace->busy = true;
    uint8_t status = finish_at(service, workspace, prepared, aaguid, output, capacity, length, now_ms);
    /* Retain the response until commit and publication, then erase partial or
     * complete scratch on every exit. A nested call must leave it intact. */
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    workspace->busy = false;
    auth_credentials_release_nonresident(service);
    return status;
}
