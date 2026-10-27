#include "ctap/ctap_make_credential.h"
#include "ctap/cbor_reader.h"
#include "ctap/ctap_request.h"
#include "ctap/ctap_entities.h"

#include <string.h>

static uint8_t member(const CborValue *map, const char *name, uint8_t type, bool required, CborValue *value)
{
    if (!cbor_map_text(map, name, value)) return required ? CTAP_STATUS_CBOR_UNEXPECTED_TYPE : CTAP_STATUS_OK;
    return value->major == type ? CTAP_STATUS_OK : CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
}

static uint8_t algorithms(AuthCredentialService *service, const CborValue *array, int32_t *selected)
{
    if (array->major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    const uint8_t *cursor = array->data, *end = array->encoded + array->encoded_length;
    CborValue entry, type, algorithm;
    bool supported = false;
    for (uint64_t i = 0; i < array->value; ++i) {
        if (!cbor_read_next(&cursor, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
        uint8_t status = ctap_request_text_map(&entry);
        if (status != 0U) return status;
        if (!cbor_map_text(&entry, "type", &type) || !cbor_map_text(&entry, "alg", &algorithm)) return CTAP_STATUS_INVALID_CBOR;
        if (type.major != 3U || algorithm.major > 1U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        /* Keep duplicate rejection based on type/alg, ignoring unknown members.
         * Input bounds the scan; retain no per-entry table on embedded targets. */
        const uint8_t *previous = array->data;
        CborValue earlier;
        for (uint64_t j = 0; j < i; ++j) {
            /* Reuse the entry view now that type/algorithm retain our fields.
             * Earlier entries have already passed field/type validation. */
            if (!cbor_read_next(&previous, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
            if (!cbor_map_text(&entry, "alg", &earlier)) return CTAP_STATUS_INVALID_CBOR;
            bool same_algorithm = earlier.major == algorithm.major && earlier.value == algorithm.value;
            if (!cbor_map_text(&entry, "type", &earlier)) return CTAP_STATUS_INVALID_CBOR;
            if (same_algorithm && earlier.value == type.value &&
                memcmp(earlier.data, type.data, (size_t)type.value) == 0) return CTAP_STATUS_INVALID_PARAMETER;
        }
        if (!supported && cbor_text_equal(&type, "public-key") && algorithm.major == 1U && algorithm.value <= INT32_MAX) {
            int32_t candidate = -1 - (int32_t)algorithm.value;
            if (auth_credentials_algorithm_supported(service, candidate)) {
                *selected = candidate; supported = true;
            }
        }
    }
    return supported ? CTAP_STATUS_OK : CTAP_STATUS_UNSUPPORTED_ALGORITHM;
}

static uint8_t exclusions(AuthCredentialService *service, const CborValue *array, CtapMakeCredential *prepared, AuthCredential *found)
{
    if (array->major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (array->value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    const uint8_t *cursor = array->data, *end = array->encoded + array->encoded_length;
    CborValue entry, type, id;
    for (uint64_t i = 0; i < array->value; ++i) {
        if (!cbor_read_next(&cursor, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
        uint8_t status = ctap_request_descriptor(&entry, &id, &type);
        if (status != 0U) return status;
        /* Unknown credential types and other authenticators' ID sizes cannot
         * refer to our records. Still validate the entire list before touch. */
        if (cbor_text_equal(&type, "public-key") && id.value != 0U && id.value <= AUTH_CREDENTIAL_ID_MAX_SIZE) {
            AuthStatus lookup = auth_credentials_get_id(service, id.data, (size_t)id.value, prepared->rp_id_hash, found);
            if (lookup == AUTH_OK && (found->cred_protect != 3U || prepared->user_verified)) prepared->credential_excluded = true;
            else if (lookup == AUTH_OK) continue;
            else if (lookup != AUTH_NOT_FOUND) return CTAP_STATUS_OTHER;
        }
    }
    return CTAP_STATUS_OK;
}

/* Parse into owned state now; report extension errors only at step 15,
 * after authorization, exclusion and presence (CTAP 2.3 §6.1.2). */
static uint8_t parse_extensions(AuthCredentialService *service, CtapClientPin *pin,
    const CborValue *extensions, CtapMakeCredential *result)
{
    CborValue value;
    uint8_t status;
    if (auth_credentials_resident_supported(service) && cbor_map_text(extensions, "credBlob", &value)) {
        if (value.major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        result->cred_blob_requested = true;
        result->cred_blob_stored = result->discoverable && value.value <= 32U;
        if (result->cred_blob_stored) {
            result->metadata.cred_blob_length = (uint8_t)value.value;
            memcpy(result->metadata.cred_blob, value.data, (size_t)value.value);
        }
    }
    if (service->large_blobs && service->secrets.large_blob_key != NULL && cbor_map_text(extensions, "largeBlobKey", &value)) {
        if (value.major != 7U || (value.encoded[0] != 0xf4U && value.encoded[0] != 0xf5U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (value.encoded[0] != 0xf5U || !result->discoverable) return CTAP_STATUS_INVALID_OPTION;
        result->large_blob_requested = result->metadata.large_blob_key = true;
    }
    if (auth_secret_crypto_valid(&service->secrets) && cbor_map_text(extensions, "hmac-secret", &value)) {
        if (value.major != 7U || (value.encoded[0] != 0xF4U && value.encoded[0] != 0xF5U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        result->hmac_secret_requested = value.encoded[0] == 0xF5U;
    }
    if (auth_secret_crypto_valid(&service->secrets) && cbor_map_text(extensions, "hmac-secret-mc", &value)) {
        if (!result->hmac_secret_requested) return CTAP_STATUS_MISSING_PARAMETER;
        status = ctap_hmac_secret_parse(&value, &result->hmac_secret_mc);
        if (status != CTAP_STATUS_OK) return status;
    }
    if (pin != NULL && cbor_map_text(extensions, "minPinLength", &value) &&
        (value.major != 7U || (value.encoded[0] != 0xf4U && value.encoded[0] != 0xf5U)))
        return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (pin != NULL && cbor_map_text(extensions, "credProtect", &value)) {
        if (value.major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (value.value < 1U || value.value > 3U) return CTAP_STATUS_INVALID_PARAMETER;
        result->cred_protect_requested = true; result->cred_protect = (uint8_t)value.value;
    }
    return CTAP_STATUS_OK;
}

uint8_t ctap_make_credential_prepare(AuthCredentialService *service, CtapMakeCredentialWorkspace *workspace,
    const uint8_t *parameters, size_t length, CtapMakeCredential *prepared)
{
    return ctap_make_credential_prepare_with_pin(service, workspace, NULL, 0U, parameters, length, prepared);
}

static uint8_t prepare_with_pin(AuthCredentialService *service, CtapMakeCredentialWorkspace *workspace, CtapClientPin *pin,
    uint32_t now_ms, const uint8_t *parameters, size_t length, CtapMakeCredential *prepared)
{
    if (service == NULL || prepared == NULL || (pin != NULL && pin->service != service)) return CTAP_STATUS_OTHER;
    CborValue value, fields[12] = {{0}};
    bool present[12] = {false};
    uint8_t status = ctap_request_map(parameters, length, 12U, fields, present);
    if (status != 0U) return status;
    CtapMakeCredential *result = &workspace->scratch.prepare.request;
    result->pin = pin; result->cred_protect = 1U;
    status = ctap_pin_auth_parse(pin, present[8] ? &fields[8] : NULL, present[9] ? &fields[9] : NULL, &result->auth);
    if (status != CTAP_STATUS_OK) return status;
    if (result->auth.probe) { *prepared = *result; return CTAP_STATUS_OK; }
    for (size_t i = 1U; i <= 4U; ++i) if (!present[i]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value != 32U) return CTAP_STATUS_INVALID_LENGTH;
    status = ctap_request_text_map(&fields[2]);
    if (status != 0U) return status;
    status = member(&fields[2], "id", 3U, true, &value);
    if (status != 0U) return status;
    if (value.value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    const uint8_t *rp_id = value.data;
    size_t rp_id_length = (size_t)value.value;
    status = member(&fields[2], "name", 3U, false, &value);
    if (status != 0U) return status;
    status = ctap_request_text_map(&fields[3]);
    if (status != 0U) return status;
    status = member(&fields[3], "id", 2U, true, &value);
    if (status != 0U) return status;
    if (value.value > AUTH_USER_ID_MAX_SIZE) return CTAP_STATUS_INVALID_LENGTH;
    const uint8_t *user_id = value.data;
    size_t user_id_length = (size_t)value.value;
    status = member(&fields[3], "name", 3U, false, &value);
    if (status != 0U) return status;
    status = member(&fields[3], "displayName", 3U, false, &value);
    if (status != 0U) return status;
    /* icon is deprecated: intentionally ignored, including its value type. */
    status = algorithms(service, &fields[4], &result->algorithm);
    if (status != 0U) return status;
    if (present[7]) {
        status = ctap_request_text_map(&fields[7]);
        if (status != 0U) return status;
        const char *names[] = {"uv", "rk", "up"};
        bool enabled[3] = {false, false, true};
        for (size_t i = 0; i < 3U; ++i) {
            if (cbor_map_text(&fields[7], names[i], &value)) {
                if (value.major != 7U || (value.encoded[0] != 0xF4U && value.encoded[0] != 0xF5U)) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                enabled[i] = value.encoded[0] == 0xF5U;
            }
        }
        if ((enabled[0] && !result->auth.present) || !enabled[2]) return CTAP_STATUS_INVALID_OPTION;
        if (enabled[1] && (pin == NULL || !auth_credentials_resident_supported(service))) return CTAP_STATUS_UNSUPPORTED_OPTION;
        result->discoverable = enabled[1];
    }
    if (present[10]) return fields[10].major == 0U ? CTAP_STATUS_INVALID_PARAMETER : CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (present[6]) {
        status = ctap_request_text_map(&fields[6]);
        if (status != CTAP_STATUS_OK) return status;
        result->extension_status = parse_extensions(service, pin, &fields[6], result);
    }
    if (present[11]) {
        if (fields[11].major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        const uint8_t *next = fields[11].data, *limit = fields[11].encoded + fields[11].encoded_length;
        for (uint64_t i = 0; i < fields[11].value; ++i) {
            if (!cbor_read_next(&next, limit, &value) || value.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            if (fields[11].value == 1U && cbor_text_equal(&value, "none")) result->omit_attestation = true;
        }
    }
    memcpy(result->client_data_hash, fields[1].data, 32U);
    result->user_id_length = user_id_length;
    memcpy(result->user_id, user_id, result->user_id_length); /* Empty user.id is valid. */
    if (service->crypto.sha256(service->crypto.context, rp_id, rp_id_length, result->rp_id_hash) != AUTH_OK) return CTAP_STATUS_OTHER;
    status = ctap_client_pin_authorize(pin, &result->auth, result->rp_id_hash, result->client_data_hash,
        CTAP_PIN_PERMISSION_MC, now_ms, false);
    if (status != CTAP_STATUS_OK) return status;
    result->user_verified = result->auth.present;
    if (result->discoverable) {
        bool set;
        status = ctap_client_pin_status(pin, &set);
        if (status != CTAP_STATUS_OK) return status;
        if (set && !result->user_verified) return CTAP_STATUS_PUAT_REQUIRED;
        status = ctap_rp_entity_parse(&fields[2], &result->metadata);
        if (status != CTAP_STATUS_OK) return status;
        status = ctap_user_entity_parse(&fields[3], &result->metadata);
        if (status != CTAP_STATUS_OK) return status;
        memcpy(result->metadata.rp_id_hash, result->rp_id_hash, 32U);
        result->metadata.cred_protect = result->cred_protect;
        result->metadata.algorithm = result->algorithm;
    }
    if (present[5]) {
        status = exclusions(service, &fields[5], result, &workspace->scratch.prepare.excluded);
        if (status != 0U) return status;
    }
    status = ctap_client_pin_authorize(pin, &result->auth, result->rp_id_hash, result->client_data_hash,
        CTAP_PIN_PERMISSION_MC, now_ms, true);
    if (status != CTAP_STATUS_OK) return status;
    *prepared = *result;
    return CTAP_STATUS_OK;
}

uint8_t ctap_make_credential_prepare_with_pin(AuthCredentialService *service, CtapMakeCredentialWorkspace *workspace,
    CtapClientPin *pin, uint32_t now_ms, const uint8_t *parameters, size_t length, CtapMakeCredential *prepared)
{
    if (workspace == NULL || workspace->busy) return CTAP_STATUS_OTHER;
    workspace->busy = true;
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    uint8_t status = prepare_with_pin(service, workspace, pin, now_ms, parameters, length, prepared);
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    workspace->busy = false;
    auth_credentials_release_nonresident(service);
    return status;
}
