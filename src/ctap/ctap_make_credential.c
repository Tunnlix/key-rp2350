#include "ctap/ctap_make_credential.h"
#include "ctap/ctap_attestation.h"
#include "ctap/cbor_reader.h"

#include <string.h>

static uint8_t string_keys(const CborValue *map)
{
    if (map->major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    const uint8_t *cursor = map->data, *end = map->encoded + map->encoded_length;
    CborValue key, value;
    for (uint64_t i = 0; i < map->value; ++i) {
        if (!cbor_read_next(&cursor, end, &key) || !cbor_read_next(&cursor, end, &value)) return CTAP_STATUS_INVALID_CBOR;
        if (key.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    return CTAP_STATUS_OK;
}

static uint8_t member(const CborValue *map, const char *name, uint8_t type, bool required, CborValue *value)
{
    if (!cbor_map_text(map, name, value)) return required ? CTAP_STATUS_CBOR_UNEXPECTED_TYPE : CTAP_STATUS_OK;
    return value->major == type ? CTAP_STATUS_OK : CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
}

static bool es256(const CborValue *algorithm)
{ return algorithm->major == 1U && algorithm->value == 6U; }

static uint8_t algorithms(const CborValue *array)
{
    if (array->major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    const uint8_t *cursor = array->data, *end = array->encoded + array->encoded_length;
    CborValue entry, type, algorithm;
    bool supported = false;
    for (uint64_t i = 0; i < array->value; ++i) {
        if (!cbor_read_next(&cursor, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
        uint8_t status = string_keys(&entry);
        if (status != 0U) return status;
        if (!cbor_map_text(&entry, "type", &type) || !cbor_map_text(&entry, "alg", &algorithm)) return CTAP_STATUS_INVALID_CBOR;
        if (type.major != 3U || algorithm.major > 1U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        /* The request array must not contain duplicate entries (6.1). Input
         * bounds the scan; retain no per-entry table on embedded targets. */
        const uint8_t *previous = array->data;
        CborValue earlier;
        for (uint64_t j = 0; j < i; ++j) {
            if (!cbor_read_next(&previous, end, &earlier)) return CTAP_STATUS_INVALID_CBOR;
            if (earlier.encoded_length == entry.encoded_length &&
                memcmp(earlier.encoded, entry.encoded, entry.encoded_length) == 0) return CTAP_STATUS_INVALID_PARAMETER;
        }
        if (cbor_text_equal(&type, "public-key") && es256(&algorithm)) supported = true;
    }
    return supported ? CTAP_STATUS_OK : CTAP_STATUS_UNSUPPORTED_ALGORITHM;
}

static uint8_t exclusions(AuthCredentialService *service, const CborValue *array, CtapMakeCredential *prepared)
{
    if (array->major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (array->value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    const uint8_t *cursor = array->data, *end = array->encoded + array->encoded_length;
    CborValue entry, type, id, transports, transport;
    for (uint64_t i = 0; i < array->value; ++i) {
        if (!cbor_read_next(&cursor, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
        uint8_t status = string_keys(&entry);
        if (status != 0U) return status;
        if (member(&entry, "type", 3U, true, &type) != 0U || member(&entry, "id", 2U, true, &id) != 0U)
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (cbor_map_text(&entry, "transports", &transports)) {
            if (transports.major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            const uint8_t *next = transports.data, *limit = transports.encoded + transports.encoded_length;
            for (uint64_t j = 0; j < transports.value; ++j) {
                if (!cbor_read_next(&next, limit, &transport) || transport.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
        }
        /* Unknown credential types and other authenticators' ID sizes cannot
         * refer to our records. Still validate the entire list before touch. */
        if (cbor_text_equal(&type, "public-key") && id.value == 32U) {
            AuthCredential found;
            AuthStatus lookup = auth_credentials_get(service, id.data, prepared->rp_id_hash, &found);
            if (lookup == AUTH_OK) prepared->credential_excluded = true;
            else if (lookup != AUTH_NOT_FOUND) return CTAP_STATUS_OTHER;
        }
    }
    return CTAP_STATUS_OK;
}

uint8_t ctap_make_credential_prepare(AuthCredentialService *service,
    const uint8_t *parameters, size_t length, CtapMakeCredential *prepared)
{
    if (service == NULL || prepared == NULL) return CTAP_STATUS_OTHER;
    CborValue map, fields[12] = {{0}};
    bool present[12] = {false};
    if (!cbor_read_document(parameters, length, &map)) return CTAP_STATUS_INVALID_CBOR;
    if (map.major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    const uint8_t *cursor = map.data, *end = map.encoded + map.encoded_length;
    CborValue key, value;
    for (uint64_t i = 0; i < map.value; ++i) {
        if (!cbor_read_next(&cursor, end, &key) || !cbor_read_next(&cursor, end, &value)) return CTAP_STATUS_INVALID_CBOR;
        if (key.major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (key.value < 12U) { fields[key.value] = value; present[key.value] = true; }
    }
    for (size_t i = 1U; i <= 4U; ++i) if (!present[i]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value != 32U) return CTAP_STATUS_INVALID_LENGTH;
    uint8_t status = string_keys(&fields[2]);
    if (status != 0U) return status;
    CborValue rp, user;
    status = member(&fields[2], "id", 3U, true, &rp);
    if (status != 0U) return status;
    if (rp.value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    status = member(&fields[2], "name", 3U, false, &value);
    if (status != 0U) return status;
    status = string_keys(&fields[3]);
    if (status != 0U) return status;
    status = member(&fields[3], "id", 2U, true, &user);
    if (status != 0U) return status;
    if (user.value > AUTH_USER_ID_MAX_SIZE) return CTAP_STATUS_INVALID_LENGTH;
    status = member(&fields[3], "name", 3U, false, &value);
    if (status != 0U) return status;
    status = member(&fields[3], "displayName", 3U, false, &value);
    if (status != 0U) return status;
    /* icon is deprecated: intentionally ignored, including its value type. */
    if (present[8]) {
        if (fields[8].major != 2U || (present[9] && fields[9].major != 0U)) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        return present[9] ? CTAP_STATUS_INVALID_PARAMETER : CTAP_STATUS_MISSING_PARAMETER;
    }
    if (present[9] && fields[9].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    status = algorithms(&fields[4]);
    if (status != 0U) return status;
    if (present[7]) {
        status = string_keys(&fields[7]);
        if (status != 0U) return status;
        const char *names[] = {"uv", "rk", "up"};
        bool enabled[3] = {false, false, true};
        for (size_t i = 0; i < 3U; ++i) {
            if (cbor_map_text(&fields[7], names[i], &value)) {
                if (value.major != 7U || (value.encoded[0] != 0xF4U && value.encoded[0] != 0xF5U)) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                enabled[i] = value.encoded[0] == 0xF5U;
            }
        }
        if (enabled[0] || !enabled[2]) return CTAP_STATUS_INVALID_OPTION;
        if (enabled[1]) return CTAP_STATUS_UNSUPPORTED_OPTION;
    }
    if (present[10]) return fields[10].major == 0U ? CTAP_STATUS_INVALID_PARAMETER : CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (present[6]) {
        status = string_keys(&fields[6]);
        if (status != 0U) return status;
    }
    CtapMakeCredential result = {0};
    if (present[11]) {
        if (fields[11].major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        const uint8_t *next = fields[11].data, *limit = fields[11].encoded + fields[11].encoded_length;
        for (uint64_t i = 0; i < fields[11].value; ++i) {
            if (!cbor_read_next(&next, limit, &value) || value.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            if (fields[11].value == 1U && cbor_text_equal(&value, "none")) result.omit_attestation = true;
        }
    }
    memcpy(result.client_data_hash, fields[1].data, 32U);
    result.user_id_length = (size_t)user.value;
    memcpy(result.user_id, user.data, result.user_id_length); /* Empty user.id is valid. */
    if (service->crypto.sha256(service->crypto.context, rp.data, (size_t)rp.value, result.rp_id_hash) != AUTH_OK) return CTAP_STATUS_OTHER;
    if (present[5]) {
        status = exclusions(service, &fields[5], &result);
        if (status != 0U) return status;
    }
    *prepared = result;
    return CTAP_STATUS_OK;
}

uint8_t ctap_make_credential_finish(AuthCredentialService *service,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length)
{
    if (service == NULL || prepared == NULL || aaguid == NULL || output == NULL || length == NULL || capacity < 384U)
        return CTAP_STATUS_OTHER;
    if (prepared->credential_excluded) return CTAP_STATUS_CREDENTIAL_EXCLUDED;
    AuthCredential credential;
    uint8_t public_key[65];
    AuthStatus status = auth_credentials_create(service, prepared->rp_id_hash,
        prepared->user_id, prepared->user_id_length, false, &credential, public_key);
    if (status != AUTH_OK) return status == AUTH_CAPACITY ? CTAP_STATUS_KEY_STORE_FULL : CTAP_STATUS_OTHER;
    if (!ctap_attestation_encode(service, &credential, public_key, prepared->client_data_hash, aaguid,
        prepared->omit_attestation, output, capacity, length)) {
        (void)auth_credentials_delete(service, credential.credential_id, credential.rp_id_hash);
        return CTAP_STATUS_OTHER;
    }
    return CTAP_STATUS_OK;
}
