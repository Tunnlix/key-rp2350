#include "ctap/ctap_get_assertion.h"
#include "ctap/ctap_request.h"
#include "ctap/cbor_writer.h"

#include <string.h>

uint8_t ctap_get_assertion_prepare(AuthCredentialService *service,
    const uint8_t *parameters, size_t length, CtapGetAssertion *prepared)
{
    if (service == NULL || prepared == NULL) return CTAP_STATUS_OTHER;
    CborValue fields[8] = {{0}}, value;
    bool present[8] = {false};
    uint8_t status = ctap_request_map(parameters, length, 8U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[1] || !present[2]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 3U || fields[2].major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[2].value != 32U) return CTAP_STATUS_INVALID_LENGTH;
    if (present[6]) {
        if (fields[6].major != 2U || (present[7] && fields[7].major != 0U)) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        /* No PIN/UV protocols are supported. Never silently ignore an auth param. */
        return present[7] ? CTAP_STATUS_INVALID_PARAMETER : CTAP_STATUS_MISSING_PARAMETER;
    }
    if (present[7] && fields[7].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    CtapGetAssertion result = {0};
    result.user_presence_required = true;
    if (present[5]) {
        status = ctap_request_text_map(&fields[5]);
        if (status != CTAP_STATUS_OK) return status;
        const char *names[] = {"uv", "rk", "up"};
        bool enabled[3] = {false, false, true}, known[3] = {false};
        for (size_t i = 0U; i < 3U; ++i) {
            if (cbor_map_text(&fields[5], names[i], &value)) {
                known[i] = true;
                if (value.major != 7U || (value.encoded[0] != 0xF4U && value.encoded[0] != 0xF5U))
                    return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                enabled[i] = value.encoded[0] == 0xF5U;
            }
        }
        if (enabled[0]) return CTAP_STATUS_INVALID_OPTION;
        if (known[1]) return CTAP_STATUS_UNSUPPORTED_OPTION; /* rk is invalid even when false (6.2.2). */
        result.user_presence_required = enabled[2];
    }
    if (present[4]) {
        status = ctap_request_text_map(&fields[4]);
        if (status != CTAP_STATUS_OK) return status;
        if (auth_secret_crypto_valid(&service->secrets) && cbor_map_text(&fields[4], "hmac-secret", &value)) {
            status = ctap_hmac_secret_parse(&value, &result.hmac_secret);
            if (status != CTAP_STATUS_OK) return status;
            if (!result.user_presence_required) return CTAP_STATUS_UNSUPPORTED_OPTION;
        }
        /* Other unsupported extensions and options have no effects/output. */
    }
    if (present[3] && fields[3].major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (present[3] && fields[3].value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    memcpy(result.client_data_hash, fields[2].data, 32U);
    if (service->crypto.sha256(service->crypto.context, fields[1].data,
        (size_t)fields[1].value, result.rp_id_hash) != AUTH_OK) return CTAP_STATUS_OTHER;
    if (!present[3]) return CTAP_STATUS_NO_CREDENTIALS;
    const uint8_t *cursor = fields[3].data, *end = fields[3].encoded + fields[3].encoded_length;
    CborValue entry, id, type;
    bool selected = false;
    for (uint64_t i = 0U; i < fields[3].value; ++i) {
        if (!cbor_read_next(&cursor, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
        status = ctap_request_descriptor(&entry, &id, &type);
        if (status != CTAP_STATUS_OK) return status;
        if (!cbor_text_equal(&type, "public-key") || id.value != AUTH_CREDENTIAL_ID_SIZE) continue;
        AuthCredential found;
        AuthStatus lookup = auth_credentials_get(service, id.data, result.rp_id_hash, &found);
        if (lookup == AUTH_OK && !selected) {
            memcpy(result.credential_id, found.credential_id, 32U);
            selected = true;
        } else if (lookup != AUTH_OK && lookup != AUTH_NOT_FOUND) return CTAP_STATUS_OTHER;
    }
    if (!selected) return CTAP_STATUS_NO_CREDENTIALS;
    *prepared = result;
    return CTAP_STATUS_OK;
}

uint8_t ctap_get_assertion_finish(AuthCredentialService *service,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length)
{
    if (service == NULL || prepared == NULL || output == NULL || length == NULL ||
        capacity < (prepared->hmac_secret.requested ? 288U : 192U))
        return CTAP_STATUS_OTHER;
    AuthCredential credential;
    AuthStatus status = auth_credentials_get(service, prepared->credential_id, prepared->rp_id_hash, &credential);
    if (status != AUTH_OK) return status == AUTH_NOT_FOUND ? CTAP_STATUS_NO_CREDENTIALS : CTAP_STATUS_OTHER;
    uint8_t extension_output[80]; size_t extension_length = 0U;
    if (prepared->hmac_secret.requested) {
        if (!prepared->user_presence_required) return CTAP_STATUS_UNSUPPORTED_OPTION;
        uint8_t extension_status = ctap_hmac_secret_evaluate(service, &credential, &prepared->hmac_secret,
            false, extension_output, &extension_length);
        if (extension_status != CTAP_STATUS_OK) return extension_status;
    }
    /* Signed bytes = rpIdHash[32] || flags[1] || counter[4] || clientDataHash[32].
     * Optional encrypted extension map is between counter and clientDataHash.
     * No AT/UV/backup flags: this is a local, non-discoverable credential. */
    uint8_t signed_data[164], digest[32], signature[72];
    memcpy(signed_data, prepared->rp_id_hash, 32U);
    signed_data[32] = (prepared->user_presence_required ? 1U : 0U) | (extension_length != 0U ? 0x80U : 0U);
    size_t data_length = 37U;
    if (extension_length != 0U) {
        CborWriter extension; cbor_writer_init(&extension, signed_data + data_length, sizeof signed_data - data_length - 32U);
        if (!cbor_write_map(&extension, 1U) || !cbor_write_text(&extension, "hmac-secret") ||
            !cbor_write_bytes(&extension, extension_output, extension_length)) return CTAP_STATUS_OTHER;
        data_length += extension.length;
    }
    uint32_t counter;
    if (auth_credentials_next_counter(service, prepared->credential_id, prepared->rp_id_hash, &counter) != AUTH_OK)
        return CTAP_STATUS_OTHER;
    for (size_t i = 0U; i < 4U; ++i) signed_data[33U + i] = (uint8_t)(counter >> (24U - 8U * i));
    memcpy(signed_data + data_length, prepared->client_data_hash, 32U);
    size_t signature_length = 0U;
    if (service->crypto.sha256(service->crypto.context, signed_data, data_length + 32U, digest) != AUTH_OK ||
        auth_credentials_sign_digest(service, prepared->credential_id, prepared->rp_id_hash,
            digest, signature, &signature_length) != AUTH_OK || signature_length == 0U || signature_length > sizeof signature)
        return CTAP_STATUS_OTHER;
    uint8_t encoded[288];
    CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
    /* Only allowList credentials are returned: no user information, enumeration
     * count, userSelected or next-assertion state. Keys are canonical. */
    bool ok = cbor_write_map(&writer, 3U) &&
        cbor_write_uint(&writer, 1U) && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "id") && cbor_write_bytes(&writer, prepared->credential_id, 32U) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key") &&
        cbor_write_uint(&writer, 2U) && cbor_write_bytes(&writer, signed_data, data_length) &&
        cbor_write_uint(&writer, 3U) && cbor_write_bytes(&writer, signature, signature_length);
    if (!ok) return CTAP_STATUS_OTHER;
    memcpy(output, encoded, writer.length);
    *length = writer.length;
    return CTAP_STATUS_OK;
}
