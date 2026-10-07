#include "ctap/ctap_get_assertion.h"
#include "ctap/ctap_request.h"
#include "ctap/cbor_writer.h"
#include "ctap/ctap_entities.h"

#include <string.h>

uint8_t ctap_get_assertion_prepare(AuthCredentialService *service,
    const uint8_t *parameters, size_t length, CtapGetAssertion *prepared)
{
    return ctap_get_assertion_prepare_with_pin(service, NULL, 0U, parameters, length, prepared);
}

uint8_t ctap_get_assertion_prepare_with_pin(AuthCredentialService *service, CtapClientPin *pin,
    uint32_t now_ms, const uint8_t *parameters, size_t length, CtapGetAssertion *prepared)
{
    if (service == NULL || prepared == NULL || (pin != NULL && pin->service != service)) return CTAP_STATUS_OTHER;
    CborValue fields[8] = {{0}}, value;
    bool present[8] = {false};
    uint8_t status = ctap_request_map(parameters, length, 8U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    CtapGetAssertion result = {0}; result.pin = pin; result.user_presence_required = true;
    status = ctap_pin_auth_parse(pin, present[6] ? &fields[6] : NULL, present[7] ? &fields[7] : NULL, &result.auth);
    if (status != CTAP_STATUS_OK) return status;
    if (result.auth.probe) { *prepared = result; return CTAP_STATUS_OK; }
    if (!present[1] || !present[2]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 3U || fields[2].major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[2].value != 32U) return CTAP_STATUS_INVALID_LENGTH;
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
        if (enabled[0] && !result.auth.present) return CTAP_STATUS_INVALID_OPTION;
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
    status = ctap_client_pin_authorize(pin, &result.auth, result.rp_id_hash, result.client_data_hash,
        CTAP_PIN_PERMISSION_GA, now_ms, false);
    if (status != CTAP_STATUS_OK) return status;
    result.user_verified = result.auth.present;
    if (!present[3]) {
        if (pin == NULL || !auth_credentials_resident_supported(service)) return CTAP_STATUS_NO_CREDENTIALS;
        uint64_t order[AUTH_RESIDENT_MAX_COUNT] = {0};
        for (size_t i = 0U; i < service->storage.capacity; ++i) {
            AuthCredential found; AuthStatus lookup = auth_credentials_enumerate(service, i, &found);
            if (lookup == AUTH_NOT_FOUND) break;
            if (lookup != AUTH_OK) return CTAP_STATUS_OTHER;
            if (!found.discoverable || memcmp(found.rp_id_hash, result.rp_id_hash, 32U) != 0 ||
                (found.cred_protect != 1U && !result.user_verified)) continue;
            for (size_t j = 0U; j < result.credential_count; ++j)
                if (memcmp(result.credential_ids[j], found.credential_id, 32U) == 0) return CTAP_STATUS_OTHER;
            size_t slot = result.credential_count++;
            while (slot != 0U && order[slot - 1U] < found.creation_order) {
                memcpy(result.credential_ids[slot], result.credential_ids[slot - 1U], 32U);
                order[slot] = order[slot - 1U]; --slot;
            }
            memcpy(result.credential_ids[slot], found.credential_id, 32U); order[slot] = found.creation_order;
        }
        if (result.credential_count == 0U) return CTAP_STATUS_NO_CREDENTIALS;
        result.discovery = true; result.metadata_revision = service->metadata_revision;
        memcpy(result.credential_id, result.credential_ids[0], 32U);
        status = ctap_client_pin_authorize(pin, &result.auth, result.rp_id_hash, result.client_data_hash,
            CTAP_PIN_PERMISSION_GA, now_ms, true);
        if (status != CTAP_STATUS_OK) return status;
        *prepared = result; return CTAP_STATUS_OK;
    }
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
        if (lookup == AUTH_OK && !selected && (found.cred_protect != 3U || result.user_verified)) {
            memcpy(result.credential_id, found.credential_id, 32U);
            selected = true;
        } else if (lookup != AUTH_OK && lookup != AUTH_NOT_FOUND) return CTAP_STATUS_OTHER;
    }
    if (!selected) return CTAP_STATUS_NO_CREDENTIALS;
    status = ctap_client_pin_authorize(pin, &result.auth, result.rp_id_hash, result.client_data_hash,
        CTAP_PIN_PERMISSION_GA, now_ms, true);
    if (status != CTAP_STATUS_OK) return status;
    *prepared = result;
    return CTAP_STATUS_OK;
}

uint8_t ctap_get_assertion_finish(AuthCredentialService *service,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length)
{
    if (prepared != NULL && prepared->pin != NULL) return CTAP_STATUS_OTHER;
    return ctap_get_assertion_finish_at(service, prepared, output, capacity, length, 0U);
}

static uint8_t finish(AuthCredentialService *service, const CtapGetAssertion *prepared,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms, bool continuation)
{
    if (service == NULL || prepared == NULL || output == NULL || length == NULL ||
        capacity < (prepared->hmac_secret.requested ? 288U : 192U))
        return CTAP_STATUS_OTHER;
    if (prepared->auth.probe) return ctap_client_pin_probe(prepared->pin);
    if (prepared->user_verified != prepared->auth.present || (prepared->pin != NULL && prepared->pin->service != service))
        return CTAP_STATUS_OTHER;
    if (prepared->discovery && (prepared->metadata_revision != service->metadata_revision || capacity < 768U)) return CTAP_STATUS_OTHER;
    if (!continuation) {
        CtapPinAuth auth = prepared->auth;
        if (auth.present && auth.token_generation == 0U) return CTAP_STATUS_PIN_AUTH_INVALID;
        uint8_t authorized = ctap_client_pin_authorize(prepared->pin, &auth, prepared->rp_id_hash, prepared->client_data_hash,
            CTAP_PIN_PERMISSION_GA, now_ms, false);
        if (authorized != CTAP_STATUS_OK) return authorized;
    }
    AuthCredential credential;
    AuthStatus status = auth_credentials_get(service, prepared->credential_id, prepared->rp_id_hash, &credential);
    if (status != AUTH_OK) return status == AUTH_NOT_FOUND ? CTAP_STATUS_NO_CREDENTIALS : CTAP_STATUS_OTHER;
    if (credential.cred_protect == 3U && !prepared->user_verified) return CTAP_STATUS_NO_CREDENTIALS;
    if (credential.discoverable && capacity < 768U) return CTAP_STATUS_OTHER;
    if (prepared->discovery && (!credential.discoverable || (credential.cred_protect != 1U && !prepared->user_verified)))
        return CTAP_STATUS_NO_CREDENTIALS;
    if (!continuation && prepared->user_presence_required) ctap_client_pin_invalidate(prepared->pin);
    uint8_t extension_output[80]; size_t extension_length = 0U;
    if (prepared->hmac_secret.requested) {
        if (!prepared->user_presence_required) return CTAP_STATUS_UNSUPPORTED_OPTION;
        uint8_t extension_status = ctap_hmac_secret_evaluate(service, &credential, &prepared->hmac_secret,
            prepared->user_verified, extension_output, &extension_length);
        if (extension_status != CTAP_STATUS_OK) return extension_status;
    }
    /* Signed bytes = rpIdHash[32] || flags[1] || counter[4] || clientDataHash[32].
     * Optional encrypted extension map is between counter and clientDataHash.
     * UV reflects authorization; no AT/backup flags for these local credentials. */
    uint8_t signed_data[164], digest[32], signature[72];
    memcpy(signed_data, prepared->rp_id_hash, 32U);
    signed_data[32] = (prepared->user_presence_required ? 1U : 0U) | (prepared->user_verified ? 4U : 0U) |
        (extension_length != 0U ? 0x80U : 0U);
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
    uint8_t encoded[768];
    CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
    /* Canonical response. Resident user handles are included; identifying
     * names require UV and multi-account discovery. Only the first discovery
     * reply includes account count. */
    bool include_user = credential.discoverable;
    bool include_count = prepared->discovery && prepared->credential_count > 1U && !continuation;
    bool ok = cbor_write_map(&writer, 3U + (include_user ? 1U : 0U) + (include_count ? 1U : 0U)) &&
        cbor_write_uint(&writer, 1U) && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "id") && cbor_write_bytes(&writer, prepared->credential_id, 32U) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key") &&
        cbor_write_uint(&writer, 2U) && cbor_write_bytes(&writer, signed_data, data_length) &&
        cbor_write_uint(&writer, 3U) && cbor_write_bytes(&writer, signature, signature_length);
    if (include_user) ok = ok && cbor_write_uint(&writer, 4U) && ctap_user_entity_write(&writer, &credential,
        prepared->user_verified && prepared->discovery && prepared->credential_count > 1U);
    if (include_count) ok = ok && cbor_write_uint(&writer, 5U) && cbor_write_uint(&writer, prepared->credential_count);
    if (!ok || writer.length > capacity) return CTAP_STATUS_OTHER;
    memcpy(output, encoded, writer.length);
    *length = writer.length;
    return CTAP_STATUS_OK;
}

uint8_t ctap_get_assertion_finish_at(AuthCredentialService *service, const CtapGetAssertion *prepared,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    return finish(service, prepared, output, capacity, length, now_ms, false);
}

void ctap_assertion_sequence_clear(CtapAssertionSequence *sequence)
{ if (sequence != NULL) auth_secure_zero(sequence, sizeof *sequence); }

void ctap_assertion_sequence_begin(CtapAssertionSequence *sequence, const CtapGetAssertion *request, uint32_t now_ms)
{
    ctap_assertion_sequence_clear(sequence);
    if (sequence == NULL || request == NULL || !request->discovery || request->credential_count <= 1U ||
        request->credential_count > AUTH_RESIDENT_MAX_COUNT) return;
    sequence->request = *request; sequence->next = 1U; sequence->last_call_ms = now_ms; sequence->active = true;
}

uint8_t ctap_get_next_assertion(AuthCredentialService *service, CtapAssertionSequence *sequence,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (service == NULL || sequence == NULL || !sequence->active || sequence->next >= sequence->request.credential_count ||
        sequence->request.credential_count > AUTH_RESIDENT_MAX_COUNT ||
        (uint32_t)(now_ms - sequence->last_call_ms) > 30000U || sequence->request.metadata_revision != service->metadata_revision ||
        (sequence->request.user_verified && (sequence->request.pin == NULL || sequence->request.pin->faulted ||
            !sequence->request.pin->pin_set || sequence->request.pin->token_generation != sequence->request.auth.token_generation))) {
        ctap_assertion_sequence_clear(sequence); return CTAP_STATUS_NOT_ALLOWED;
    }
    CtapGetAssertion request = sequence->request;
    memcpy(request.credential_id, request.credential_ids[sequence->next], 32U);
    uint8_t status = finish(service, &request, output, capacity, length, now_ms, true);
    if (status == CTAP_STATUS_OK) {
        ++sequence->next; sequence->last_call_ms = now_ms;
        if (sequence->next == sequence->request.credential_count) ctap_assertion_sequence_clear(sequence);
    } else ctap_assertion_sequence_clear(sequence);
    return status;
}
