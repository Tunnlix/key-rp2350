#include "ctap/ctap_get_assertion.h"
#include "ctap/ctap_request.h"

#include <string.h>

uint8_t ctap_get_assertion_prepare(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    const uint8_t *parameters, size_t length, CtapGetAssertion *prepared)
{
    return ctap_get_assertion_prepare_with_pin(service, workspace, NULL, 0U, parameters, length, prepared);
}

static uint8_t prepare_with_pin(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace, CtapClientPin *pin,
    uint32_t now_ms, const uint8_t *parameters, size_t length, CtapGetAssertion *prepared)
{
    if (service == NULL || prepared == NULL || (pin != NULL && pin->service != service)) return CTAP_STATUS_OTHER;
    CborValue fields[8] = {{0}}, value;
    bool present[8] = {false};
    uint8_t status = ctap_request_map(parameters, length, 8U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    CtapGetAssertion *result = &workspace->scratch.request;
    AuthCredential *found = &workspace->scratch.credential;
    result->pin = pin; result->user_presence_required = true;
    status = ctap_pin_auth_parse(pin, present[6] ? &fields[6] : NULL, present[7] ? &fields[7] : NULL, &result->auth);
    if (status != CTAP_STATUS_OK) return status;
    if (result->auth.probe) { *prepared = *result; return CTAP_STATUS_OK; }
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
        if (enabled[0] && !result->auth.present) return CTAP_STATUS_INVALID_OPTION;
        if (known[1]) return CTAP_STATUS_UNSUPPORTED_OPTION; /* rk is invalid even when false (6.2.2). */
        result->user_presence_required = enabled[2];
    }
    if (present[4]) {
        status = ctap_request_text_map(&fields[4]);
        if (status != CTAP_STATUS_OK) return status;
        if (auth_secret_crypto_valid(&service->secrets) && cbor_map_text(&fields[4], "hmac-secret", &value)) {
            status = ctap_hmac_secret_parse(&value, &result->hmac_secret);
            if (status != CTAP_STATUS_OK) return status;
            if (!result->user_presence_required) return CTAP_STATUS_UNSUPPORTED_OPTION;
        }
        /* Other unsupported extensions and options have no effects/output. */
    }
    if (present[3] && fields[3].major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (present[3] && fields[3].value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
    memcpy(result->client_data_hash, fields[2].data, 32U);
    if (service->crypto.sha256(service->crypto.context, fields[1].data,
        (size_t)fields[1].value, result->rp_id_hash) != AUTH_OK) return CTAP_STATUS_OTHER;
    status = ctap_client_pin_authorize(pin, &result->auth, result->rp_id_hash, result->client_data_hash,
        CTAP_PIN_PERMISSION_GA, now_ms, false);
    if (status != CTAP_STATUS_OK) return status;
    result->user_verified = result->auth.present;
    if (!present[3]) {
        if (pin == NULL || !auth_credentials_resident_supported(service)) return CTAP_STATUS_NO_CREDENTIALS;
        uint64_t *order = workspace->scratch.order;
        for (size_t i = 0U; i < service->storage.capacity; ++i) {
            AuthStatus lookup = auth_credentials_enumerate(service, i, found);
            if (lookup == AUTH_NOT_FOUND) break;
            if (lookup != AUTH_OK) return CTAP_STATUS_OTHER;
            if (!found->discoverable || memcmp(found->rp_id_hash, result->rp_id_hash, 32U) != 0 ||
                (found->cred_protect != 1U && !result->user_verified)) continue;
            for (size_t j = 0U; j < result->credential_count; ++j)
                if (memcmp(result->credential_ids[j], found->credential_id, 32U) == 0) return CTAP_STATUS_OTHER;
            size_t slot = result->credential_count++;
            while (slot != 0U && order[slot - 1U] < found->creation_order) {
                memcpy(result->credential_ids[slot], result->credential_ids[slot - 1U], 32U);
                order[slot] = order[slot - 1U]; --slot;
            }
            memcpy(result->credential_ids[slot], found->credential_id, 32U); order[slot] = found->creation_order;
        }
        if (result->credential_count == 0U) return CTAP_STATUS_NO_CREDENTIALS;
        result->discovery = true; result->metadata_revision = service->metadata_revision;
        memcpy(result->credential_id, result->credential_ids[0], 32U);
        status = ctap_client_pin_authorize(pin, &result->auth, result->rp_id_hash, result->client_data_hash,
            CTAP_PIN_PERMISSION_GA, now_ms, true);
        if (status != CTAP_STATUS_OK) return status;
        *prepared = *result; return CTAP_STATUS_OK;
    }
    const uint8_t *cursor = fields[3].data, *end = fields[3].encoded + fields[3].encoded_length;
    CborValue entry, id, type;
    bool selected = false;
    for (uint64_t i = 0U; i < fields[3].value; ++i) {
        if (!cbor_read_next(&cursor, end, &entry)) return CTAP_STATUS_INVALID_CBOR;
        status = ctap_request_descriptor(&entry, &id, &type);
        if (status != CTAP_STATUS_OK) return status;
        if (!cbor_text_equal(&type, "public-key") || id.value != AUTH_CREDENTIAL_ID_SIZE) continue;
        AuthStatus lookup = auth_credentials_get(service, id.data, result->rp_id_hash, found);
        if (lookup == AUTH_OK && !selected && (found->cred_protect != 3U || result->user_verified)) {
            memcpy(result->credential_id, found->credential_id, 32U);
            selected = true;
        } else if (lookup != AUTH_OK && lookup != AUTH_NOT_FOUND) return CTAP_STATUS_OTHER;
    }
    if (!selected) return CTAP_STATUS_NO_CREDENTIALS;
    status = ctap_client_pin_authorize(pin, &result->auth, result->rp_id_hash, result->client_data_hash,
        CTAP_PIN_PERMISSION_GA, now_ms, true);
    if (status != CTAP_STATUS_OK) return status;
    *prepared = *result;
    return CTAP_STATUS_OK;
}

uint8_t ctap_get_assertion_prepare_with_pin(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    CtapClientPin *pin, uint32_t now_ms, const uint8_t *parameters, size_t length, CtapGetAssertion *prepared)
{
    if (workspace == NULL || workspace->busy) return CTAP_STATUS_OTHER;
    workspace->busy = true;
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    uint8_t status = prepare_with_pin(service, workspace, pin, now_ms, parameters, length, prepared);
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    workspace->busy = false;
    return status;
}
