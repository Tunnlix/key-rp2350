#include "ctap/ctap_credential_management.h"
#include "ctap/ctap_entities.h"
#include "ctap/ctap_request.h"
#include <string.h>

void ctap_credential_management_clear(CtapCredentialManagement *state)
{ if (state != NULL) auth_secure_zero(state, sizeof *state); }

static uint8_t entry(AuthCredentialService *service, CtapCredentialManagement *state,
    bool first, uint8_t *output, size_t capacity, size_t *length)
{
    AuthCredential *credential = &state->scratch.record;
    AuthStatus status = service->storage.read(service->storage.context, state->ids[state->next], credential);
    if (status != AUTH_OK || !auth_credential_valid(credential) || !credential->discoverable ||
        memcmp(credential->credential_id, state->ids[state->next], 32U) != 0) return CTAP_STATUS_OTHER;
    uint8_t *encoded = state->scratch.bytes; CborWriter writer;
    cbor_writer_init(&writer, encoded, sizeof state->scratch.bytes);
    bool ok;
    if (state->kind == 2U) {
        ok = cbor_write_map(&writer, first ? 3U : 2U) && cbor_write_uint(&writer, 3U) &&
            ctap_rp_entity_write(&writer, credential) && cbor_write_uint(&writer, 4U) &&
            cbor_write_bytes(&writer, credential->rp_id_hash, 32U);
        if (first) ok = ok && cbor_write_uint(&writer, 5U) && cbor_write_uint(&writer, state->count);
    } else {
        uint8_t key[65];
        if (memcmp(credential->rp_id_hash, state->rp_hash, 32U) != 0 ||
            service->crypto.public_key(service->crypto.context, &credential->key, key) != AUTH_OK) return CTAP_STATUS_OTHER;
        ok = cbor_write_map(&writer, first ? 5U : 4U) && cbor_write_uint(&writer, 6U) &&
            ctap_user_entity_write(&writer, credential, true) && cbor_write_uint(&writer, 7U) &&
            ctap_credential_descriptor_write(&writer, credential->credential_id) && cbor_write_uint(&writer, 8U) &&
            ctap_public_key_write(&writer, key);
        if (first) ok = ok && cbor_write_uint(&writer, 9U) && cbor_write_uint(&writer, state->count);
        ok = ok && cbor_write_uint(&writer, 10U) && cbor_write_uint(&writer, credential->cred_protect);
    }
    if (!ok || writer.length > capacity) return CTAP_STATUS_OTHER;
    memcpy(output, encoded, writer.length); *length = writer.length; ++state->next;
    return CTAP_STATUS_OK;
}

static uint8_t execute(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const uint8_t *input, size_t input_length,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (!auth_credentials_resident_supported(service) || pin == NULL || pin->service != service || state == NULL ||
        output == NULL || length == NULL) return CTAP_STATUS_OTHER;
    CborValue fields[5] = {{0}}; bool present[5] = {false};
    uint8_t status = ctap_request_map(input, input_length, 5U, fields, present);
    if (status != CTAP_STATUS_OK) { ctap_credential_management_clear(state); return status; }
    if (!present[1]) { ctap_credential_management_clear(state); return CTAP_STATUS_MISSING_PARAMETER; }
    if (fields[1].major != 0U || (present[2] && fields[2].major != 5U) ||
        (present[3] && fields[3].major != 0U) || (present[4] && fields[4].major != 2U))
        { ctap_credential_management_clear(state); return CTAP_STATUS_CBOR_UNEXPECTED_TYPE; }
    uint64_t command = fields[1].value;
    if (command < 1U || command > 7U) { ctap_credential_management_clear(state); return CTAP_STATUS_INVALID_SUBCOMMAND; }
    ctap_client_pin_poll(pin, now_ms);
    if (command == 3U || command == 5U) {
        uint8_t kind = command == 3U ? 2U : 4U;
        if (state->kind != kind || state->next >= state->count || pin->faulted || !pin->token_active ||
            (pin->permissions & CTAP_PIN_PERMISSION_CM) == 0U || pin->token_rp_bound ||
            state->token_generation != pin->token_generation || state->metadata_revision != service->metadata_revision ||
            (uint32_t)(now_ms - state->last_call_ms) > 30000U) {
            ctap_credential_management_clear(state); return CTAP_STATUS_NOT_ALLOWED;
        }
        status = entry(service, state, false, output, capacity, length);
        if (status == CTAP_STATUS_OK) state->last_call_ms = now_ms;
        if (status != CTAP_STATUS_OK || state->next == state->count) ctap_credential_management_clear(state);
        return status;
    }
    ctap_credential_management_clear(state);
    if (!present[4]) return CTAP_STATUS_PUAT_REQUIRED;
    if (!present[3] || (command >= 4U && !present[2])) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[3].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[4].value != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
    CborValue params[4] = {{0}}; bool supplied[4] = {false};
    uint8_t id[32] = {0}, rp_hash[32] = {0}; AuthCredential *updated = &state->scratch.updated_user;
    bool supported_descriptor = true;
    if (present[2] && command >= 4U) {
        status = ctap_request_map(fields[2].encoded, fields[2].encoded_length, 4U, params, supplied);
        if (status != CTAP_STATUS_OK) return status;
    }
    if (command == 4U) {
        if (!supplied[1]) return CTAP_STATUS_MISSING_PARAMETER;
        if (params[1].major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (params[1].value != 32U) return CTAP_STATUS_INVALID_PARAMETER;
        memcpy(rp_hash, params[1].data, 32U);
    }
    if (command == 6U || command == 7U) {
        if (!supplied[2] || (command == 7U && !supplied[3])) return CTAP_STATUS_MISSING_PARAMETER;
        CborValue credential_id, type;
        status = ctap_request_descriptor(&params[2], &credential_id, &type);
        if (status != CTAP_STATUS_OK) return status;
        supported_descriptor = cbor_text_equal(&type, "public-key") && credential_id.value == sizeof id;
        if (supported_descriptor) memcpy(id, credential_id.data, sizeof id);
        if (command == 7U) {
            status = ctap_user_entity_parse(&params[3], updated);
            if (status != CTAP_STATUS_OK) return status;
        }
    }
    uint8_t *message = state->scratch.bytes; message[0] = (uint8_t)command;
    size_t message_length = 1U;
    if (present[2] && command >= 4U) {
        if (fields[2].encoded_length > sizeof state->scratch.bytes - 1U) return CTAP_STATUS_INVALID_LENGTH;
        memcpy(message + 1U, fields[2].encoded, fields[2].encoded_length); message_length += fields[2].encoded_length;
    }
    const uint8_t *scope = command >= 6U && pin->token_rp_bound ? pin->token_rp_hash : NULL;
    status = ctap_client_pin_authorize_management(pin, scope, message, message_length, fields[4].data, now_ms);
    if (status != CTAP_STATUS_OK) return status;
    if (command == 6U || command == 7U) {
        /* Authenticate before reporting credential availability (§6.8.5–6).
         * Structurally valid foreign descriptors cannot match local records. */
        if (!supported_descriptor) return CTAP_STATUS_NO_CREDENTIALS;
        AuthCredential *found = &state->scratch.record;
        AuthStatus lookup = service->storage.read(service->storage.context, id, found);
        if (lookup == AUTH_NOT_FOUND) return CTAP_STATUS_NO_CREDENTIALS;
        if (lookup != AUTH_OK || !auth_credential_valid(found) || memcmp(found->credential_id, id, 32U) != 0) return CTAP_STATUS_OTHER;
        if (!found->discoverable) return CTAP_STATUS_NO_CREDENTIALS;
        if (pin->token_rp_bound && memcmp(pin->token_rp_hash, found->rp_id_hash, 32U) != 0) return CTAP_STATUS_PIN_AUTH_INVALID;
        if (command == 6U) lookup = auth_credentials_delete(service, id, found->rp_id_hash);
        else {
            if (found->user_id_length != updated->user_id_length || memcmp(found->user_id, updated->user_id, found->user_id_length) != 0)
                return CTAP_STATUS_INVALID_PARAMETER;
            memcpy(found->user_name, updated->user_name, sizeof found->user_name); found->user_name_length = updated->user_name_length;
            memcpy(found->user_display_name, updated->user_display_name, sizeof found->user_display_name);
            found->user_display_name_length = updated->user_display_name_length;
            lookup = auth_credentials_update_user(service, found);
        }
        if (lookup != AUTH_OK) return lookup == AUTH_CAPACITY ? CTAP_STATUS_KEY_STORE_FULL : CTAP_STATUS_OTHER;
        *length = 0U; return CTAP_STATUS_OK;
    }
    size_t resident_count = 0U;
    uint8_t (*rp_hashes)[32] = state->scratch.rp_hashes;
    for (size_t i = 0U; i < service->storage.capacity; ++i) {
        AuthCredential *found = &state->scratch.record; AuthStatus lookup = auth_credentials_enumerate(service, i, found);
        if (lookup == AUTH_NOT_FOUND) break;
        if (lookup != AUTH_OK) { ctap_credential_management_clear(state); return CTAP_STATUS_OTHER; }
        if (!found->discoverable) continue;
        ++resident_count;
        if (command == 1U) continue;
        if (command == 4U && memcmp(found->rp_id_hash, rp_hash, 32U) != 0) continue;
        if (command == 2U) {
            bool duplicate = false;
            for (size_t j = 0U; j < state->count; ++j) if (memcmp(rp_hashes[j], found->rp_id_hash, 32U) == 0) duplicate = true;
            if (duplicate) continue;
            memcpy(rp_hashes[state->count], found->rp_id_hash, 32U);
        }
        memcpy(state->ids[state->count++], found->credential_id, 32U);
    }
    if (command == 1U) {
        size_t total; if (service->storage.count(service->storage.context, &total) != AUTH_OK || total > service->storage.capacity)
            return CTAP_STATUS_OTHER;
        uint8_t encoded[24]; CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
        if (!cbor_write_map(&writer, 2U) || !cbor_write_uint(&writer, 1U) || !cbor_write_uint(&writer, resident_count) ||
            !cbor_write_uint(&writer, 2U) || !cbor_write_uint(&writer, service->storage.capacity - total) || writer.length > capacity)
            return CTAP_STATUS_OTHER;
        memcpy(output, encoded, writer.length); *length = writer.length; return CTAP_STATUS_OK;
    }
    if (state->count == 0U) return CTAP_STATUS_NO_CREDENTIALS;
    state->kind = (uint8_t)command; state->token_generation = pin->token_generation;
    state->metadata_revision = service->metadata_revision; state->last_call_ms = now_ms; memcpy(state->rp_hash, rp_hash, 32U);
    status = entry(service, state, true, output, capacity, length);
    if (status != CTAP_STATUS_OK || state->next == state->count) ctap_credential_management_clear(state);
    return status;
}

uint8_t ctap_credential_management_execute(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const uint8_t *input, size_t input_length,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (state == NULL) return CTAP_STATUS_OTHER;
    uint8_t status = execute(service, pin, state, input, input_length, output, capacity, length, now_ms);
    /* Enumeration retains only its authenticated snapshot between calls. This
     * common exit also clears partial provider output and rejected requests. */
    auth_secure_zero(&state->scratch, sizeof state->scratch);
    return status;
}
