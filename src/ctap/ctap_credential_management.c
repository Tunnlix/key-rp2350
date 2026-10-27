#include "ctap/ctap_credential_management.h"
#include "ctap/ctap_entities.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/ctap_request.h"
#include <string.h>

enum {
    CM_GET_METADATA = 1U,
    CM_ENUMERATE_RPS_BEGIN = 2U,
    CM_ENUMERATE_RPS_NEXT = 3U,
    CM_ENUMERATE_CREDENTIALS_BEGIN = 4U,
    CM_ENUMERATE_CREDENTIALS_NEXT = 5U,
    CM_DELETE_CREDENTIAL = 6U,
    CM_UPDATE_USER = 7U
};

/* Borrowed CBOR spans live only during execute; IDs/hashes are copied before
 * authorization. Parsed user metadata belongs to the instance's wiped scratch. */
typedef struct {
    CborValue fields[5];
    bool present[5];
    uint8_t command, id[32], rp_hash[32];
    bool supported_descriptor;
} ManagementRequest;

static bool mutation(uint8_t command)
{
    return command == CM_DELETE_CREDENTIAL || command == CM_UPDATE_USER;
}

static bool has_parameters(uint8_t command)
{
    return command == CM_ENUMERATE_CREDENTIALS_BEGIN || mutation(command);
}

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
    if (state->kind == CM_ENUMERATE_RPS_BEGIN) {
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
            ctap_public_key_write_algorithm(&writer, credential->algorithm, key);
        if (first) ok = ok && cbor_write_uint(&writer, 9U) && cbor_write_uint(&writer, state->count);
        ok = ok && cbor_write_uint(&writer, 10U) && cbor_write_uint(&writer, credential->cred_protect);
    }
    if (!ok || writer.length > capacity) return CTAP_STATUS_OTHER;
    memcpy(output, encoded, writer.length); *length = writer.length; ++state->next;
    return CTAP_STATUS_OK;
}

static uint8_t parse_subcommand(const uint8_t *input, size_t input_length, ManagementRequest *request)
{
    uint8_t status = ctap_request_map(input, input_length, 5U, request->fields, request->present);
    if (status != CTAP_STATUS_OK) return status;
    if (!request->present[1]) return CTAP_STATUS_MISSING_PARAMETER;
    if (request->fields[1].major != 0U || (request->present[2] && request->fields[2].major != 5U) ||
        (request->present[3] && request->fields[3].major != 0U) || (request->present[4] && request->fields[4].major != 2U))
        return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    uint64_t command = request->fields[1].value;
    if (command < CM_GET_METADATA || command > CM_UPDATE_USER) return CTAP_STATUS_INVALID_SUBCOMMAND;
    request->command = (uint8_t)command;
    return CTAP_STATUS_OK;
}

/* Requires the same live token, unchanged metadata and matching sequence kind. */
static uint8_t continue_enumeration(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, uint8_t command,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    uint8_t status;
    uint8_t kind = command == CM_ENUMERATE_RPS_NEXT ? CM_ENUMERATE_RPS_BEGIN : CM_ENUMERATE_CREDENTIALS_BEGIN;
    if (state->kind != kind || state->next >= state->count || pin->faulted || !pin->token_active ||
        (pin->permissions & CTAP_PIN_PERMISSION_CM) == 0U ||
        (pin->token_rp_bound && (kind != CM_ENUMERATE_CREDENTIALS_BEGIN ||
            !ctap_pin_equal(pin->token_rp_hash, state->rp_hash, 32U))) ||
        state->token_generation != pin->token_generation || state->metadata_revision != service->metadata_revision ||
        (uint32_t)(now_ms - state->last_call_ms) > 30000U) {
        ctap_credential_management_clear(state); return CTAP_STATUS_NOT_ALLOWED;
    }
    status = entry(service, state, false, output, capacity, length);
    if (status == CTAP_STATUS_OK) state->last_call_ms = now_ms;
    if (status != CTAP_STATUS_OK || state->next == state->count) ctap_credential_management_clear(state);
    return status;
}

static uint8_t parse_parameters(ManagementRequest *request, CtapCredentialManagement *state)
{
    uint8_t command = request->command, status;
    if (!request->present[4]) return CTAP_STATUS_PUAT_REQUIRED;
    if (!request->present[3] || (has_parameters(command) && !request->present[2])) return CTAP_STATUS_MISSING_PARAMETER;
    CborValue params[4] = {{0}}; bool supplied[4] = {false};
    AuthCredential *updated = &state->scratch.updated_user;
    request->supported_descriptor = true;
    if (request->present[2] && has_parameters(command)) {
        status = ctap_request_map(request->fields[2].encoded, request->fields[2].encoded_length, 4U, params, supplied);
        if (status != CTAP_STATUS_OK) return status;
    }
    /* Required subcommand fields precede protocol and MAC checks (§6.8.4–6). */
    if ((command == CM_ENUMERATE_CREDENTIALS_BEGIN && !supplied[1]) ||
        (mutation(command) && !supplied[2]) || (command == CM_UPDATE_USER && !supplied[3]))
        return CTAP_STATUS_MISSING_PARAMETER;
    if ((request->fields[3].value != 1U && request->fields[3].value != 2U)) return CTAP_STATUS_INVALID_PARAMETER;
    if (request->fields[4].value != ctap_pin_protocol_auth_length((uint8_t)request->fields[3].value)) return CTAP_STATUS_PIN_AUTH_INVALID;
    if (command == CM_ENUMERATE_CREDENTIALS_BEGIN) {
        if (params[1].major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (params[1].value != 32U) return CTAP_STATUS_INVALID_PARAMETER;
        memcpy(request->rp_hash, params[1].data, 32U);
    }
    if (command == CM_DELETE_CREDENTIAL || command == CM_UPDATE_USER) {
        CborValue credential_id, type;
        status = ctap_request_descriptor(&params[2], &credential_id, &type);
        if (status != CTAP_STATUS_OK) return status;
        request->supported_descriptor = cbor_text_equal(&type, "public-key") && credential_id.value == sizeof request->id;
        if (request->supported_descriptor) memcpy(request->id, credential_id.data, sizeof request->id);
        if (command == CM_UPDATE_USER) {
            status = ctap_user_entity_parse(&params[3], updated);
            if (status != CTAP_STATUS_OK) return status;
        }
    }
    return CTAP_STATUS_OK;
}

/* MAC covers the received canonical bytes, never reconstructed parameters.
 * Credential enumeration accepts a token scoped to the requested RP (§6.8.4).
 * Metadata/RP enumeration require unscoped tokens. Mutations check target scope
 * after lookup, before changing anything. */
static uint8_t authorize_request(CtapClientPin *pin, CtapCredentialManagement *state,
    const ManagementRequest *request, uint32_t now_ms)
{
    uint8_t command = request->command;
    uint8_t *message = state->scratch.bytes; message[0] = (uint8_t)command;
    size_t message_length = 1U;
    if (request->present[2] && has_parameters(command)) {
        if (request->fields[2].encoded_length > sizeof state->scratch.bytes - 1U) return CTAP_STATUS_INVALID_LENGTH;
        memcpy(message + 1U, request->fields[2].encoded, request->fields[2].encoded_length); message_length += request->fields[2].encoded_length;
    }
    const uint8_t *scope = command == CM_ENUMERATE_CREDENTIALS_BEGIN ? request->rp_hash :
        (mutation(command) && pin->token_rp_bound ? pin->token_rp_hash : NULL);
    return ctap_client_pin_authorize_management_version(pin, (uint8_t)request->fields[3].value, scope, message, message_length, request->fields[4].data, now_ms);
}

/* Requires successful authorization; no mutation precedes availability,
 * RP scope and user-ID checks. The service atomically commits metadata/state. */
static uint8_t mutate_credential(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const ManagementRequest *request, size_t *length)
{
    uint8_t command = request->command;
    AuthCredential *updated = &state->scratch.updated_user;
    if (!request->supported_descriptor) return CTAP_STATUS_NO_CREDENTIALS;
    AuthCredential *found = &state->scratch.record;
    AuthStatus lookup = service->storage.read(service->storage.context, request->id, found);
    if (lookup == AUTH_NOT_FOUND) return CTAP_STATUS_NO_CREDENTIALS;
    if (lookup != AUTH_OK || !auth_credential_valid(found) || memcmp(found->credential_id, request->id, 32U) != 0) return CTAP_STATUS_OTHER;
    if (!found->discoverable) return CTAP_STATUS_NO_CREDENTIALS;
    if (pin->token_rp_bound && memcmp(pin->token_rp_hash, found->rp_id_hash, 32U) != 0) return CTAP_STATUS_PIN_AUTH_INVALID;
    if (command == CM_DELETE_CREDENTIAL) lookup = auth_credentials_delete(service, request->id, found->rp_id_hash);
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

/* Scope was authenticated before entry; only credential enumeration may use
 * an RP-scoped token. State was cleared before parsing. */
static uint8_t begin_enumeration(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const ManagementRequest *request,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    uint8_t command = request->command;
    size_t resident_count = 0U;
    uint8_t (*rp_hashes)[32] = state->scratch.rp_hashes;
    for (size_t i = 0U; i < service->storage.capacity; ++i) {
        AuthCredential *found = &state->scratch.record;
        /* Use the RP index rather than rereading every other site's metadata
         * for each RP in a manager's unlock/inventory sequence. */
        AuthStatus lookup = command == CM_ENUMERATE_CREDENTIALS_BEGIN ?
            auth_credentials_find_discoverable(service, request->rp_hash, i, found) :
            auth_credentials_enumerate(service, i, found);
        if (lookup == AUTH_NOT_FOUND) break;
        if (lookup != AUTH_OK) { ctap_credential_management_clear(state); return CTAP_STATUS_OTHER; }
        if (!found->discoverable) continue;
        ++resident_count;
        if (command == CM_GET_METADATA) continue;
        if (command == CM_ENUMERATE_CREDENTIALS_BEGIN && memcmp(found->rp_id_hash, request->rp_hash, 32U) != 0) continue;
        if (command == CM_ENUMERATE_RPS_BEGIN) {
            bool duplicate = false;
            for (size_t j = 0U; j < state->count; ++j) if (memcmp(rp_hashes[j], found->rp_id_hash, 32U) == 0) duplicate = true;
            if (duplicate) continue;
            memcpy(rp_hashes[state->count], found->rp_id_hash, 32U);
        }
        memcpy(state->ids[state->count++], found->credential_id, 32U);
    }
    if (command == CM_GET_METADATA) {
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
    state->metadata_revision = service->metadata_revision; state->last_call_ms = now_ms; memcpy(state->rp_hash, request->rp_hash, 32U);
    uint8_t status = entry(service, state, true, output, capacity, length);
    if (status != CTAP_STATUS_OK || state->next == state->count) ctap_credential_management_clear(state);
    return status;
}

static uint8_t execute(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const uint8_t *input, size_t input_length,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (!auth_credentials_resident_supported(service) || pin == NULL || pin->service != service || state == NULL ||
        output == NULL || length == NULL) return CTAP_STATUS_OTHER;
    ManagementRequest request = {0};
    uint8_t status = parse_subcommand(input, input_length, &request);
    if (status != CTAP_STATUS_OK) {
        ctap_credential_management_clear(state);
        return status;
    }
    ctap_client_pin_poll(pin, now_ms);
    if (request.command == CM_ENUMERATE_RPS_NEXT || request.command == CM_ENUMERATE_CREDENTIALS_NEXT)
        return continue_enumeration(service, pin, state, request.command, output, capacity, length, now_ms);
    ctap_credential_management_clear(state);
    status = parse_parameters(&request, state);
    if (status != CTAP_STATUS_OK) return status;
    status = authorize_request(pin, state, &request, now_ms);
    if (status != CTAP_STATUS_OK) return status;
    if (mutation(request.command)) return mutate_credential(service, pin, state, &request, length);
    return begin_enumeration(service, pin, state, &request, output, capacity, length, now_ms);
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
