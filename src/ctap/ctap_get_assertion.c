#include "ctap/ctap_get_assertion.h"
#include "ctap/cbor_writer.h"
#include "ctap/ctap_entities.h"

#include <string.h>

static uint8_t finish(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace, const CtapGetAssertion *prepared,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms, bool continuation)
{
    if (service == NULL || prepared == NULL || output == NULL || length == NULL ||
        capacity < (prepared->hmac_secret.requested ? 288U : 192U))
        return CTAP_STATUS_OTHER;
    if (prepared->auth.probe) return ctap_client_pin_probe(prepared->pin);
    if (!auth_credential_id_length_valid(prepared->credential_id_length)) return CTAP_STATUS_OTHER;
    size_t id_extra = prepared->credential_id_length > AUTH_CREDENTIAL_ID_SIZE ?
        prepared->credential_id_length - AUTH_CREDENTIAL_ID_SIZE : 0U;
    if (capacity < (prepared->hmac_secret.requested ? 288U : 192U) + id_extra)
        return CTAP_STATUS_OTHER;
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
    AuthCredential *credential = &workspace->scratch.credential;
    AuthStatus status = auth_credentials_get_id(service, prepared->credential_id,
        prepared->credential_id_length, prepared->rp_id_hash, credential);
    if (status != AUTH_OK) return status == AUTH_NOT_FOUND ? CTAP_STATUS_NO_CREDENTIALS : CTAP_STATUS_OTHER;
    if (credential->cred_protect == 3U && !prepared->user_verified) return CTAP_STATUS_NO_CREDENTIALS;
    if (credential->discoverable && capacity < 768U) return CTAP_STATUS_OTHER;
    if (prepared->discovery && (!credential->discoverable || (credential->cred_protect != 1U && !prepared->user_verified)))
        return CTAP_STATUS_NO_CREDENTIALS;
    if (!continuation && prepared->user_presence_required) ctap_client_pin_invalidate(prepared->pin);
    if (prepared->extension_status != CTAP_STATUS_OK) return prepared->extension_status;
    uint8_t *extension_output = workspace->scratch.phase.finish.extension_output; size_t extension_length = 0U;
    if (prepared->hmac_secret.requested) {
        if (!prepared->user_presence_required) return CTAP_STATUS_UNSUPPORTED_OPTION;
        uint8_t extension_status = ctap_hmac_secret_evaluate(service, credential, &prepared->hmac_secret,
            prepared->user_verified, extension_output, &extension_length);
        if (extension_status != CTAP_STATUS_OK) return extension_status;
    }
    /* Signed bytes = rpIdHash[32] || flags[1] || counter[4] || clientDataHash[32].
     * Optional encrypted extension map is between counter and clientDataHash.
     * UV reflects authorization; no AT/backup flags for these local credentials. */
    uint8_t *signed_data = workspace->scratch.phase.finish.signed_data;
    uint8_t *digest = workspace->scratch.phase.finish.digest;
    uint8_t *signature = workspace->scratch.phase.finish.signature;
    memcpy(signed_data, prepared->rp_id_hash, 32U);
    signed_data[32] = (prepared->user_presence_required ? 1U : 0U) | (prepared->user_verified ? 4U : 0U) |
        (extension_length != 0U ? 0x80U : 0U);
    size_t data_length = 37U;
    if (extension_length != 0U) {
        CborWriter extension; cbor_writer_init(&extension, signed_data + data_length, sizeof workspace->scratch.phase.finish.signed_data - data_length - 32U);
        if (!cbor_write_map(&extension, 1U) || !cbor_write_text(&extension, "hmac-secret") ||
            !cbor_write_bytes(&extension, extension_output, extension_length)) return CTAP_STATUS_OTHER;
        data_length += extension.length;
    }
    uint32_t counter;
    if (auth_credentials_next_counter_id(service, prepared->credential_id, prepared->credential_id_length,
        prepared->rp_id_hash, &counter) != AUTH_OK)
        return CTAP_STATUS_OTHER;
    for (size_t i = 0U; i < 4U; ++i) signed_data[33U + i] = (uint8_t)(counter >> (24U - 8U * i));
    memcpy(signed_data + data_length, prepared->client_data_hash, 32U);
    size_t signature_length = 0U;
    if (service->crypto.sha256(service->crypto.context, signed_data, data_length + 32U, digest) != AUTH_OK ||
        auth_credentials_sign_digest_id(service, prepared->credential_id, prepared->credential_id_length, prepared->rp_id_hash,
            digest, signature, &signature_length) != AUTH_OK || signature_length == 0U || signature_length > sizeof workspace->scratch.phase.finish.signature)
        return CTAP_STATUS_OTHER;
    uint8_t *encoded = workspace->scratch.phase.finish.encoded;
    CborWriter writer; cbor_writer_init(&writer, encoded, sizeof workspace->scratch.phase.finish.encoded);
    /* Canonical response. Resident user handles are included; identifying
     * names require UV and multi-account discovery. Only the first discovery
     * reply includes account count. */
    bool include_user = credential->discoverable;
    bool include_count = prepared->discovery && prepared->credential_count > 1U && !continuation;
    bool ok = cbor_write_map(&writer, 3U + (include_user ? 1U : 0U) + (include_count ? 1U : 0U)) &&
        cbor_write_uint(&writer, 1U) && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "id") && cbor_write_bytes(&writer, prepared->credential_id, prepared->credential_id_length) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key") &&
        cbor_write_uint(&writer, 2U) && cbor_write_bytes(&writer, signed_data, data_length) &&
        cbor_write_uint(&writer, 3U) && cbor_write_bytes(&writer, signature, signature_length);
    if (include_user) ok = ok && cbor_write_uint(&writer, 4U) && ctap_user_entity_write(&writer, credential,
        prepared->user_verified && prepared->discovery && prepared->credential_count > 1U);
    if (include_count) ok = ok && cbor_write_uint(&writer, 5U) && cbor_write_uint(&writer, prepared->credential_count);
    if (!ok || writer.length > capacity) return CTAP_STATUS_OTHER;
    memcpy(output, encoded, writer.length);
    *length = writer.length;
    return CTAP_STATUS_OK;
}

static bool acquire(CtapGetAssertionWorkspace *workspace)
{
    if (workspace == NULL || workspace->busy) return false;
    workspace->busy = true;
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    return true;
}

static uint8_t release(CtapGetAssertionWorkspace *workspace, uint8_t status)
{
    auth_secure_zero(&workspace->scratch, sizeof workspace->scratch);
    workspace->busy = false;
    return status;
}

uint8_t ctap_get_assertion_finish(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length)
{
    if (!acquire(workspace)) return CTAP_STATUS_OTHER;
    uint8_t status = prepared != NULL && prepared->pin != NULL ? CTAP_STATUS_OTHER :
        finish(service, workspace, prepared, output, capacity, length, 0U, false);
    auth_credentials_release_nonresident(service);
    return release(workspace, status);
}

uint8_t ctap_get_assertion_finish_at(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (!acquire(workspace)) return CTAP_STATUS_OTHER;
    uint8_t status=finish(service, workspace, prepared, output, capacity, length, now_ms, false);
    auth_credentials_release_nonresident(service);
    return release(workspace, status);
}

void ctap_assertion_sequence_clear(CtapAssertionSequence *sequence)
{ if (sequence != NULL) auth_secure_zero(sequence, sizeof *sequence); }

void ctap_assertion_sequence_begin(CtapAssertionSequence *sequence, const CtapGetAssertion *request, uint32_t now_ms)
{
    ctap_assertion_sequence_clear(sequence);
    if (sequence == NULL || request == NULL || !request->discovery || request->credential_count <= 1U ||
        request->credential_count > AUTH_RESIDENT_MAX_COUNT) return;
    sequence->request = *request; sequence->next = 1U; sequence->last_call_ms = now_ms; sequence->active = true;
    if (request->user_verified && request->pin != NULL)
        sequence->token_issued_at_ms = request->pin->issued_at_ms;
    ctap_assertion_sequence_poll(sequence, now_ms);
}

void ctap_assertion_sequence_poll(CtapAssertionSequence *sequence, uint32_t now_ms)
{
    if (sequence == NULL || !sequence->active) return;
    const CtapClientPin *pin = sequence->request.pin;
    /* Do not require token_active: a successful UP assertion consumes its
     * permissions before the sequence begins. Preserve the absolute expiry. */
    if ((uint32_t)(now_ms - sequence->last_call_ms) > 30000U ||
        (sequence->request.user_verified && (pin == NULL || pin->faulted || !pin->pin_set ||
            pin->token_generation != sequence->request.auth.token_generation ||
            (uint32_t)(now_ms - sequence->token_issued_at_ms) >= CTAP_PIN_MAX_TIMEOUT_MS)))
        ctap_assertion_sequence_clear(sequence);
}

uint8_t ctap_get_next_assertion(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace, CtapAssertionSequence *sequence,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (!acquire(workspace)) return CTAP_STATUS_OTHER;
    ctap_assertion_sequence_poll(sequence, now_ms);
    if (service == NULL || sequence == NULL || !sequence->active || sequence->next >= sequence->request.credential_count ||
        sequence->request.credential_count > AUTH_RESIDENT_MAX_COUNT ||
        sequence->request.metadata_revision != service->metadata_revision) {
        ctap_assertion_sequence_clear(sequence); return release(workspace, CTAP_STATUS_NOT_ALLOWED);
    }
    CtapGetAssertion *request = &workspace->scratch.request;
    *request = sequence->request;
    memcpy(request->credential_id, request->credential_ids[sequence->next], 32U);
    request->credential_id_length = AUTH_CREDENTIAL_ID_SIZE;
    uint8_t status = finish(service, workspace, request, output, capacity, length, now_ms, true);
    if (status == CTAP_STATUS_OK) {
        ++sequence->next; sequence->last_call_ms = now_ms;
        if (sequence->next == sequence->request.credential_count) ctap_assertion_sequence_clear(sequence);
    } else ctap_assertion_sequence_clear(sequence);
    return release(workspace, status);
}
