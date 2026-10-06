#include "protocol/ctaphid_ctap_backend.h"

#include <string.h>

bool ctaphid_ctap_backend_init(CtaphidCtapBackend *backend,
    const CtapGetInfoProfile *profile)
{
    if (backend == NULL || profile == NULL ||
        profile->max_message_size != CTAPHID_MAX_MESSAGE_SIZE) return false;
    CtapGetInfoProfile copied = *profile;
    memset(backend, 0, sizeof *backend);
    backend->profile = copied;
    backend->profile.make_credential = false; /* Only binding enables this claim. */
    backend->presence_timeout_ms = CTAP_USER_PRESENCE_DEFAULT_TIMEOUT_MS;
    return true;
}

bool ctaphid_ctap_backend_configure_credentials(CtaphidCtapBackend *backend,
    AuthCredentialService *service)
{
    if (backend == NULL || service == NULL || backend->pending || backend->credentials != NULL ||
        !backend->profile.user_presence) return false;
    backend->credentials = service;
    backend->profile.make_credential = true;
    return true;
}

bool ctaphid_ctap_backend_configure_reset(CtaphidCtapBackend *backend,
    uint32_t powered_at_ms, CtapResetStorage reset_storage, void *storage_context)
{
    if (backend == NULL || backend->pending || backend->reset_configured) return false;
    ctap_reset_init(&backend->reset, powered_at_ms, reset_storage, storage_context);
    backend->reset_configured = true;
    return true;
}

void ctaphid_ctap_backend_start(void *context, uint64_t operation_id,
    const uint8_t *request, size_t request_length)
{
    CtaphidCtapBackend *backend = context;
    backend->operation_id = operation_id;
    backend->presence_started = false;
    backend->awaiting_make_credential = false;
    memset(&backend->make_credential, 0, sizeof backend->make_credential);
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_MAKE_CREDENTIAL && backend->credentials != NULL) {
        uint8_t status = ctap_make_credential_prepare(backend->credentials, request + 1U,
            request_length - 1U, &backend->make_credential);
        backend->awaiting_make_credential = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_make_credential;
        backend->awaiting_reset = backend->reset_authorized = false;
        backend->response[0] = status;
        backend->response_length = backend->awaiting_presence ? 0U : 1U;
        backend->pending = true;
        return;
    }
    CtapExecutionResult execution = ctap_execute(&backend->profile, request, request_length,
        backend->response, sizeof backend->response, &backend->response_length);
    backend->awaiting_reset = execution == CTAP_EXECUTION_WAIT_FACTORY_RESET;
    backend->reset_authorized = false;
    backend->awaiting_presence = execution == CTAP_EXECUTION_WAIT_USER_PRESENCE || backend->awaiting_reset;
    if (backend->awaiting_presence) backend->response_length = 0U;
    else if (execution == CTAP_EXECUTION_ERROR) {
        backend->response[0] = CTAP_STATUS_OTHER;
        backend->response_length = 1U;
    }
    backend->pending = true;
}

void ctaphid_ctap_backend_abort(void *context, uint64_t operation_id)
{
    CtaphidCtapBackend *backend = context;
    if (backend->pending && backend->operation_id == operation_id) {
        backend->pending = false;
        backend->response_length = 0U;
        backend->awaiting_presence = false;
        backend->presence_started = false;
        ctap_user_presence_abort(&backend->presence, operation_id);
        ctap_reset_abort(&backend->reset, operation_id);
        backend->awaiting_reset = backend->reset_authorized = false;
        backend->awaiting_make_credential = false;
        memset(&backend->make_credential, 0, sizeof backend->make_credential);
    }
}

CtaphidDeviceResult ctaphid_ctap_backend_poll(CtaphidCtapBackend *backend,
    CtaphidDevice *device, uint32_t now_ms)
{
    if (backend == NULL || device == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    if (!backend->pending) {
        ctap_reset_poll(&backend->reset, now_ms);
        return CTAPHID_DEVICE_OK;
    }
    if (!device->cbor_running || device->phase != CTAPHID_DEVICE_PROCESSING ||
        device->transaction_id != backend->operation_id) {
        ctaphid_ctap_backend_abort(backend, backend->operation_id);
        return CTAPHID_DEVICE_IGNORED;
    }
    if (backend->awaiting_reset && !backend->reset_authorized) {
        uint8_t allowed = ctap_reset_authorize(&backend->reset, backend->operation_id,
            device->reassembler.last_activity_time_ms);
        if (allowed == CTAP_STATUS_OK) backend->reset_authorized = true;
        else {
            backend->awaiting_presence = false;
            backend->response[0] = allowed;
            backend->response_length = 1U;
        }
    }
    ctap_reset_poll(&backend->reset, now_ms);
    if (backend->awaiting_presence) {
        if (!backend->presence_started) {
            if (!ctap_user_presence_begin(&backend->presence, backend->operation_id,
                now_ms, backend->presence_timeout_ms)) return CTAPHID_DEVICE_INVALID_STATE;
            backend->presence_started = true;
        }
        CtapPresenceResult presence = ctap_user_presence_poll(&backend->presence, now_ms);
        if (presence == CTAP_PRESENCE_WAITING) {
            if (device->keepalive_status != CTAPHID_STATUS_UPNEEDED) {
                return ctaphid_device_set_keepalive(device, backend->operation_id,
                    CTAPHID_STATUS_UPNEEDED, now_ms);
            }
            return CTAPHID_DEVICE_OK;
        }
        backend->response[0] = presence == CTAP_PRESENCE_CONFIRMED ? CTAP_STATUS_OK :
            (presence == CTAP_PRESENCE_DENIED ? CTAP_STATUS_OPERATION_DENIED : CTAP_STATUS_USER_ACTION_TIMEOUT);
        if (presence == CTAP_PRESENCE_CONFIRMED && backend->awaiting_reset) {
            backend->response[0] = ctap_reset_commit(&backend->reset, backend->operation_id, &backend->presence);
        }
        backend->response_length = 1U;
        if (backend->awaiting_make_credential) {
            /* Exclusion waits for UP but returns EXCLUDED even after timeout.
             * Normal registration refusal/timeout is OPERATION_DENIED (6.1.2).
             * A coordinator CANCEL aborts us before reaching this code. */
            uint8_t status = CTAP_STATUS_OPERATION_DENIED;
            size_t encoded_length = 0U;
            if (backend->make_credential.credential_excluded) status = CTAP_STATUS_CREDENTIAL_EXCLUDED;
            else if (presence == CTAP_PRESENCE_CONFIRMED) {
                status = ctap_make_credential_finish(backend->credentials, &backend->make_credential,
                    backend->profile.aaguid, backend->response + 1U, sizeof backend->response - 1U, &encoded_length);
            }
            backend->response[0] = status;
            backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
        }
    }
    CtaphidDeviceResult result = ctaphid_device_complete_cbor(device, backend->operation_id,
        backend->response, backend->response_length);
    backend->pending = false;
    backend->response_length = 0U;
    backend->awaiting_presence = false;
    backend->presence_started = false;
    ctap_user_presence_abort(&backend->presence, backend->operation_id);
    ctap_reset_abort(&backend->reset, backend->operation_id);
    backend->awaiting_reset = backend->reset_authorized = false;
    backend->awaiting_make_credential = false;
    memset(&backend->make_credential, 0, sizeof backend->make_credential);
    return result == CTAPHID_DEVICE_INVALID_STATE ? CTAPHID_DEVICE_IGNORED : result;
}

bool ctaphid_ctap_backend_signal_presence(CtaphidCtapBackend *backend,
    uint64_t operation_id, bool confirmed, uint32_t now_ms)
{
    return backend != NULL && backend->pending && backend->awaiting_presence &&
        ctap_user_presence_signal(&backend->presence, operation_id, confirmed, now_ms);
}
