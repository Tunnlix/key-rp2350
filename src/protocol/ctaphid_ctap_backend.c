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
    backend->profile.hmac_secret = false;
    backend->profile.pin_uv_auth = backend->profile.pin_set = false;
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
    backend->profile.hmac_secret = auth_secret_crypto_valid(&service->secrets);
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

bool ctaphid_ctap_backend_configure_pin(CtaphidCtapBackend *backend, CtapClientPin *pin)
{
    if (backend == NULL || pin == NULL || backend->pending || backend->pin != NULL ||
        backend->credentials == NULL || pin->service != backend->credentials || pin->faulted ||
        !backend->reset_configured || backend->reset.reset_storage == NULL) return false;
    backend->pin = pin;
    backend->profile.pin_uv_auth = true;
    backend->profile.pin_set = pin->pin_set;
    return true;
}

void ctaphid_ctap_backend_start(void *context, uint64_t operation_id,
    const uint8_t *request, size_t request_length)
{
    CtaphidCtapBackend *backend = context;
    backend->operation_id = operation_id;
    backend->presence_started = false;
    backend->awaiting_pin = false;
    backend->awaiting_get_info = false;
    backend->awaiting_credential_prepare = false;
    backend->credential_request_length = 0U;
    auth_secure_zero(backend->credential_request, sizeof backend->credential_request);
    auth_secure_zero(&backend->pin_request, sizeof backend->pin_request);
    backend->awaiting_make_credential = false;
    memset(&backend->make_credential, 0, sizeof backend->make_credential);
    backend->awaiting_get_assertion = false;
    memset(&backend->get_assertion, 0, sizeof backend->get_assertion);
    if (request != NULL && request_length == 1U && request[0] == CTAP_COMMAND_GET_INFO && backend->pin != NULL) {
        backend->awaiting_get_info = true;
        backend->awaiting_presence = backend->awaiting_reset = backend->reset_authorized = false;
        backend->response_length = 0U; backend->pending = true; return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_CLIENT_PIN && backend->pin != NULL) {
        uint8_t status = ctap_client_pin_prepare(request + 1U, request_length - 1U, &backend->pin_request);
        backend->awaiting_pin = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_reset = backend->reset_authorized = false;
        backend->response[0] = status;
        backend->response_length = backend->awaiting_pin ? 0U : 1U;
        backend->pending = true;
        return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_CLIENT_PIN &&
        backend->credentials != NULL && backend->profile.hmac_secret) {
        size_t encoded_length = 0U;
        uint8_t status = ctap_hmac_secret_key_agreement(backend->credentials, request + 1U,
            request_length - 1U, backend->response + 1U, sizeof backend->response - 1U, &encoded_length);
        backend->awaiting_presence = backend->awaiting_reset = backend->reset_authorized = false;
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
        backend->pending = true;
        return;
    }
    if (request != NULL && request_length != 0U && backend->pin != NULL &&
        (request[0] == CTAP_COMMAND_MAKE_CREDENTIAL || request[0] == CTAP_COMMAND_GET_ASSERTION)) {
        backend->awaiting_presence = backend->awaiting_reset = backend->reset_authorized = false;
        backend->response_length = 0U;
        if (request_length - 1U > sizeof backend->credential_request) {
            backend->response[0] = CTAP_STATUS_INVALID_LENGTH; backend->response_length = 1U;
        } else {
            backend->prepare_make = request[0] == CTAP_COMMAND_MAKE_CREDENTIAL;
            memcpy(backend->credential_request, request + 1U, request_length - 1U);
            backend->credential_request_length = request_length - 1U;
            backend->awaiting_credential_prepare = true;
        }
        backend->pending = true; return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_GET_ASSERTION && backend->credentials != NULL) {
        uint8_t status = ctap_get_assertion_prepare(backend->credentials, request + 1U,
            request_length - 1U, &backend->get_assertion);
        backend->awaiting_get_assertion = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_get_assertion && backend->get_assertion.user_presence_required;
        backend->awaiting_reset = backend->reset_authorized = false;
        backend->response[0] = status;
        backend->response_length = backend->awaiting_get_assertion ? 0U : 1U;
        backend->pending = true;
        return;
    }
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
        backend->awaiting_pin = false;
        backend->awaiting_get_info = false;
        backend->awaiting_credential_prepare = false;
        backend->credential_request_length = 0U;
        auth_secure_zero(backend->credential_request, sizeof backend->credential_request);
        auth_secure_zero(&backend->pin_request, sizeof backend->pin_request);
        backend->response_length = 0U;
        backend->awaiting_presence = false;
        backend->presence_started = false;
        ctap_user_presence_abort(&backend->presence, operation_id);
        ctap_reset_abort(&backend->reset, operation_id);
        backend->awaiting_reset = backend->reset_authorized = false;
        backend->awaiting_make_credential = false;
        memset(&backend->make_credential, 0, sizeof backend->make_credential);
        backend->awaiting_get_assertion = false;
        memset(&backend->get_assertion, 0, sizeof backend->get_assertion);
    }
}

CtaphidDeviceResult ctaphid_ctap_backend_poll(CtaphidCtapBackend *backend,
    CtaphidDevice *device, uint32_t now_ms)
{
    if (backend == NULL || device == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    ctap_client_pin_poll(backend->pin, now_ms);
    if (!backend->pending) {
        ctap_reset_poll(&backend->reset, now_ms);
        return CTAPHID_DEVICE_OK;
    }
    if (!device->cbor_running || device->phase != CTAPHID_DEVICE_PROCESSING ||
        device->transaction_id != backend->operation_id) {
        ctaphid_ctap_backend_abort(backend, backend->operation_id);
        return CTAPHID_DEVICE_IGNORED;
    }
    if (backend->awaiting_credential_prepare) {
        uint8_t status;
        if (backend->prepare_make) {
            status = ctap_make_credential_prepare_with_pin(backend->credentials, backend->pin, now_ms,
                backend->credential_request, backend->credential_request_length, &backend->make_credential);
            backend->awaiting_make_credential = status == CTAP_STATUS_OK;
            backend->awaiting_presence = backend->awaiting_make_credential;
        } else {
            status = ctap_get_assertion_prepare_with_pin(backend->credentials, backend->pin, now_ms,
                backend->credential_request, backend->credential_request_length, &backend->get_assertion);
            backend->awaiting_get_assertion = status == CTAP_STATUS_OK;
            backend->awaiting_presence = backend->awaiting_get_assertion && backend->get_assertion.user_presence_required;
        }
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 0U : 1U;
        backend->awaiting_credential_prepare = false; backend->credential_request_length = 0U;
        auth_secure_zero(backend->credential_request, sizeof backend->credential_request);
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
            if (backend->response[0] == CTAP_STATUS_OK && backend->pin != NULL) {
                ctap_client_pin_reset_state(backend->pin);
                if (backend->pin->faulted) backend->response[0] = CTAP_STATUS_OTHER;
            }
        }
        backend->response_length = 1U;
        if (backend->awaiting_get_assertion && presence != CTAP_PRESENCE_CONFIRMED) {
            backend->response[0] = CTAP_STATUS_OPERATION_DENIED;
            backend->awaiting_get_assertion = false;
        }
        if (backend->awaiting_make_credential) {
            /* Exclusion waits for UP but returns EXCLUDED even after timeout.
             * Normal registration refusal/timeout is OPERATION_DENIED (6.1.2).
             * A coordinator CANCEL aborts us before reaching this code. */
            uint8_t status = CTAP_STATUS_OPERATION_DENIED;
            size_t encoded_length = 0U;
            if (backend->make_credential.credential_excluded) {
                CtapPinAuth auth = backend->make_credential.auth;
                status = ctap_client_pin_authorize(backend->pin, &auth, backend->make_credential.rp_id_hash,
                    backend->make_credential.client_data_hash, CTAP_PIN_PERMISSION_MC, now_ms, false);
                if (status == CTAP_STATUS_OK) status = CTAP_STATUS_CREDENTIAL_EXCLUDED;
            }
            else if (presence == CTAP_PRESENCE_CONFIRMED) {
                status = ctap_make_credential_finish_at(backend->credentials, &backend->make_credential,
                    backend->profile.aaguid, backend->response + 1U, sizeof backend->response - 1U, &encoded_length, now_ms);
            }
            backend->response[0] = status;
            backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
        }
    }
    if (backend->awaiting_pin) {
        size_t encoded_length = 0U;
        uint8_t status = ctap_client_pin_execute(backend->pin, &backend->pin_request,
            backend->response + 1U, sizeof backend->response - 1U, &encoded_length, now_ms);
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
    }
    if (backend->awaiting_get_assertion) {
        /* Only outside coordinator callbacks, after fresh UP or explicit up=false.
         * CANCEL/resync aborts before this point, including silent requests. */
        size_t encoded_length = 0U;
        uint8_t status = ctap_get_assertion_finish_at(backend->credentials, &backend->get_assertion,
            backend->response + 1U, sizeof backend->response - 1U, &encoded_length, now_ms);
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
    }
    if (backend->awaiting_get_info) {
        uint8_t status = ctap_client_pin_status(backend->pin, &backend->profile.pin_set);
        size_t encoded_length = 0U;
        if (status == CTAP_STATUS_OK && !ctap_get_info_encode(&backend->profile, backend->response + 1U,
            sizeof backend->response - 1U, &encoded_length)) status = CTAP_STATUS_OTHER;
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
    }
    CtaphidDeviceResult result = ctaphid_device_complete_cbor(device, backend->operation_id,
        backend->response, backend->response_length);
    backend->pending = false;
    backend->awaiting_pin = false;
    backend->awaiting_get_info = false;
    auth_secure_zero(&backend->pin_request, sizeof backend->pin_request);
    backend->response_length = 0U;
    backend->awaiting_presence = false;
    backend->presence_started = false;
    ctap_user_presence_abort(&backend->presence, backend->operation_id);
    ctap_reset_abort(&backend->reset, backend->operation_id);
    backend->awaiting_reset = backend->reset_authorized = false;
    backend->awaiting_make_credential = false;
    memset(&backend->make_credential, 0, sizeof backend->make_credential);
    backend->awaiting_get_assertion = false;
    memset(&backend->get_assertion, 0, sizeof backend->get_assertion);
    return result == CTAPHID_DEVICE_INVALID_STATE ? CTAPHID_DEVICE_IGNORED : result;
}

bool ctaphid_ctap_backend_signal_presence(CtaphidCtapBackend *backend,
    uint64_t operation_id, bool confirmed, uint32_t now_ms)
{
    return backend != NULL && backend->pending && backend->awaiting_presence &&
        ctap_user_presence_signal(&backend->presence, operation_id, confirmed, now_ms);
}
