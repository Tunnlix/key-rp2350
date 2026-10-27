#include "protocol/ctaphid_ctap_backend.h"
#include "ctap/ctap_authenticator_config.h"

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
    backend->profile.ed25519 = false;
    backend->profile.pin_uv_auth = backend->profile.pin_set = false;
    backend->profile.resident_credentials = backend->profile.large_blobs = false;
    backend->profile.always_uv = backend->profile.force_pin_change = false;
    backend->profile.min_pin_length = 4U;
    backend->profile.max_credential_id_length = AUTH_CREDENTIAL_ID_SIZE;
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
    backend->profile.ed25519 = auth_credentials_algorithm_supported(service, AUTH_COSE_ALG_EDDSA);
    backend->profile.hmac_secret = auth_secret_crypto_valid(&service->secrets);
    backend->profile.max_credential_id_length = auth_credentials_nonresident_supported(service) ?
        AUTH_CREDENTIAL_ID_MAX_SIZE : AUTH_CREDENTIAL_ID_SIZE;
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
    backend->profile.min_pin_length = pin->min_length;
    backend->profile.always_uv = pin->always_uv; backend->profile.force_pin_change = pin->force_change;
    backend->profile.resident_credentials = auth_credentials_resident_supported(backend->credentials);
    return true;
}

/* Clears one operation's inputs and wait flags, preserving continuations.
 * Only RAM cleanup here: never repeat a committed provider side effect. */
static void clear_pending(CtaphidCtapBackend *backend)
{
    auth_credentials_release_nonresident(backend->credentials);
    backend->pending = false;
    backend->awaiting_next_assertion = backend->awaiting_management = false;
    backend->awaiting_pin = backend->awaiting_get_info = backend->awaiting_config = backend->awaiting_blobs = false;
    backend->awaiting_credential_prepare = false;
    backend->credential_request_length = 0U;
    auth_secure_zero(backend->credential_request, sizeof backend->credential_request);
    auth_secure_zero(&backend->pin_request, sizeof backend->pin_request);
    backend->response_length = 0U;
    backend->awaiting_presence = backend->presence_started = false;
    ctap_user_presence_abort(&backend->presence, backend->operation_id);
    ctap_reset_abort(&backend->reset, backend->operation_id);
    backend->awaiting_reset = backend->reset_authorized = false;
    backend->awaiting_make_credential = backend->awaiting_get_assertion = false;
    auth_secure_zero(&backend->make_credential, sizeof backend->make_credential);
    auth_secure_zero(&backend->get_assertion, sizeof backend->get_assertion);
}

static void clear_continuations(CtaphidCtapBackend *backend)
{
    ctap_assertion_sequence_clear(&backend->assertion_sequence);
    ctap_credential_management_clear(&backend->management);
}

static void prepare_command(CtaphidCtapBackend *backend, const uint8_t *request,
    size_t request_length, bool next, bool management)
{
    if ((next || management) && backend->profile.resident_credentials) {
        if ((next && request_length != 1U) || request_length - 1U > sizeof backend->credential_request) {
            backend->response[0] = CTAP_STATUS_INVALID_LENGTH; backend->response_length = 1U;
            clear_continuations(backend);
        } else {
            backend->awaiting_next_assertion = next; backend->awaiting_management = management;
            memcpy(backend->credential_request, request + 1U, request_length - 1U);
            backend->credential_request_length = request_length - 1U; backend->response_length = 0U;
        }
        return;
    }
    if (request != NULL && request_length != 0U && (request[0] == CTAP_COMMAND_AUTHENTICATOR_CONFIG || (request[0] == CTAP_COMMAND_LARGE_BLOBS && backend->profile.large_blobs)) && backend->pin != NULL) {
        if (request_length - 1U > sizeof backend->credential_request) {
            backend->response[0] = CTAP_STATUS_INVALID_LENGTH; backend->response_length = 1U;
        } else {
            memcpy(backend->credential_request, request + 1U, request_length - 1U);
            backend->credential_request_length = request_length - 1U;
            backend->awaiting_config = request[0] == CTAP_COMMAND_AUTHENTICATOR_CONFIG; backend->awaiting_blobs = request[0] == CTAP_COMMAND_LARGE_BLOBS;
            backend->response_length = 0U;
        }
        return;
    }
    if (request != NULL && request_length == 1U && request[0] == CTAP_COMMAND_GET_INFO && backend->pin != NULL) {
        backend->awaiting_get_info = true;
        backend->response_length = 0U; return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_CLIENT_PIN && backend->pin != NULL) {
        uint8_t status = ctap_client_pin_prepare(request + 1U, request_length - 1U, &backend->pin_request);
        backend->awaiting_pin = status == CTAP_STATUS_OK;
        backend->response[0] = status;
        backend->response_length = backend->awaiting_pin ? 0U : 1U;
        return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_CLIENT_PIN &&
        backend->credentials != NULL && backend->profile.hmac_secret) {
        size_t encoded_length = 0U;
        uint8_t status = ctap_hmac_secret_key_agreement(backend->credentials, request + 1U,
            request_length - 1U, backend->response + 1U, sizeof backend->response - 1U, &encoded_length);
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
        return;
    }
    if (request != NULL && request_length != 0U && backend->pin != NULL &&
        (request[0] == CTAP_COMMAND_MAKE_CREDENTIAL || request[0] == CTAP_COMMAND_GET_ASSERTION)) {
        backend->response_length = 0U;
        if (request_length - 1U > sizeof backend->credential_request) {
            backend->response[0] = CTAP_STATUS_INVALID_LENGTH; backend->response_length = 1U;
        } else {
            backend->prepare_make = request[0] == CTAP_COMMAND_MAKE_CREDENTIAL;
            memcpy(backend->credential_request, request + 1U, request_length - 1U);
            backend->credential_request_length = request_length - 1U;
            backend->awaiting_credential_prepare = true;
        }
        return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_GET_ASSERTION && backend->credentials != NULL) {
        uint8_t status = ctap_get_assertion_prepare(backend->credentials, &backend->get_assertion_workspace, request + 1U,
            request_length - 1U, &backend->get_assertion);
        backend->awaiting_get_assertion = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_get_assertion && backend->get_assertion.user_presence_required;
        backend->response[0] = status;
        backend->response_length = backend->awaiting_get_assertion ? 0U : 1U;
        return;
    }
    if (request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_MAKE_CREDENTIAL && backend->credentials != NULL) {
        uint8_t status = ctap_make_credential_prepare(backend->credentials, &backend->make_credential_workspace, request + 1U,
            request_length - 1U, &backend->make_credential);
        backend->awaiting_make_credential = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_make_credential;
        backend->response[0] = status;
        backend->response_length = backend->awaiting_presence ? 0U : 1U;
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
}

void ctaphid_ctap_backend_start(void *context, uint64_t operation_id,
    const uint8_t *request, size_t request_length)
{
    CtaphidCtapBackend *backend = context;
    bool next = request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_GET_NEXT_ASSERTION;
    bool management = request != NULL && request_length != 0U && request[0] == CTAP_COMMAND_CREDENTIAL_MANAGEMENT;
    clear_pending(backend);
    if (request == NULL || request_length == 0U || request[0] != CTAP_COMMAND_LARGE_BLOBS) ctap_large_blobs_clear(&backend->blobs);
    if (!next) ctap_assertion_sequence_clear(&backend->assertion_sequence);
    if (!management) ctap_credential_management_clear(&backend->management);
    backend->operation_id = operation_id;
    prepare_command(backend, request, request_length, next, management);
    backend->pending = true;
}

void ctaphid_ctap_backend_abort(void *context, uint64_t operation_id)
{
    CtaphidCtapBackend *backend = context;
    if (backend->pending && backend->operation_id == operation_id) {
        clear_pending(backend);
        ctap_large_blobs_clear(&backend->blobs);
        clear_continuations(backend);
    }
}

static void prepare_credentials(CtaphidCtapBackend *backend, uint32_t now_ms)
{
    uint8_t status;
    if (backend->prepare_make) {
        status = ctap_make_credential_prepare_with_pin(backend->credentials, &backend->make_credential_workspace, backend->pin, now_ms,
            backend->credential_request, backend->credential_request_length, &backend->make_credential);
        backend->awaiting_make_credential = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_make_credential;
    } else {
        status = ctap_get_assertion_prepare_with_pin(backend->credentials, &backend->get_assertion_workspace, backend->pin, now_ms,
            backend->credential_request, backend->credential_request_length, &backend->get_assertion);
        backend->awaiting_get_assertion = status == CTAP_STATUS_OK;
        backend->awaiting_presence = backend->awaiting_get_assertion && backend->get_assertion.user_presence_required;
    }
    backend->response[0] = status;
    backend->response_length = status == CTAP_STATUS_OK ? 0U : 1U;
    backend->awaiting_credential_prepare = false; backend->credential_request_length = 0U;
    auth_secure_zero(backend->credential_request, sizeof backend->credential_request);
}

/* Runs once after presence resolves, with coordinator ownership established. */
static void finish_presence(CtaphidCtapBackend *backend, CtapPresenceResult presence, uint32_t now_ms)
{
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
            /* Authorization/exclusion was established before waiting.
             * §6.1.2 step 12 returns EXCLUDED even if that wait times out;
             * token expiry during the wait must not replace it with 0x33. */
            status = CTAP_STATUS_CREDENTIAL_EXCLUDED;
            ctap_client_pin_invalidate(backend->pin);
        }
        else if (presence == CTAP_PRESENCE_CONFIRMED) {
            status = ctap_make_credential_finish_at(backend->credentials, &backend->make_credential_workspace, &backend->make_credential,
                backend->profile.aaguid, backend->response + 1U, sizeof backend->response - 1U, &encoded_length, now_ms);
        }
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
    }
}

static void execute_ready_command(CtaphidCtapBackend *backend, CtaphidDevice *device, uint32_t now_ms)
{
    if (backend->awaiting_blobs) {
        size_t length = 0U;
        uint8_t status = ctap_large_blobs_execute(&backend->blobs, backend->pin, device->active_channel_id,
            backend->credential_request, backend->credential_request_length, backend->response + 1U,
            sizeof backend->response - 1U, &length, now_ms);
        backend->response[0] = status; backend->response_length = status == CTAP_STATUS_OK ? length + 1U : 1U;
    }
    if (backend->awaiting_config) {
        backend->response[0] = ctap_authenticator_config_execute(backend->pin, backend->credential_request,
            backend->credential_request_length, now_ms);
        backend->response_length = 1U;
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
        uint8_t status = ctap_get_assertion_finish_at(backend->credentials, &backend->get_assertion_workspace, &backend->get_assertion,
            backend->response + 1U, sizeof backend->response - 1U, &encoded_length, now_ms);
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
        if (status == CTAP_STATUS_OK) {
            ctap_assertion_sequence_begin(&backend->assertion_sequence, &backend->get_assertion, now_ms);
            backend->assertion_cid = device->active_channel_id;
        }
    }
    if (backend->awaiting_next_assertion || backend->awaiting_management) {
        size_t encoded_length = 0U; uint8_t status;
        if (backend->awaiting_next_assertion) {
            if (backend->assertion_cid != device->active_channel_id) {
                ctap_assertion_sequence_clear(&backend->assertion_sequence); status = CTAP_STATUS_NOT_ALLOWED;
            } else status = ctap_get_next_assertion(backend->credentials, &backend->get_assertion_workspace, &backend->assertion_sequence,
                backend->response + 1U, sizeof backend->response - 1U, &encoded_length, now_ms);
        } else {
            if (backend->management.kind != 0U && backend->management_cid != device->active_channel_id)
                ctap_credential_management_clear(&backend->management);
            status = ctap_credential_management_execute(backend->credentials, backend->pin, &backend->management,
                backend->credential_request, backend->credential_request_length, backend->response + 1U,
                sizeof backend->response - 1U, &encoded_length, now_ms);
            backend->management_cid = device->active_channel_id;
        }
        backend->response[0] = status; backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
        auth_secure_zero(backend->credential_request, sizeof backend->credential_request); backend->credential_request_length = 0U;
    }
    if (backend->awaiting_get_info) {
        uint8_t status = ctap_client_pin_status(backend->pin, &backend->profile.pin_set);
        backend->profile.min_pin_length = backend->pin->min_length;
        backend->profile.always_uv = backend->pin->always_uv;
        backend->profile.force_pin_change = backend->pin->force_change;
        if (status == CTAP_STATUS_OK && backend->profile.resident_credentials) {
            size_t total = 0U;
            const AuthStorage *storage = &backend->credentials->storage;
            if (storage->count(storage->context, &total) != AUTH_OK ||
                total > storage->capacity || storage->capacity - total > UINT32_MAX) {
                status = CTAP_STATUS_OTHER;
            } else {
                /* Non-discoverable records share this pool and consume slots too. */
                backend->profile.remaining_credentials = (uint32_t)(storage->capacity - total);
            }
        }
        size_t encoded_length = 0U;
        if (status == CTAP_STATUS_OK && !ctap_get_info_encode(&backend->profile, backend->response + 1U,
            sizeof backend->response - 1U, &encoded_length)) status = CTAP_STATUS_OTHER;
        backend->response[0] = status;
        backend->response_length = status == CTAP_STATUS_OK ? 1U + encoded_length : 1U;
    }
}

static CtaphidDeviceResult publish_response(CtaphidCtapBackend *backend, CtaphidDevice *device)
{
    CtaphidDeviceResult result = ctaphid_device_complete_cbor(device, backend->operation_id,
        backend->response, backend->response_length);
    clear_pending(backend);
    return result == CTAPHID_DEVICE_INVALID_STATE ? CTAPHID_DEVICE_IGNORED : result;
}

static bool transport_cancelled(const CtaphidCtapBackend *backend,const CtaphidDevice *device)
{
    return device->config.cancel_requested != NULL &&
        device->config.cancel_requested(device->config.transport_context,backend->operation_id);
}

static CtaphidDeviceResult publish_cancel(CtaphidCtapBackend *backend,CtaphidDevice *device)
{
    clear_continuations(backend);
    ctap_large_blobs_clear(&backend->blobs);
    auth_secure_zero(backend->response,sizeof backend->response);
    backend->response[0]=0x2dU;
    backend->response_length=1U;
    return publish_response(backend,device);
}

CtaphidDeviceResult ctaphid_ctap_backend_poll(CtaphidCtapBackend *backend,
    CtaphidDevice *device, uint32_t now_ms)
{
    if (backend == NULL || device == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    ctap_client_pin_poll(backend->pin, now_ms);
    ctap_assertion_sequence_poll(&backend->assertion_sequence, now_ms);
    /* Discard the authenticated snapshot as soon as its token expires (§6). */
    if (backend->management.kind != 0U &&
        (backend->pin == NULL || !backend->pin->token_active ||
         backend->management.token_generation != backend->pin->token_generation ||
         (uint32_t)(now_ms - backend->management.last_call_ms) > 30000U))
        ctap_credential_management_clear(&backend->management);
    if (backend->blobs.expected_length && (uint32_t)(now_ms - backend->blobs.last_call_ms) > 30000U)
        ctap_large_blobs_clear(&backend->blobs);
    if (!backend->pending) {
        ctap_reset_poll(&backend->reset, now_ms);
        return CTAPHID_DEVICE_OK;
    }
    if (!device->cbor_running || device->phase != CTAPHID_DEVICE_PROCESSING ||
        device->transaction_id != backend->operation_id) {
        ctaphid_ctap_backend_abort(backend, backend->operation_id);
        return CTAPHID_DEVICE_IGNORED;
    }
    if (transport_cancelled(backend,device)) return publish_cancel(backend,device);
    if (backend->awaiting_credential_prepare) prepare_credentials(backend, now_ms);
    if (transport_cancelled(backend,device)) return publish_cancel(backend,device);
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
        finish_presence(backend, presence, now_ms);
        if (transport_cancelled(backend,device)) return publish_cancel(backend,device);
    }
    execute_ready_command(backend, device, now_ms);
    if (transport_cancelled(backend,device)) return publish_cancel(backend,device);
    return publish_response(backend, device);
}

bool ctaphid_ctap_backend_signal_presence(CtaphidCtapBackend *backend,
    uint64_t operation_id, bool confirmed, uint32_t now_ms)
{
    return backend != NULL && backend->pending && backend->awaiting_presence &&
        ctap_user_presence_signal(&backend->presence, operation_id, confirmed, now_ms);
}

void ctaphid_ctap_backend_resync(void *context, uint32_t cid)
{
    CtaphidCtapBackend *backend = context;
    if (backend == NULL) return;
    if (backend->blobs.channel == cid) ctap_large_blobs_clear(&backend->blobs);
    if (backend->assertion_cid == cid) ctap_assertion_sequence_clear(&backend->assertion_sequence);
    if (backend->management_cid == cid) ctap_credential_management_clear(&backend->management);
}

bool ctaphid_ctap_backend_configure_blobs(CtaphidCtapBackend *backend, const CtapLargeBlobStorage *storage)
{
    if (backend == NULL || storage == NULL || storage->read == NULL || storage->commit == NULL ||
        backend->pin == NULL || backend->pending || backend->profile.large_blobs ||
        !backend->profile.resident_credentials || backend->credentials->secrets.large_blob_key == NULL) return false;
    backend->blobs.storage = *storage;
    backend->profile.large_blobs = backend->credentials->large_blobs = true;
    backend->pin->large_blobs = true;
    return true;
}
