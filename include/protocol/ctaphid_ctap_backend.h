#ifndef CTAPHID_CTAP_BACKEND_H
#define CTAPHID_CTAP_BACKEND_H

#include "ctap/ctap.h"
#include "ctap/ctap_user_presence.h"
#include "ctap/ctap_reset.h"
#include "ctap/ctap_make_credential.h"
#include "ctap/ctap_get_assertion.h"
#include "ctap/ctap_client_pin.h"
#include "protocol/ctaphid_device.h"

/* Bridge between CTAP command execution and the HID coordinator. CTAP code does
 * not depend on HID. Caller owns this context, one per device; no heap or threads. */
typedef struct {
    CtapGetInfoProfile profile;
    bool pending;
    uint64_t operation_id;
    uint8_t response[CTAP_MAX_RESPONSE_SIZE];
    size_t response_length;
    bool awaiting_presence;
    bool presence_started;
    uint32_t presence_timeout_ms;
    CtapUserPresence presence;
    CtapReset reset;
    bool reset_configured;
    bool awaiting_reset;
    bool reset_authorized;
    AuthCredentialService *credentials;
    bool awaiting_make_credential;
    CtapMakeCredential make_credential;
    bool awaiting_get_assertion;
    CtapGetAssertion get_assertion;
    CtapClientPin *pin;
    bool awaiting_pin;
    CtapClientPinRequest pin_request;
    bool awaiting_get_info;
    bool awaiting_credential_prepare, prepare_make;
    uint8_t credential_request[CTAPHID_MAX_MESSAGE_SIZE];
    size_t credential_request_length;
} CtaphidCtapBackend;

/* Profile's advertised size must match the coordinator's receive capacity.
 * Initialize before configuring start_cbor/abort_cbor/cbor_context on the device. */
bool ctaphid_ctap_backend_init(CtaphidCtapBackend *backend,
    const CtapGetInfoProfile *profile);

/* Configure once after backend init, before accepting requests. powered_at_ms
 * is actual device power-on, not the last reset/INIT. NULL callback disables reset
 * on this transport. No-display timing applies; optional long-touch is not enabled. */
bool ctaphid_ctap_backend_configure_reset(CtaphidCtapBackend *backend,
    uint32_t powered_at_ms, CtapResetStorage reset_storage, void *storage_context);

/* Bind an initialized portable service once before requests. Caller keeps it
 * alive for this backend's lifetime. Requires a configured UP provider; makes
 * Enables ES256 registration/assertions and packed self-attestation. Bind the
 * service's optional secret provider before this call to enable hmac-secret and
 * protocol 2 getKeyAgreement. No PIN setup/token/UV capability is implied. */
bool ctaphid_ctap_backend_configure_credentials(CtaphidCtapBackend *backend,
    AuthCredentialService *service);

/* Complete protocol 2 PIN/token binding, after credentials/reset. Enables
 * clientPin, pinUvAuthToken and credProtect; built-in uv remains absent. The
 * combined application
 * Reset callback must erase persistent PIN state as well as credentials/keys. */
bool ctaphid_ctap_backend_configure_pin(CtaphidCtapBackend *backend, CtapClientPin *pin);

/* Config callbacks: start prepares a reply, abort discards it. Neither callback
 * reenters the coordinator. context must point to an initialized backend. */
void ctaphid_ctap_backend_start(void *context, uint64_t operation_id,
    const uint8_t *request, size_t request_length);
void ctaphid_ctap_backend_abort(void *context, uint64_t operation_id);

/* Call outside coordinator callbacks, after device_poll. Delivers the prepared
 * reply through complete_cbor; another device_poll then transmits it. Selection,
 * Reset, MakeCredential and normal GetAssertion remain pending with UPNEEDED.
 * GetAssertion with up=false completes without touch, with the UP bit cleared.
 * PIN-bound credential requests are copied and validated in poll using the
 * current injected clock; token authorization is rechecked after touch.
 * MakeCredential creates/signs only after confirmation; cancellation/resync
 * discards validated request state without creating credentials or changing
 * assertion counters. Counters persist before signing; failed signing may skip
 * a counter value, and must never roll it back.
 * now_ms must share the device's clock. Stale operation results are discarded. */
CtaphidDeviceResult ctaphid_ctap_backend_poll(CtaphidCtapBackend *backend,
    CtaphidDevice *device, uint32_t now_ms);

/* Main-loop entry point for GPIO/touch or host-simulation events. */
bool ctaphid_ctap_backend_signal_presence(CtaphidCtapBackend *backend,
    uint64_t operation_id, bool confirmed, uint32_t now_ms);

#endif
