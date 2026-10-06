#ifndef CTAPHID_CTAP_BACKEND_H
#define CTAPHID_CTAP_BACKEND_H

#include "ctap/ctap.h"
#include "ctap/ctap_user_presence.h"
#include "ctap/ctap_reset.h"
#include "ctap/ctap_make_credential.h"
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
 * GetInfo advertise ES256 registration and packed self-attestation. */
bool ctaphid_ctap_backend_configure_credentials(CtaphidCtapBackend *backend,
    AuthCredentialService *service);

/* Config callbacks: start prepares a reply, abort discards it. Neither callback
 * reenters the coordinator. context must point to an initialized backend. */
void ctaphid_ctap_backend_start(void *context, uint64_t operation_id,
    const uint8_t *request, size_t request_length);
void ctaphid_ctap_backend_abort(void *context, uint64_t operation_id);

/* Call outside coordinator callbacks, after device_poll. Delivers the prepared
 * reply through complete_cbor; another device_poll then transmits it. Selection,
 * Reset and MakeCredential remain pending with UPNEEDED until touch or timeout.
 * MakeCredential creates/signs only after confirmation; cancellation/resync
 * discards validated request state without creating keys or credentials.
 * now_ms must share the device's clock. Stale operation results are discarded. */
CtaphidDeviceResult ctaphid_ctap_backend_poll(CtaphidCtapBackend *backend,
    CtaphidDevice *device, uint32_t now_ms);

/* Main-loop entry point for GPIO/touch or host-simulation events. */
bool ctaphid_ctap_backend_signal_presence(CtaphidCtapBackend *backend,
    uint64_t operation_id, bool confirmed, uint32_t now_ms);

#endif
