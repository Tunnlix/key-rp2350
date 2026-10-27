#ifndef CTAP_MAKE_CREDENTIAL_H
#define CTAP_MAKE_CREDENTIAL_H

#include "ctap/ctap.h"
#include "authenticator/auth_credentials.h"
#include "ctap/ctap_client_pin.h"
#include "ctap/ctap_hmac_secret.h"

/* Parsed request state (including deferred extension errors) owns only the data needed after touch. No borrowed
 * receive-buffer pointers, credential keys or platform details are retained. */
typedef struct {
    uint8_t client_data_hash[32], rp_id_hash[32], user_id[64];
    size_t user_id_length;
    int32_t algorithm;
    bool credential_excluded, omit_attestation;
    bool hmac_secret_requested;
    CtapHmacSecret hmac_secret_mc;
    CtapClientPin *pin;
    CtapPinAuth auth;
    bool user_verified, cred_protect_requested;
    uint8_t cred_protect;
    uint8_t extension_status; /* Deferred until after authorization/exclusion/UP. */
    bool cred_blob_requested, cred_blob_stored, large_blob_requested;
    bool discoverable;
    AuthCredential metadata;
} CtapMakeCredential;

/* Zero-initialize once in persistent caller-owned RAM. Each prepare/finish call wipes
 * scratch before returning. Do not alias API buffers with this workspace or
 * reenter an active workspace; callbacks may not retain pointers into it. */
typedef struct {
    union {
        struct {
            AuthCredential credential;
            uint8_t public_key[65], encoded[576U + AUTH_CREDENTIAL_ID_MAX_SIZE - AUTH_CREDENTIAL_ID_SIZE];
            uint8_t wire_id[AUTH_CREDENTIAL_ID_MAX_SIZE];
            size_t wire_id_length;
        } finish;
        struct {
            CtapMakeCredential request;
            AuthCredential excluded;
        } prepare;
    } scratch;
    bool busy;
} CtapMakeCredentialWorkspace;

/* Validate the parameter map and check RP-bound exclusion before asking for UP.
 * Success means ready to wait for a fresh touch, not a created credential.
 * Preparation leaves output unchanged on failure and clears acquired scratch.
 * Prepared output must not alias workspace; prepare and finish share its guard.
 * Extension-value errors are retained for finish, after authorization/exclusion
 * and UP. Invalid/unsupported requests never create keys.
 * Supports ES256 and optional Ed25519; resident creation requires the complete storage/PIN binding.
 * Unsupported extensions/options are ignored.
 * This entry point has no PIN binding; the with_pin variant adds protocol 2
 * authorization, credProtect and discoverable credentials. Enterprise attestation
 * remains unsupported. */
uint8_t ctap_make_credential_prepare(AuthCredentialService *service, CtapMakeCredentialWorkspace *workspace,
    const uint8_t *parameters, size_t length, CtapMakeCredential *prepared);
/* Authorize against the injected clock after validating all descriptors. The
 * prepared state snapshots the token generation and may be discarded on abort. */
uint8_t ctap_make_credential_prepare_with_pin(AuthCredentialService *service, CtapMakeCredentialWorkspace *workspace, CtapClientPin *pin,
    uint32_t now_ms, const uint8_t *parameters, size_t length, CtapMakeCredential *prepared);

/* Caller MUST establish fresh user presence for this operation first.
 * Prepares resident extension output/attestation before committing metadata;
 * publishes response CBOR (no status) only after successful persistence.
 * Signing/encoding failure attempts to erase the new credential and key;
 * provider cleanup failures surface as OTHER and may require provider recovery.
 * Excluded credentials never create
 * keys. Output must not overlap any inputs; caller supplies at least 384 bytes
 * (512 bytes when hmac-secret-mc is requested).
 * CANCEL/INIT before this call must discard prepared state without invoking it. */
uint8_t ctap_make_credential_finish(AuthCredentialService *service,
    CtapMakeCredentialWorkspace *workspace,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length);
/* Required for PIN-bound prepared state: rechecks expiry/generation after UP,
 * then consumes token permissions before creating/signing. Failures may consume
 * permissions but cannot publish an unauthorized credential. */
uint8_t ctap_make_credential_finish_at(AuthCredentialService *service,
    CtapMakeCredentialWorkspace *workspace,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);

#endif
