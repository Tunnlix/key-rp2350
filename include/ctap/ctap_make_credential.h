#ifndef CTAP_MAKE_CREDENTIAL_H
#define CTAP_MAKE_CREDENTIAL_H

#include "ctap/ctap.h"
#include "authenticator/auth_credentials.h"

/* Validated request state owns only the data needed after touch. No borrowed
 * receive-buffer pointers, credential keys or platform details are retained. */
typedef struct {
    uint8_t client_data_hash[32], rp_id_hash[32], user_id[64];
    size_t user_id_length;
    bool credential_excluded, omit_attestation;
    bool hmac_secret_requested;
} CtapMakeCredential;

/* Validate the parameter map and check RP-bound exclusion before asking for UP.
 * Success means ready to wait for a fresh touch, not a created credential.
 * Invalid/unsupported requests produce a CTAP status and never create keys.
 * Supports non-discoverable ES256 only; ignores unsupported extensions/options.
 * No PIN, UV, enterprise attestation or resident-key features are claimed. */
uint8_t ctap_make_credential_prepare(AuthCredentialService *service,
    const uint8_t *parameters, size_t length, CtapMakeCredential *prepared);

/* Caller MUST establish fresh user presence for this operation first.
 * Creates/persists the credential, then encodes the response CBOR (no status).
 * Signing/encoding failure attempts to erase the new credential and key;
 * provider cleanup failures surface as OTHER and may require provider recovery.
 * Excluded credentials never create
 * keys. Output must not overlap any inputs; caller supplies at least 384 bytes.
 * CANCEL/INIT before this call must discard prepared state without invoking it. */
uint8_t ctap_make_credential_finish(AuthCredentialService *service,
    const CtapMakeCredential *prepared, const uint8_t aaguid[16],
    uint8_t *output, size_t capacity, size_t *length);

#endif
