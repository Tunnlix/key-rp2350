#ifndef CTAP_GET_INFO_H
#define CTAP_GET_INFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CTAP_GET_INFO_MAX_CBOR_SIZE 256U

/* Device metadata supplied by the application. AAGUID is stable per model;
 * the host development harness uses all zeroes until a production identity is
 * assigned. max_message_size includes the CTAP command byte and its CBOR data. */
typedef struct {
    uint8_t aaguid[16];
    uint32_t max_message_size;
    bool user_presence; /* Set only when a platform presence provider is connected. */
    bool make_credential; /* ES256 provider + UP configured; set by the backend. */
    bool hmac_secret; /* Complete secret provider bound; protocol 2 key agreement. */
    bool pin_uv_auth; /* Complete PIN/token + credential protection configured. */
    bool pin_set; /* Current persistent PIN state, refreshed before GetInfo. */
    bool resident_credentials; /* Complete discovery + credential management binding. */
} CtapGetInfoProfile;

/* Encode the GetInfo map only (without status byte or HID framing). Returns
 * false for incomplete profiles (credentials, hmac-secret and UP are required),
 * invalid output or insufficient capacity; failure leaves
 * output and output_length unchanged. Storage must not overlap the profile.
 *
 * CTAP 2.3 section 6.4: versions, aaguid, options, maxMsgSize. Options currently
 * report up=profile.user_presence and plat=false. Complete resident_credentials
 * enables rk=true and credMgmt=true; other bindings keep rk=false. With MakeCredential
 * configured, advertise ES256 and packed self-attestation (none is implicit),
 * and makeCredUvNotRqd=true. hmac-secret adds extensions and pinUvAuthProtocols=[2]
 * for key agreement, plus hmac-secret-mc when MakeCredential is configured.
 * pin_uv_auth adds credProtect and pinUvAuthToken=true;
 * clientPin reflects pin_set and includes minPINLength=4. Built-in uv remains omitted.
 * FIDO_2_3 is the
 * development target; full authenticator conformance has not been established.
 */
bool ctap_get_info_encode(const CtapGetInfoProfile *profile,
    uint8_t *output, size_t capacity, size_t *output_length);

#endif
