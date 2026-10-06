#ifndef CTAP_GET_ASSERTION_H
#define CTAP_GET_ASSERTION_H

#include "ctap/ctap.h"
#include "authenticator/auth_credentials.h"
#include "ctap/ctap_hmac_secret.h"
#include "ctap/ctap_client_pin.h"

/* Owned, validated request state. No borrowed receive-buffer pointers or keys.
 * First eligible RP-bound allowList credential wins; the whole list is validated.
 * rk=false means no discoverable lookup, account enumeration or next-assertion
 * state. hmac-secret supports protocol 2 with UP; PIN authorization explicitly
 * selects its WithUV secret. Credential protection is enforced on selection. */
typedef struct {
    uint8_t client_data_hash[32], rp_id_hash[32], credential_id[32];
    bool user_presence_required;
    CtapHmacSecret hmac_secret;
    CtapClientPin *pin;
    CtapPinAuth auth;
    bool user_verified;
} CtapGetAssertion;

/* Validate CBOR, options, descriptors and RP binding. No counter updates/signing.
 * OK means a credential was selected. NO_CREDENTIALS also applies when allowList
 * is omitted; it never discovers our non-discoverable records by RP alone. */
uint8_t ctap_get_assertion_prepare(AuthCredentialService *service,
    const uint8_t *parameters, size_t length, CtapGetAssertion *prepared);
/* Adds protocol 2 GA authorization and snapshots the token generation only
 * after validating the whole allowList. No counter/signing effects. */
uint8_t ctap_get_assertion_prepare_with_pin(AuthCredentialService *service, CtapClientPin *pin,
    uint32_t now_ms, const uint8_t *parameters, size_t length, CtapGetAssertion *prepared);

/* Caller MUST collect fresh UP when prepared.user_presence_required is true.
 * For up=false, caller may finish without touch: UP=0; UV reflects authorization.
 * Persist the next counter BEFORE signing, then produce response CBOR without
 * status or HID framing. Signing failures can consume a counter: never roll it
 * back. Failures leave output/length unchanged. CANCEL/INIT before this call
 * discards prepared state without updating counters or signing.
 * Rechecks the selected credential's existence and RP binding. Caller provides
 * at least 192 bytes, or 288 for an hmac-secret request. The extension requires
 * UP and is evaluated before counter updates; its encrypted output is signed
 * inside authenticator data with ED set. Storage/signing errors fail with OTHER.
 * Output must not overlap inputs/service. */
uint8_t ctap_get_assertion_finish(AuthCredentialService *service,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length);
/* Required for PIN-bound prepared state. Recheck token/credential policy at
 * current injected time after UP. UP consumes token permissions before signing;
 * an authorized up=false request preserves them for a later touch operation. */
uint8_t ctap_get_assertion_finish_at(AuthCredentialService *service,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);

#endif
