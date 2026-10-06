#ifndef CTAP_GET_ASSERTION_H
#define CTAP_GET_ASSERTION_H

#include "ctap/ctap.h"
#include "authenticator/auth_credentials.h"

/* Owned, validated request state. No borrowed receive-buffer pointers or keys.
 * First eligible RP-bound allowList credential wins; the whole list is validated.
 * rk=false means no discoverable lookup, account enumeration or next-assertion
 * state. No PIN/UV or extensions are advertised/implemented. */
typedef struct {
    uint8_t client_data_hash[32], rp_id_hash[32], credential_id[32];
    bool user_presence_required;
} CtapGetAssertion;

/* Validate CBOR, options, descriptors and RP binding. No counter updates/signing.
 * OK means a credential was selected. NO_CREDENTIALS also applies when allowList
 * is omitted; it never discovers our non-discoverable records by RP alone. */
uint8_t ctap_get_assertion_prepare(AuthCredentialService *service,
    const uint8_t *parameters, size_t length, CtapGetAssertion *prepared);

/* Caller MUST collect fresh UP when prepared.user_presence_required is true.
 * For up=false, caller may finish without touch: UP=0, UV=0 (silent check).
 * Persist the next counter BEFORE signing, then produce response CBOR without
 * status or HID framing. Signing failures can consume a counter: never roll it
 * back. Failures leave output/length unchanged. CANCEL/INIT before this call
 * discards prepared state without updating counters or signing.
 * Rechecks the selected credential's existence and RP binding. Caller provides
 * at least 192 bytes; storage and signing errors fail closed with OTHER.
 * Output must not overlap inputs/service. */
uint8_t ctap_get_assertion_finish(AuthCredentialService *service,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length);

#endif
