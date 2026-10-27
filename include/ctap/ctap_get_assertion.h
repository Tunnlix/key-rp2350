#ifndef CTAP_GET_ASSERTION_H
#define CTAP_GET_ASSERTION_H

#include "ctap/ctap.h"
#include "authenticator/auth_credentials.h"
#include "ctap/ctap_hmac_secret.h"
#include "ctap/ctap_client_pin.h"

/* Owned, validated request state. No borrowed receive-buffer pointers or keys.
 * First eligible RP-bound allowList credential wins; the whole list is validated.
 * Complete resident storage permits RP-based discovery and bounded ID snapshots.
 * hmac-secret supports protocol 2 with UP; PIN authorization explicitly
 * selects its WithUV secret. Credential protection is enforced on selection. */
typedef struct {
    uint8_t client_data_hash[32], rp_id_hash[32], credential_id[AUTH_CREDENTIAL_ID_MAX_SIZE];
    uint16_t credential_id_length;
    bool user_presence_required;
    bool cred_blob_requested, large_blob_requested;
    uint8_t extension_status;
    CtapHmacSecret hmac_secret;
    CtapClientPin *pin;
    CtapPinAuth auth;
    bool user_verified;
    bool discovery;
    uint8_t credential_ids[AUTH_RESIDENT_MAX_COUNT][32];
    size_t credential_count;
    uint64_t metadata_revision;
} CtapGetAssertion;

/* Zero-initialize in persistent caller-owned RAM. Preparation and finishing wipe acquired
 * scratch on every exit; nested use is rejected without clearing active scratch.
 * Inputs/output must not alias this workspace; callbacks may not retain pointers. */
typedef struct {
    struct {
        CtapGetAssertion request;
        AuthCredential credential;
        union {
            uint64_t order[AUTH_RESIDENT_MAX_COUNT];
            struct {
                uint8_t extension_output[80], signed_data[212], digest[32];
                uint8_t signature[72], encoded[768];
            } finish;
        } phase;
    } scratch;
    bool busy;
} CtapGetAssertionWorkspace;

typedef struct {
    CtapGetAssertion request;
    size_t next;
    uint32_t last_call_ms;
    uint32_t token_issued_at_ms;
    bool active;
} CtapAssertionSequence;
void ctap_assertion_sequence_clear(CtapAssertionSequence *sequence);
/* Begin only after the first assertion was successfully signed/encoded. */
void ctap_assertion_sequence_begin(CtapAssertionSequence *sequence, const CtapGetAssertion *request, uint32_t now_ms);
/* Call while idle as well as before continuation. UP consumes permissions,
 * but the initializing token's original lifetime still bounds this snapshot. */
void ctap_assertion_sequence_poll(CtapAssertionSequence *sequence, uint32_t now_ms);
uint8_t ctap_get_next_assertion(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace, CtapAssertionSequence *sequence,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);

/* Validate CBOR, options, descriptors and RP binding. No counter updates/signing.
 * OK means a credential was selected; extension-value errors are deferred to
 * finish after authorization and UP. Omitted allowList discovers resident
 * records only; non-resident credentials always require explicit IDs.
 * Prepared output remains unchanged on failure. */
uint8_t ctap_get_assertion_prepare(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    const uint8_t *parameters, size_t length, CtapGetAssertion *prepared);
/* Adds protocol 2 GA authorization and snapshots the token generation only
 * after validating the whole allowList. No counter/signing effects. */
uint8_t ctap_get_assertion_prepare_with_pin(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace, CtapClientPin *pin,
    uint32_t now_ms, const uint8_t *parameters, size_t length, CtapGetAssertion *prepared);

/* Caller MUST collect fresh UP when prepared.user_presence_required is true.
 * For up=false, caller may finish without touch: UP=0; UV reflects authorization.
 * Persist the next counter BEFORE signing, then produce response CBOR without
 * status or HID framing. Signing failures can consume a counter: never roll it
 * back. Failures leave output/length unchanged. CANCEL/INIT before this call
 * discards prepared state without updating counters or signing.
 * Rechecks the selected credential's existence and RP binding. Caller provides
 * at least 192 bytes, 288 for non-resident hmac-secret, or 768 for resident user
 * information and extensions. The extension requires
 * UP and is evaluated before counter updates; its encrypted output is signed
 * inside authenticator data with ED set. Storage/signing errors fail with OTHER.
 * Output must not overlap inputs/service/workspace. Finish and continuation
 * share the preparation guard and wipe acquired scratch on every exit. */
uint8_t ctap_get_assertion_finish(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length);
/* Required for PIN-bound prepared state. Recheck token/credential policy at
 * current injected time after UP. UP consumes token permissions before signing;
 * an authorized up=false request preserves them for a later touch operation. */
uint8_t ctap_get_assertion_finish_at(AuthCredentialService *service, CtapGetAssertionWorkspace *workspace,
    const CtapGetAssertion *prepared, uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);

#endif
