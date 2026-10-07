#ifndef CTAP_CREDENTIAL_MANAGEMENT_H
#define CTAP_CREDENTIAL_MANAGEMENT_H

#include "ctap/ctap_client_pin.h"

/* Authenticated snapshot of IDs only. Core revision/token replacement and a
 * 30-second inactivity timeout invalidate it. Transport binds it to a CID. */
typedef struct {
    uint8_t ids[AUTH_RESIDENT_MAX_COUNT][32], rp_hash[32];
    size_t count, next;
    uint8_t kind;
    uint64_t token_generation, metadata_revision;
    uint32_t last_call_ms;
} CtapCredentialManagement;

void ctap_credential_management_clear(CtapCredentialManagement *state);
uint8_t ctap_credential_management_execute(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const uint8_t *input, size_t input_length,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);

#endif
