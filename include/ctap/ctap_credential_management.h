#ifndef CTAP_CREDENTIAL_MANAGEMENT_H
#define CTAP_CREDENTIAL_MANAGEMENT_H

#include "ctap/ctap_client_pin.h"

/* Per-instance command workspace, wiped after every execute call. No private
 * key material is exported here; records contain opaque provider handles. */
typedef struct {
    AuthCredential record, updated_user;
    uint8_t bytes[CTAP_MAX_RESPONSE_SIZE];
    uint8_t rp_hashes[AUTH_RESIDENT_MAX_COUNT][32];
} CtapCredentialManagementScratch;

/* Authenticated snapshot of IDs only. Core revision/token replacement and a
 * 30-second inactivity timeout invalidate it. Transport binds it to a CID.
 * Allocate this state (or its enclosing backend) in static/caller-owned RAM,
 * not on a command's stack. Calls and provider callbacks must not reenter the
 * same instance. Input/output buffers must not alias this state. */
typedef struct {
    uint8_t ids[AUTH_RESIDENT_MAX_COUNT][32], rp_hash[32];
    size_t count, next;
    uint8_t kind;
    uint64_t token_generation, metadata_revision;
    uint32_t last_call_ms;
    CtapCredentialManagementScratch scratch;
} CtapCredentialManagement;

void ctap_credential_management_clear(CtapCredentialManagement *state);
uint8_t ctap_credential_management_execute(AuthCredentialService *service, CtapClientPin *pin,
    CtapCredentialManagement *state, const uint8_t *input, size_t input_length,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);

#endif
