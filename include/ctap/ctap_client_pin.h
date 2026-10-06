#ifndef CTAP_CLIENT_PIN_H
#define CTAP_CLIENT_PIN_H

#include "authenticator/auth_pin.h"
#include "authenticator/auth_credentials.h"
#include "ctap/ctap.h"

/* Development PIN maintenance milestone only. No tokens, permissions or UV
 * authorization; do not advertise clientPin/UV/token support from this module.
 * Initialize at real power-on. INIT must not reset consecutive failures. */
typedef struct {
    AuthCredentialService *service;
    AuthPinStorage storage;
    uint8_t consecutive_failures;
    bool faulted;
} CtapClientPin;

/* Only public/ciphertext data, safe to discard on CANCEL/resynchronization. */
typedef struct {
    uint8_t subcommand;
    uint8_t peer[65], new_pin_enc[80], pin_hash_enc[32], auth[32];
    size_t auth_length;
} CtapClientPinRequest;

bool ctap_client_pin_init(CtapClientPin *pin, AuthCredentialService *service, const AuthPinStorage *storage);
uint8_t ctap_client_pin_prepare(const uint8_t *input, size_t length, CtapClientPinRequest *request);
/* Execute only outside transport callbacks after checking transaction ownership.
 * read/write/crypto failure fails closed. Successful set/change has no CBOR body.
 * Failure leaves output/length unchanged, although retries may have committed. */
uint8_t ctap_client_pin_execute(CtapClientPin *pin, const CtapClientPinRequest *request,
    uint8_t *output, size_t capacity, size_t *length);
/* Call ONLY after the application's combined persistent factory reset succeeds.
 * Persistent deletion is the application's responsibility; this clears RAM. */
void ctap_client_pin_reset_state(CtapClientPin *pin);

#endif
