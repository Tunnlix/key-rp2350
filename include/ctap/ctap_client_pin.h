#ifndef CTAP_CLIENT_PIN_H
#define CTAP_CLIENT_PIN_H

#include "authenticator/auth_pin.h"
#include "authenticator/auth_credentials.h"
#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"

#define CTAP_PIN_PERMISSION_MC 0x01U
#define CTAP_PIN_PERMISSION_GA 0x02U
#define CTAP_PIN_INITIAL_TIMEOUT_MS 30000U
#define CTAP_PIN_MAX_TIMEOUT_MS 600000U

/* Protocol 2 PINs and volatile permission-scoped tokens. No built-in UV or
 * persistent tokens. Initialize at real power-on; INIT cannot reset retries.
 * Poll on the injected device clock, including while idle/waiting for touch.
 * USB initial-use limit 30 s, total lifetime 600 s; no cached user presence. */
typedef struct {
    AuthCredentialService *service;
    AuthPinStorage storage;
    uint8_t consecutive_failures;
    bool faulted;
    bool pin_set;
    uint8_t token[32], token_rp_hash[32], permissions;
    uint32_t issued_at_ms;
    bool token_active, token_used;
    uint64_t token_generation;
} CtapClientPin;

/* Only public/ciphertext data, safe to discard on CANCEL/resynchronization. */
typedef struct {
    uint8_t subcommand;
    uint8_t peer[65], new_pin_enc[80], pin_hash_enc[32], auth[32];
    size_t auth_length;
    uint64_t permissions;
    bool rp_present;
    uint8_t rp_id[1024];
    size_t rp_length;
} CtapClientPinRequest;

typedef struct {
    bool present, probe;
    uint8_t mac[32];
    uint64_t token_generation;
} CtapPinAuth;

bool ctap_client_pin_init(CtapClientPin *pin, AuthCredentialService *service, const AuthPinStorage *storage);
uint8_t ctap_client_pin_prepare(const uint8_t *input, size_t length, CtapClientPinRequest *request);
/* Execute only outside transport callbacks after checking transaction ownership.
 * read/write/crypto failure fails closed. Successful set/change has no CBOR body.
 * Failure leaves output/length unchanged, although retries may have committed. */
uint8_t ctap_client_pin_execute(CtapClientPin *pin, const CtapClientPinRequest *request,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms);
/* Call ONLY after the application's combined persistent factory reset succeeds.
 * Persistent deletion is the application's responsibility; this clears RAM and
 * regenerates an inactive token. RNG failure sets faulted: return a CTAP failure
 * rather than claiming success, even if persistent deletion already committed. */
void ctap_client_pin_reset_state(CtapClientPin *pin);
void ctap_client_pin_poll(CtapClientPin *pin, uint32_t now_ms);
void ctap_client_pin_invalidate(CtapClientPin *pin);
uint8_t ctap_client_pin_status(CtapClientPin *pin, bool *set);
uint8_t ctap_client_pin_probe(CtapClientPin *pin);
uint8_t ctap_pin_auth_parse(CtapClientPin *pin, const CborValue *param,
    const CborValue *protocol, CtapPinAuth *auth);
/* mark_used only after the entire request is validated. Revalidate the same
 * token generation after waiting for UP, before key/counter/signing effects. */
uint8_t ctap_client_pin_authorize(CtapClientPin *pin, CtapPinAuth *auth,
    const uint8_t rp_hash[32], const uint8_t client_data_hash[32], uint8_t permission,
    uint32_t now_ms, bool mark_used);

#endif
