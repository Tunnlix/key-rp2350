#ifndef AUTH_PIN_H
#define AUTH_PIN_H

#include "authenticator/auth_platform.h"

#define AUTH_PIN_MAX_RETRIES 8U
#define AUTH_PIN_MAX_RP_IDS 4U

/* Persistent PIN verifier and policy, never plaintext. Code point length
 * permits raising the minimum and requiring a PIN change. A missing PIN has a zero verifier/length and
 * eight retries. This state is separate from credential metadata and keys. */
typedef struct {
    bool set;
    uint8_t hash[16];
    uint8_t code_points, retries;
    uint8_t min_length; /* Zero is the backwards-compatible default of four. */
    bool always_uv, force_change;
    /* Exact RP IDs are represented by their SHA-256 hashes, not suffix matches.
     * Unused entries are zero. The list is replaced by authenticated policy
     * configuration and cleared by the combined factory reset. */
    uint8_t min_length_rp_count;
    uint8_t min_length_rp_hashes[AUTH_PIN_MAX_RP_IDS][32];
} AuthPinRecord;

/* Serial, bounded callbacks. read returns a valid empty record for new storage.
 * write atomically persists before returning OK; errors must never authorize
 * work. No native struct serialization. Application factory reset must erase
 * this record together with credentials/keys in its combined reset callback. */
typedef struct {
    void *context;
    AuthStatus (*read)(void *, AuthPinRecord *);
    AuthStatus (*write)(void *, const AuthPinRecord *);
} AuthPinStorage;

bool auth_pin_record_valid(const AuthPinRecord *record);

#endif
