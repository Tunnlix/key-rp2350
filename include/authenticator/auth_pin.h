#ifndef AUTH_PIN_H
#define AUTH_PIN_H

#include "authenticator/auth_platform.h"

#define AUTH_PIN_MAX_RETRIES 8U

/* Persistent PIN verifier, never plaintext. Code point length is retained for
 * future minimum-length policy. A missing PIN has a zero verifier/length and
 * eight retries. This state is separate from credential metadata and keys. */
typedef struct {
    bool set;
    uint8_t hash[16];
    uint8_t code_points, retries;
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
