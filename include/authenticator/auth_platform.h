#ifndef AUTH_PLATFORM_H
#define AUTH_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ctap_config.h"
#include "authenticator/auth_credential_id.h"

#define AUTH_CREDENTIAL_ID_SIZE 32U /* Stored resident/stateful locator size. */
#define AUTH_RP_HASH_SIZE 32U
#define AUTH_USER_ID_MAX_SIZE 64U
#define AUTH_ENTITY_NAME_MAX_SIZE 64U
#define AUTH_RP_ID_MAX_SIZE CTAP_MESSAGE_CAPACITY
#define AUTH_RESIDENT_MAX_COUNT CTAP_RESIDENT_CAPACITY
#define AUTH_KEY_HANDLE_SIZE 32U
#define AUTH_P256_PUBLIC_KEY_SIZE 65U /* SEC1 uncompressed: 04 || X[32] || Y[32]. */
#define AUTH_ES256_DER_MAX_SIZE 72U
#define AUTH_COSE_ALG_ES256 (-7)
#define AUTH_COSE_ALG_EDDSA (-8)

typedef enum {
    AUTH_OK = 0,
    AUTH_INVALID_ARGUMENT,
    AUTH_NOT_FOUND,
    AUTH_ALREADY_EXISTS,
    AUTH_CAPACITY,
    AUTH_IO_ERROR,
    AUTH_BAD_DATA,
    AUTH_CRYPTO_ERROR,
    AUTH_BUSY,
    AUTH_UNSUPPORTED
} AuthStatus;

/* Persistent opaque locator. Only its owning crypto provider interprets bytes.
 * Zero is invalid. Handles are provider-specific and must not be reused after
 * deletion/reset. Moving existing keys to another provider requires migration
 * supported by that provider, or re-enrollment; changing callbacks is not migration. */
typedef struct { uint8_t bytes[AUTH_KEY_HANDLE_SIZE]; } AuthKeyHandle;

/* No private key bytes. Core caller validates CTAP parameters/user consent before
 * using these operations. Callbacks are serial, bounded, and non-reentrant.
 * Contexts remain application-owned and outlive all copies of these interfaces. */
/* random must be a cryptographically secure generator and fail when unavailable.
 * P-256 providers validate their keys, protect scalar/nonce operations against
 * side channels, and wipe internal secret scratch on every exit. Signing returns
 * a complete DER ECDSA signature of at most AUTH_ES256_DER_MAX_SIZE bytes;
 * signature_length is an output, not an input capacity. Key-generation failure
 * must clean up any partially created key before returning. */
typedef struct {
    void *context;
    AuthStatus (*random)(void *, uint8_t *, size_t);
    AuthStatus (*sha256)(void *, const uint8_t *, size_t, uint8_t digest[32]);
    AuthStatus (*generate_p256)(void *, AuthKeyHandle *, uint8_t public_key[65]);
    AuthStatus (*public_key)(void *, const AuthKeyHandle *, uint8_t public_key[65]);
    AuthStatus (*sign_p256_digest)(void *, const AuthKeyHandle *, const uint8_t digest[32],
        uint8_t signature[AUTH_ES256_DER_MAX_SIZE], size_t *signature_length);
    AuthStatus (*destroy_key)(void *, const AuthKeyHandle *);
    /* Optional complete Ed25519 pair. Public-key transport uses the existing
     * 65-byte buffer: Ed25519 occupies the first 32 bytes, with 33 zero bytes.
     * Sign the original message (PureEd25519), never a SHA-256 digest or Ed25519ph.
     * Existing public_key/destroy_key callbacks must handle both key kinds. */
    AuthStatus (*generate_ed25519)(void *, AuthKeyHandle *, uint8_t public_key[65]);
    AuthStatus (*sign_ed25519)(void *, const AuthKeyHandle *, const uint8_t *, size_t,
        uint8_t signature[64]);
} AuthCrypto;

typedef struct {
    uint8_t credential_id[AUTH_CREDENTIAL_ID_SIZE];
    uint8_t rp_id_hash[AUTH_RP_HASH_SIZE];
    uint8_t user_id[AUTH_USER_ID_MAX_SIZE];
    uint8_t user_id_length;
    AuthKeyHandle key;
    int32_t algorithm;
    uint32_t signature_count;
    bool discoverable;
    uint8_t cred_protect; /* CTAP policy 1..3, persisted with metadata. */
    uint8_t rp_id[AUTH_RP_ID_MAX_SIZE], rp_name[AUTH_ENTITY_NAME_MAX_SIZE];
    uint8_t user_name[AUTH_ENTITY_NAME_MAX_SIZE], user_display_name[AUTH_ENTITY_NAME_MAX_SIZE];
    uint16_t rp_id_length;
    uint8_t rp_name_length, user_name_length, user_display_name_length;
    uint8_t cred_blob[32], cred_blob_length;
    bool large_blob_key; /* Domain-separated provider derivation enabled at creation. */
    uint64_t creation_order; /* Relative creation order for newest-first discovery. */
} AuthCredential;

/* Metadata backend: do not serialize native C struct layout to persistent media.
 * insert and counter update must persist atomically before returning OK.
 * Lookup/enumeration return NOT_FOUND at end; corruption must fail closed.
 * erase removes metadata only. Key deletion remains a crypto-provider operation.
 * Factory reset is the application's combined storage/key reset callback. */
typedef struct {
    void *context;
    size_t capacity;
    AuthStatus (*read)(void *, const uint8_t id[32], AuthCredential *);
    AuthStatus (*insert)(void *, const AuthCredential *);
    AuthStatus (*erase)(void *, const uint8_t id[32]);
    AuthStatus (*find_rp)(void *, const uint8_t rp_hash[32], bool discoverable_only,
        size_t index, AuthCredential *);
    AuthStatus (*count)(void *, size_t *);
    AuthStatus (*update_counter)(void *, const uint8_t id[32], uint32_t expected, uint32_t next);
    /* Optional discoverable support, required as a complete group. enumerate
     * visits all metadata in stable order, NOT_FOUND at end. Mutations atomically
     * commit metadata AND the supplied fresh credential-store state. put_resident
     * replaces old_id when non-NULL, including at capacity; old keys are deleted
     * by the service only after commit. Crypto providers need one staging key
     * slot beyond metadata capacity. update_user changes names only, never ID,
     * RP binding, key, policy, counter or creation order. All errors fail closed. */
    AuthStatus (*enumerate)(void *, size_t index, AuthCredential *);
    AuthStatus (*put_resident)(void *, const uint8_t *old_id, const AuthCredential *, const uint8_t state[16]);
    AuthStatus (*erase_resident)(void *, const uint8_t id[32], const uint8_t state[16]);
    AuthStatus (*update_user)(void *, const AuthCredential *, const uint8_t state[16]);
} AuthStorage;

bool auth_algorithm_valid(int32_t algorithm);
/* Encoding/container checks; the provider is responsible for curve validity. */
bool auth_public_key_valid(int32_t algorithm, const uint8_t public_key[65]);
bool auth_credential_valid(const AuthCredential *credential);
bool auth_key_handle_valid(const AuthKeyHandle *key);
bool auth_text_valid(const uint8_t *data, size_t length);

#endif
