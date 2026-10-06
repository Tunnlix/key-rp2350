#ifndef AUTH_CREDENTIALS_H
#define AUTH_CREDENTIALS_H

#include "authenticator/auth_platform.h"

/* Pure core composition; no files, OS, heap, or private-key access. */
typedef struct { AuthCrypto crypto; AuthStorage storage; } AuthCredentialService;

bool auth_credentials_init(AuthCredentialService *service,
    const AuthCrypto *crypto, const AuthStorage *storage);

/* Store a new credential with a random ID and provider-owned P-256 key. Output
 * is published only after metadata persistence succeeds. On insert failure the
 * new key is destroyed; cleanup failure returns IO_ERROR and requires provider
 * recovery/garbage collection. No automatic credential overwrites or retries. */
AuthStatus auth_credentials_create(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, AuthCredential *credential, uint8_t public_key[65]);

/* RP binding is checked before returning metadata or signing. This does not
 * establish UP/UV itself: the future CTAP handler must authorize the operation. */
AuthStatus auth_credentials_get(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], AuthCredential *credential);
AuthStatus auth_credentials_sign_digest(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], const uint8_t digest[32],
    uint8_t signature[72], size_t *signature_length);

/* Commit the next counter before building/signing authenticatorData. Failures
 * must abort assertion generation. Skipped counters are allowed; wrap is not. */
AuthStatus auth_credentials_next_counter(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], uint32_t *counter);

/* Erase metadata before destroying its key so failures cannot leave usable
 * credential metadata pointing at a missing/reused key. A deletion failure may
 * leave an unreferenced key; it must not be interpreted as a successful delete. */
AuthStatus auth_credentials_delete(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32]);

#endif
