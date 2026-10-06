#ifndef AUTH_SECRET_CRYPTO_H
#define AUTH_SECRET_CRYPTO_H

#include "authenticator/auth_platform.h"

/* Optional hmac-secret primitives. Provider owns an ephemeral P-256 ECDH key
 * initialized at power-on and regenerated on factory reset. Its private bytes
 * never leave the provider. ecdh outputs the raw, big-endian x-coordinate Z;
 * the portable protocol layer applies HKDF. CBC has no padding, lengths 16/32/64.
 * Credential randoms are two independent persistent 32-byte values generated
 * with each credential key, even when registration did not request hmac-secret.
 * They remain provider-owned and are erased with key deletion/factory reset.
 * credential_hmac returns NOT_FOUND for a legacy key without these randoms.
 * This interface also supports future chip-owned secret/key handles. */
typedef struct {
    void *context;
    AuthStatus (*key_agreement)(void *, uint8_t public_key[65]);
    AuthStatus (*ecdh)(void *, const uint8_t peer_public[65], uint8_t z[32]);
    AuthStatus (*hmac_sha256)(void *, const uint8_t *key, size_t key_length,
        const uint8_t *message, size_t message_length, uint8_t result[32]);
    AuthStatus (*aes256_cbc)(void *, bool encrypt, const uint8_t key[32],
        const uint8_t iv[16], const uint8_t *input, size_t length, uint8_t *output);
    AuthStatus (*credential_supported)(void *, const AuthKeyHandle *, bool *supported);
    AuthStatus (*credential_hmac)(void *, const AuthKeyHandle *, bool user_verified,
        const uint8_t salt[32], uint8_t result[32]);
    /* Optional for hmac-secret, required for PIN/token support. Replace the
     * ephemeral agreement key atomically; failure must leave it unusable or
     * return an error so the caller can fail closed. Does not alter credentials. */
    AuthStatus (*regenerate)(void *);
} AuthSecretCrypto;

bool auth_secret_crypto_valid(const AuthSecretCrypto *crypto);
/* Best-effort portable clearing of transient sensitive buffers; volatile writes
 * prevent dead-store elimination. Does not replace provider/hardware erasure. */
void auth_secure_zero(void *buffer, size_t length);

#endif
