#ifndef RP2350_CRYPTO_H
#define RP2350_CRYPTO_H
#include "authenticator/auth_secret_crypto.h"
#include "mbedtls/hmac_drbg.h"
#define RP2350_CRYPTO_POOL_SIZE 65536U
#define RP2350_AES_MAX_BYTES 4096U
/* Bounded working slots, independent of durable credential capacity. */
#define RP2350_KEY_SLOTS 3U
/* Development primitive owner; durable restoration is a separate private binding.
 * Exactly one initialized instance:
 * Mbed TLS's bounded static allocator is process global. No libc heap fallback.
 * Caller must zero-initialize, serialize calls, and keep storage alive. */
typedef struct {
    bool used,public_ready;
    int32_t algorithm;
    AuthKeyHandle handle;
    uint8_t scalar[32]; /* P-256 scalar or Ed25519 seed, selected by algorithm. */
    uint8_t public_key[65], randoms[2][32];
} Rp2350Key;
typedef struct {
    mbedtls_hmac_drbg_context drbg;
    bool initialized, faulted, keys_locked;
    uint8_t epoch[24];
    uint64_t next_handle;
    Rp2350Key keys[RP2350_KEY_SLOTS];
    uint8_t agreement_scalar[32], agreement_public[65];
} Rp2350Crypto;
/* Entropy callback follows Mbed TLS: fill ALL requested bytes, return 0 only on
 * success. Public random outputs and new credential/agreement private keys
 * explicitly reseed. Internal blinding uses HMAC-DRBG with a 256-call reseed
 * limit. Any entropy failure revokes crypto service. Never supply the SDK
 * get_rand PRNG or deterministic data on target. */
AuthStatus rp2350_crypto_init(Rp2350Crypto *, int (*entropy)(void *, unsigned char *, size_t), void *);
void rp2350_crypto_free(Rp2350Crypto *);
/* Durable-provider working-key lifetime. Load only an independently
 * authenticated selected record; validate its scalar, algorithm and handle.
 * Derive a public point on demand (P-256 uses blinding), not for HMAC-only
 * operations or P-256 signing. Failure invalidates the provider. Clearing slots preserves session agreement
 * material/epoch/high-water, but never leaves a credential scalar resident. */
void rp2350_crypto_clear_credentials_internal(Rp2350Crypto *);
AuthStatus rp2350_crypto_load_record_internal(Rp2350Crypto *,const uint8_t[136]);
AuthCrypto rp2350_crypto_interface(Rp2350Crypto *);
AuthSecretCrypto rp2350_secret_interface(Rp2350Crypto *);
/* Target-private runtime reset gate. Invalidates ALL credential/agreement keys
 * immediately while keeping RNG/hash/MAC/AES available for storage recovery.
 * Staging regenerates agreement material and installs a freshly recovered
 * handle prefix/high-water; it never enables key service. Activate only after
 * complete recovery and application/PIN reinitialization. No durable binding
 * or physical erasure qualification is implied. Serialized owner-only calls. */
void rp2350_crypto_invalidate_internal(Rp2350Crypto *);
AuthStatus rp2350_crypto_stage_epoch_internal(Rp2350Crypto *,const uint8_t[24],uint64_t);
AuthStatus rp2350_crypto_activate_internal(Rp2350Crypto *);
#endif
