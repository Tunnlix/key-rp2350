#ifndef RP2350_CRYPTO_CONFIG_H
#define RP2350_CRYPTO_CONFIG_H
/* Development provider shared by the board app and isolated tests.
 * AES is provided separately by pinned bitsliced
 * ctaes; the Mbed TLS table-based AES implementation is not compiled. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
/* Use a bounded precomputation table within the existing 64 KiB crypto arena.
 * Mbed TLS retains its scalar blinding and constant-time multiplication. */
#define MBEDTLS_ECP_WINDOW_SIZE 4
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 1
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_MPI_MAX_SIZE 32
#endif
