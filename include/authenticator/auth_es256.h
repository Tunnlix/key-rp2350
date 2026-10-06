#ifndef AUTH_ES256_H
#define AUTH_ES256_H
#include "authenticator/auth_platform.h"

/* Encoding only, not cryptographic arithmetic. Convert provider r||s[64] to
 * WebAuthn's DER ECDSA signature format using positive, minimal ASN.1 integers.
 * Rejects zero r/s and insufficient capacity without changing output/length. */
bool auth_es256_signature_to_der(const uint8_t raw[64], uint8_t *der,
    size_t capacity, size_t *length);
#endif
