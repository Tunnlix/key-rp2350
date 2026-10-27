#ifndef CTAP_PIN_PROTOCOL_H
#define CTAP_PIN_PROTOCOL_H

#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"
#include "authenticator/auth_secret_crypto.h"

/* Protocol 2: HMAC key followed by AES key. The caller must wipe keys[64]
 * after use, including after failure: a failed derivation can leave partial key
 * material in that output. Helpers wipe their own intermediate secrets. */
/* Versioned helpers support protocols 1 and 2. Zero is reserved as the
 * previous internal API's protocol-2 default; wire parsers reject zero. */
uint8_t ctap_pin_protocol_shared_version(const AuthCrypto *, const AuthSecretCrypto *, uint8_t,
    const uint8_t peer[65], uint8_t keys[64]);
uint8_t ctap_pin_protocol_verify_version(const AuthSecretCrypto *, uint8_t, const uint8_t keys[64],
    const uint8_t *, size_t, const uint8_t *, size_t);
uint8_t ctap_pin_protocol_decrypt(const AuthSecretCrypto *, uint8_t, const uint8_t keys[64],
    const uint8_t *, size_t, uint8_t *);
uint8_t ctap_pin_protocol_encrypt(const AuthCrypto *, const AuthSecretCrypto *, uint8_t,
    const uint8_t keys[64], const uint8_t *, size_t, uint8_t *);
size_t ctap_pin_protocol_prefix(uint8_t);
size_t ctap_pin_protocol_auth_length(uint8_t);
uint8_t ctap_pin_public_key_parse(const CborValue *map, uint8_t output[65]);
bool ctap_pin_protocol_derive(const AuthSecretCrypto *crypto, const uint8_t z[32], uint8_t keys[64]);
uint8_t ctap_pin_protocol_shared(const AuthSecretCrypto *crypto, const uint8_t peer[65], uint8_t keys[64]);
uint8_t ctap_pin_protocol_verify(const AuthSecretCrypto *crypto, const uint8_t keys[64],
    const uint8_t *message, size_t length, const uint8_t *mac, size_t mac_length);
bool ctap_pin_equal(const uint8_t *left, const uint8_t *right, size_t length);
uint8_t ctap_pin_key_agreement_encode(const AuthSecretCrypto *crypto,
    uint8_t *output, size_t capacity, size_t *length);

#endif
