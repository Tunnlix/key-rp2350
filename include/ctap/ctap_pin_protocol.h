#ifndef CTAP_PIN_PROTOCOL_H
#define CTAP_PIN_PROTOCOL_H

#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"
#include "authenticator/auth_secret_crypto.h"

/* Protocol 2 only: HMAC key followed by AES key. Helpers do not retain keys. */
uint8_t ctap_pin_public_key_parse(const CborValue *map, uint8_t output[65]);
bool ctap_pin_protocol_derive(const AuthSecretCrypto *crypto, const uint8_t z[32], uint8_t keys[64]);
uint8_t ctap_pin_protocol_shared(const AuthSecretCrypto *crypto, const uint8_t peer[65], uint8_t keys[64]);
uint8_t ctap_pin_protocol_verify(const AuthSecretCrypto *crypto, const uint8_t keys[64],
    const uint8_t *message, size_t length, const uint8_t *mac, size_t mac_length);
bool ctap_pin_equal(const uint8_t *left, const uint8_t *right, size_t length);
uint8_t ctap_pin_key_agreement_encode(const AuthSecretCrypto *crypto,
    uint8_t *output, size_t capacity, size_t *length);

#endif
