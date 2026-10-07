#include "ctap/ctap_pin_protocol.h"
#include "ctap/cbor_writer.h"

#include <string.h>

uint8_t ctap_pin_public_key_parse(const CborValue *map, uint8_t output[65])
{
    if (map->major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    CborValue type, alg, curve, x, y;
    CborValue optional;
    /* Public key agreement allows alg but not the known optional COSE key
     * parameters or a private scalar. Unknown future map keys are ignored. */
    if (cbor_map_int(map, 2, &optional) || cbor_map_int(map, 4, &optional) ||
        cbor_map_int(map, 5, &optional) || cbor_map_int(map, -4, &optional)) return CTAP_STATUS_INVALID_PARAMETER;
    if (!cbor_map_int(map, 1, &type) || !cbor_map_int(map, 3, &alg) || !cbor_map_int(map, -1, &curve) ||
        !cbor_map_int(map, -2, &x) || !cbor_map_int(map, -3, &y)) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (type.major != 0U || alg.major > 1U || curve.major != 0U || x.major != 2U || y.major != 2U)
        return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (type.value != 2U || alg.major != 1U || alg.value != 24U || curve.value != 1U || x.value != 32U || y.value != 32U)
        return CTAP_STATUS_INVALID_PARAMETER;
    output[0] = 4U;
    memcpy(output + 1U, x.data, 32U); memcpy(output + 33U, y.data, 32U);
    return CTAP_STATUS_OK;
}

/* Protocol 2: HKDF extract once, then two separate 32-byte expand invocations.
 * This is not a single 64-byte HKDF expansion. */
bool ctap_pin_protocol_derive(const AuthSecretCrypto *crypto, const uint8_t z[32], uint8_t keys[64])
{
    uint8_t zero[32] = {0}, prk[32], info[16];
    const char *labels[] = {"CTAP2 HMAC key", "CTAP2 AES key"};
    bool ok = crypto->hmac_sha256(crypto->context, zero, sizeof zero, z, 32U, prk) == AUTH_OK;
    for (size_t i = 0U; ok && i < 2U; ++i) {
        size_t len = strlen(labels[i]); memcpy(info, labels[i], len); info[len] = 1U;
        ok = crypto->hmac_sha256(crypto->context, prk, 32U, info, len + 1U, keys + 32U * i) == AUTH_OK;
    }
    auth_secure_zero(prk, sizeof prk); auth_secure_zero(info, sizeof info);
    return ok;
}

uint8_t ctap_pin_key_agreement_encode(const AuthSecretCrypto *crypto,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (!auth_secret_crypto_valid(crypto) || output == NULL || length == NULL) return CTAP_STATUS_OTHER;
    uint8_t key[65], encoded[96];
    if (crypto->key_agreement(crypto->context, key) != AUTH_OK || key[0] != 4U) return CTAP_STATUS_OTHER;
    CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
    bool ok = cbor_write_map(&writer, 1U) && cbor_write_uint(&writer, 1U) && cbor_write_map(&writer, 5U) &&
        cbor_write_int(&writer, 1) && cbor_write_int(&writer, 2) &&
        cbor_write_int(&writer, 3) && cbor_write_int(&writer, -25) &&
        cbor_write_int(&writer, -1) && cbor_write_int(&writer, 1) &&
        cbor_write_int(&writer, -2) && cbor_write_bytes(&writer, key + 1U, 32U) &&
        cbor_write_int(&writer, -3) && cbor_write_bytes(&writer, key + 33U, 32U);
    if (!ok || writer.length > capacity) return CTAP_STATUS_OTHER;
    memcpy(output, encoded, writer.length); *length = writer.length;
    return CTAP_STATUS_OK;
}

bool ctap_pin_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    /* Scan every byte; an early return would reveal the matching prefix.
     * Check generated code/timing with the final compiler and target as well. */
    volatile uint8_t different = 0U;
    for (size_t i = 0U; i < length; ++i) different |= left[i] ^ right[i];
    return different == 0U;
}

uint8_t ctap_pin_protocol_shared(const AuthSecretCrypto *crypto, const uint8_t peer[65], uint8_t keys[64])
{
    uint8_t z[32] = {0};
    AuthStatus agreement = crypto->ecdh(crypto->context, peer, z);
    uint8_t status = CTAP_STATUS_OTHER;
    if (agreement == AUTH_BAD_DATA || agreement == AUTH_INVALID_ARGUMENT) status = CTAP_STATUS_INVALID_PARAMETER;
    else if (agreement == AUTH_OK && ctap_pin_protocol_derive(crypto, z, keys)) status = CTAP_STATUS_OK;
    auth_secure_zero(z, sizeof z);
    return status;
}

uint8_t ctap_pin_protocol_verify(const AuthSecretCrypto *crypto, const uint8_t keys[64],
    const uint8_t *message, size_t length, const uint8_t *mac, size_t mac_length)
{
    if (mac_length != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t expected[32] = {0};
    uint8_t status = CTAP_STATUS_OTHER;
    if (crypto->hmac_sha256(crypto->context, keys, 32U, message, length, expected) == AUTH_OK)
        status = ctap_pin_equal(expected, mac, 32U) ? CTAP_STATUS_OK : CTAP_STATUS_PIN_AUTH_INVALID;
    auth_secure_zero(expected, sizeof expected);
    return status;
}
