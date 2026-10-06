#include "ctap/ctap_hmac_secret.h"
#include "ctap/ctap_request.h"
#include "ctap/cbor_writer.h"

#include <string.h>

static uint8_t public_key(const CborValue *map, uint8_t output[65])
{
    if (map->major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    CborValue type, alg, curve, x, y;
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

uint8_t ctap_hmac_secret_parse(const CborValue *input, CtapHmacSecret *request)
{
    if (input == NULL || request == NULL) return CTAP_STATUS_OTHER;
    if (input->major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    CborValue key, enc, auth, protocol;
    if (!cbor_map_uint(input, 1U, &key) || !cbor_map_uint(input, 2U, &enc) || !cbor_map_uint(input, 3U, &auth))
        return CTAP_STATUS_MISSING_PARAMETER;
    if (!cbor_map_uint(input, 4U, &protocol)) return CTAP_STATUS_PIN_AUTH_INVALID; /* No default protocol 1. */
    if (protocol.major != 0U || enc.major != 2U || auth.major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (protocol.value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    if (enc.value != 48U && enc.value != 80U) return CTAP_STATUS_INVALID_PARAMETER;
    if (auth.value > 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
    CtapHmacSecret result = {0};
    uint8_t status = public_key(&key, result.peer_public);
    if (status != CTAP_STATUS_OK) return status;
    result.requested = true;
    result.salt_enc_length = (size_t)enc.value; result.salt_auth_length = (size_t)auth.value;
    memcpy(result.salt_enc, enc.data, result.salt_enc_length);
    memcpy(result.salt_auth, auth.data, result.salt_auth_length);
    *request = result;
    return CTAP_STATUS_OK;
}

/* Protocol 2: HKDF extract once, then two separate 32-byte expand invocations.
 * This is not a single 64-byte HKDF expansion. */
static bool derive(const AuthSecretCrypto *crypto, const uint8_t z[32], uint8_t keys[64])
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

uint8_t ctap_hmac_secret_evaluate(AuthCredentialService *service,
    const AuthCredential *credential, const CtapHmacSecret *request, bool user_verified,
    uint8_t output[80], size_t *length)
{
    if (service == NULL || !auth_secret_crypto_valid(&service->secrets) || !auth_credential_valid(credential) ||
        request == NULL || !request->requested || output == NULL || length == NULL) return CTAP_STATUS_OTHER;
    if (request->salt_enc_length != 48U && request->salt_enc_length != 80U) return CTAP_STATUS_INVALID_PARAMETER;
    if (request->salt_auth_length != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
    const AuthSecretCrypto *crypto = &service->secrets;
    uint8_t z[32] = {0}, keys[64] = {0}, mac[32] = {0}, salts[64] = {0}, results[64] = {0}, encrypted[80] = {0};
    uint8_t status = CTAP_STATUS_OTHER;
    size_t plain_length = request->salt_enc_length - 16U;
    AuthStatus agreement = crypto->ecdh(crypto->context, request->peer_public, z);
    if (agreement != AUTH_OK) {
        if (agreement == AUTH_BAD_DATA || agreement == AUTH_INVALID_ARGUMENT) status = CTAP_STATUS_INVALID_PARAMETER;
        goto done;
    }
    if (!derive(crypto, z, keys) || crypto->hmac_sha256(crypto->context, keys, 32U,
        request->salt_enc, request->salt_enc_length, mac) != AUTH_OK) goto done;
    volatile uint8_t different = 0U; /* Fixed 32-byte comparison; no early exit. */
    for (size_t i = 0U; i < 32U; ++i) different |= mac[i] ^ request->salt_auth[i];
    if (different != 0U) { status = CTAP_STATUS_PIN_AUTH_INVALID; goto done; }
    if (crypto->aes256_cbc(crypto->context, false, keys + 32U, request->salt_enc,
        request->salt_enc + 16U, plain_length, salts) != AUTH_OK) { status = CTAP_STATUS_INVALID_PARAMETER; goto done; }
    for (size_t i = 0U; i < plain_length; i += 32U) {
        AuthStatus evaluated = crypto->credential_hmac(crypto->context, &credential->key, user_verified, salts + i, results + i);
        if (evaluated == AUTH_NOT_FOUND) { *length = 0U; status = CTAP_STATUS_OK; goto done; }
        if (evaluated != AUTH_OK) goto done;
    }
    if (service->crypto.random(service->crypto.context, encrypted, 16U) != AUTH_OK ||
        crypto->aes256_cbc(crypto->context, true, keys + 32U, encrypted, results, plain_length, encrypted + 16U) != AUTH_OK) goto done;
    memcpy(output, encrypted, 16U + plain_length); *length = 16U + plain_length;
    status = CTAP_STATUS_OK;
done:
    auth_secure_zero(z, sizeof z); auth_secure_zero(keys, sizeof keys); auth_secure_zero(mac, sizeof mac);
    auth_secure_zero(salts, sizeof salts); auth_secure_zero(results, sizeof results); auth_secure_zero(encrypted, sizeof encrypted);
    return status;
}

uint8_t ctap_hmac_secret_key_agreement(AuthCredentialService *service,
    const uint8_t *input, size_t input_length, uint8_t *output, size_t capacity, size_t *length)
{
    if (service == NULL || !auth_secret_crypto_valid(&service->secrets) || output == NULL || length == NULL)
        return CTAP_STATUS_OTHER;
    CborValue fields[3] = {{0}}; bool present[3] = {false};
    uint8_t status = ctap_request_map(input, input_length, 3U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[1] || !present[2]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 0U || fields[2].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[2].value != 2U) return CTAP_STATUS_INVALID_SUBCOMMAND;
    uint8_t key[65], encoded[96];
    if (service->secrets.key_agreement(service->secrets.context, key) != AUTH_OK || key[0] != 4U) return CTAP_STATUS_OTHER;
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
