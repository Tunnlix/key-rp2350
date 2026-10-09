#include "ctap/ctap_hmac_secret.h"
#include "ctap/ctap_request.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/cbor_writer.h"

#include <string.h>

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
    uint8_t status = ctap_pin_public_key_parse(&key, result.peer_public);
    if (status != CTAP_STATUS_OK) return status;
    result.requested = true;
    result.salt_enc_length = (size_t)enc.value; result.salt_auth_length = (size_t)auth.value;
    memcpy(result.salt_enc, enc.data, result.salt_enc_length);
    memcpy(result.salt_auth, auth.data, result.salt_auth_length);
    *request = result;
    return CTAP_STATUS_OK;
}

static uint8_t decrypt_salts(const AuthSecretCrypto *crypto, const CtapHmacSecret *request,
    uint8_t keys[64], uint8_t salts[64])
{
    if (request->salt_enc_length != 48U && request->salt_enc_length != 80U) return CTAP_STATUS_INVALID_PARAMETER;
    if (request->salt_auth_length != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t status = ctap_pin_protocol_shared(crypto, request->peer_public, keys);
    if (status != CTAP_STATUS_OK) return status;
    status = ctap_pin_protocol_verify(crypto, keys, request->salt_enc, request->salt_enc_length,
        request->salt_auth, request->salt_auth_length);
    /* §12.7 maps all saltAuth verification failures to PIN_AUTH_INVALID. */
    if (status != CTAP_STATUS_OK) return CTAP_STATUS_PIN_AUTH_INVALID;
    return crypto->aes256_cbc(crypto->context, false, keys + 32U, request->salt_enc,
        request->salt_enc + 16U, request->salt_enc_length - 16U, salts) == AUTH_OK ?
        CTAP_STATUS_OK : CTAP_STATUS_INVALID_PARAMETER;
}

uint8_t ctap_hmac_secret_validate(AuthCredentialService *service, const CtapHmacSecret *request)
{
    if (service == NULL || !auth_secret_crypto_valid(&service->secrets) || request == NULL || !request->requested)
        return CTAP_STATUS_OTHER;
    uint8_t keys[64] = {0}, salts[64] = {0};
    uint8_t status = decrypt_salts(&service->secrets, request, keys, salts);
    auth_secure_zero(keys, sizeof keys); auth_secure_zero(salts, sizeof salts);
    return status;
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
    uint8_t keys[64] = {0}, salts[64] = {0}, results[64] = {0}, encrypted[80] = {0};
    uint8_t status = CTAP_STATUS_OTHER;
    size_t plain_length = request->salt_enc_length - 16U;
    status = decrypt_salts(crypto, request, keys, salts);
    if (status != CTAP_STATUS_OK) goto done;
    status = CTAP_STATUS_OTHER;
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
    auth_secure_zero(keys, sizeof keys);
    auth_secure_zero(salts, sizeof salts); auth_secure_zero(results, sizeof results); auth_secure_zero(encrypted, sizeof encrypted);
    return status;
}

uint8_t ctap_hmac_secret_key_agreement(AuthCredentialService *service,
    const uint8_t *input, size_t input_length, uint8_t *output, size_t capacity, size_t *length)
{
    if (service == NULL || !auth_secret_crypto_valid(&service->secrets) || output == NULL || length == NULL)
        return CTAP_STATUS_OTHER;
    CborValue fields[11] = {{0}}; bool present[11] = {false};
    uint8_t status = ctap_request_client_pin_map(input, input_length, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[1] || !present[2]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 0U || fields[2].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[2].value != 2U) return CTAP_STATUS_INVALID_SUBCOMMAND;
    return ctap_pin_key_agreement_encode(&service->secrets, output, capacity, length);
}
