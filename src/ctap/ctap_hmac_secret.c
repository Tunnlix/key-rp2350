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
    if (!cbor_map_uint(input, 4U, &protocol)) protocol = (CborValue){.major=0U,.value=1U};
    if (protocol.major != 0U || enc.major != 2U || auth.major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (protocol.value != 1U && protocol.value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    size_t prefix = ctap_pin_protocol_prefix((uint8_t)protocol.value);
    if (enc.value != 32U + prefix && enc.value != 64U + prefix) return CTAP_STATUS_INVALID_PARAMETER;
    if (auth.value > ctap_pin_protocol_auth_length((uint8_t)protocol.value)) return CTAP_STATUS_PIN_AUTH_INVALID;
    CtapHmacSecret result = {0};
    uint8_t status = ctap_pin_public_key_parse(&key, result.peer_public);
    if (status != CTAP_STATUS_OK) return status;
    result.requested = true; result.protocol = (uint8_t)protocol.value;
    result.salt_enc_length = (size_t)enc.value; result.salt_auth_length = (size_t)auth.value;
    memcpy(result.salt_enc, enc.data, result.salt_enc_length);
    memcpy(result.salt_auth, auth.data, result.salt_auth_length);
    *request = result;
    return CTAP_STATUS_OK;
}

static uint8_t decrypt_salts(AuthCredentialService *service, const CtapHmacSecret *request,
    uint8_t keys[64], uint8_t salts[64])
{
    const AuthSecretCrypto *crypto = &service->secrets;
    size_t prefix = ctap_pin_protocol_prefix(request->protocol);
    if (request->protocol > 2U || (request->salt_enc_length != 32U + prefix && request->salt_enc_length != 64U + prefix))
        return CTAP_STATUS_INVALID_PARAMETER;
    if (request->salt_auth_length != ctap_pin_protocol_auth_length(request->protocol)) return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t status = ctap_pin_protocol_shared_version(&service->crypto, crypto, request->protocol, request->peer_public, keys);
    if (status != CTAP_STATUS_OK) return status;
    status = ctap_pin_protocol_verify_version(crypto, request->protocol, keys, request->salt_enc, request->salt_enc_length,
        request->salt_auth, request->salt_auth_length);
    /* §12.7 maps all saltAuth verification failures to PIN_AUTH_INVALID. */
    if (status != CTAP_STATUS_OK) return CTAP_STATUS_PIN_AUTH_INVALID;
    return ctap_pin_protocol_decrypt(crypto, request->protocol, keys, request->salt_enc, request->salt_enc_length, salts);
}

uint8_t ctap_hmac_secret_validate(AuthCredentialService *service, const CtapHmacSecret *request)
{
    if (service == NULL || !auth_secret_crypto_valid(&service->secrets) || request == NULL || !request->requested)
        return CTAP_STATUS_OTHER;
    uint8_t keys[64] = {0}, salts[64] = {0};
    uint8_t status = decrypt_salts(service, request, keys, salts);
    auth_secure_zero(keys, sizeof keys); auth_secure_zero(salts, sizeof salts);
    return status;
}

uint8_t ctap_hmac_secret_evaluate(AuthCredentialService *service,
    const AuthCredential *credential, const CtapHmacSecret *request, bool user_verified,
    uint8_t output[80], size_t *length)
{
    if (service == NULL || !auth_secret_crypto_valid(&service->secrets) || !auth_credential_valid(credential) ||
        request == NULL || !request->requested || output == NULL || length == NULL) return CTAP_STATUS_OTHER;
    size_t prefix = ctap_pin_protocol_prefix(request->protocol);
    if (request->protocol > 2U || (request->salt_enc_length != 32U + prefix && request->salt_enc_length != 64U + prefix))
        return CTAP_STATUS_INVALID_PARAMETER;
    if (request->salt_auth_length != ctap_pin_protocol_auth_length(request->protocol)) return CTAP_STATUS_PIN_AUTH_INVALID;
    const AuthSecretCrypto *crypto = &service->secrets;
    uint8_t keys[64] = {0}, salts[64] = {0}, results[64] = {0}, encrypted[80] = {0};
    uint8_t status = CTAP_STATUS_OTHER;
    size_t plain_length = request->salt_enc_length - prefix;
    status = decrypt_salts(service, request, keys, salts);
    if (status != CTAP_STATUS_OK) goto done;
    status = CTAP_STATUS_OTHER;
    for (size_t i = 0U; i < plain_length; i += 32U) {
        AuthStatus evaluated = crypto->credential_hmac(crypto->context, &credential->key, user_verified, salts + i, results + i);
        if (evaluated == AUTH_NOT_FOUND) { *length = 0U; status = CTAP_STATUS_OK; goto done; }
        if (evaluated != AUTH_OK) goto done;
    }
    if (ctap_pin_protocol_encrypt(&service->crypto, crypto, request->protocol, keys, results, plain_length, encrypted) != CTAP_STATUS_OK) goto done;
    memcpy(output, encrypted, prefix + plain_length); *length = prefix + plain_length;
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
    if ((fields[1].value != 1U && fields[1].value != 2U)) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[2].value != 2U) return CTAP_STATUS_INVALID_SUBCOMMAND;
    return ctap_pin_key_agreement_encode(&service->secrets, output, capacity, length);
}
