#include "ctap/ctap_attestation.h"
#include "ctap/cbor_writer.h"

#include <string.h>

bool ctap_attestation_encode(AuthCredentialService *service,
    const AuthCredential *credential, const uint8_t public_key[65],
    const uint8_t client_data_hash[32], const uint8_t aaguid[16], bool omit, const bool *hmac_secret,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (service == NULL || !auth_credential_valid(credential) || public_key == NULL ||
        public_key[0] != 4U || client_data_hash == NULL || aaguid == NULL || output == NULL || length == NULL) return false;
    /* Fixed portion: RP hash, flags, counter, AAGUID, ID length and ID. */
    uint8_t data[212] = {0};
    memcpy(data, credential->rp_id_hash, 32U);
    data[32] = hmac_secret == NULL ? 0x41U : 0xC1U;
    if (!omit) memcpy(data + 37U, aaguid, 16U);
    data[54] = 32U;
    memcpy(data + 55U, credential->credential_id, 32U);
    CborWriter cose;
    cbor_writer_init(&cose, data + 87U, 77U);
    /* CTAP canonical order: positive integers, then negative integers. */
    bool ok = cbor_write_map(&cose, 5U) &&
        cbor_write_int(&cose, 1) && cbor_write_int(&cose, 2) &&
        cbor_write_int(&cose, 3) && cbor_write_int(&cose, -7) &&
        cbor_write_int(&cose, -1) && cbor_write_int(&cose, 1) &&
        cbor_write_int(&cose, -2) && cbor_write_bytes(&cose, public_key + 1U, 32U) &&
        cbor_write_int(&cose, -3) && cbor_write_bytes(&cose, public_key + 33U, 32U);
    if (!ok) return false;
    size_t data_length = 87U + cose.length;
    if (hmac_secret != NULL) {
        CborWriter extension; cbor_writer_init(&extension, data + data_length, sizeof data - data_length - 32U);
        if (!cbor_write_map(&extension, 1U) || !cbor_write_text(&extension, "hmac-secret") ||
            !cbor_write_bool(&extension, *hmac_secret)) return false;
        data_length += extension.length;
    }
    uint8_t signature[72], digest[32];
    size_t signature_length = 0U;
    if (!omit) {
        memcpy(data + data_length, client_data_hash, 32U);
        if (service->crypto.sha256(service->crypto.context, data, data_length + 32U, digest) != AUTH_OK ||
            auth_credentials_sign_digest(service, credential->credential_id, credential->rp_id_hash,
                digest, signature, &signature_length) != AUTH_OK ||
            signature_length == 0U || signature_length > sizeof signature) return false;
    }
    uint8_t encoded[384];
    CborWriter writer;
    cbor_writer_init(&writer, encoded, sizeof encoded);
    ok = cbor_write_map(&writer, 3U) &&
        cbor_write_uint(&writer, 1U) && cbor_write_text(&writer, omit ? "none" : "packed") &&
        cbor_write_uint(&writer, 2U) && cbor_write_bytes(&writer, data, data_length) &&
        cbor_write_uint(&writer, 3U) && cbor_write_map(&writer, omit ? 0U : 2U);
    if (!omit) ok = ok && cbor_write_text(&writer, "alg") && cbor_write_int(&writer, -7) &&
        cbor_write_text(&writer, "sig") && cbor_write_bytes(&writer, signature, signature_length);
    if (!ok || writer.length > capacity) return false;
    memcpy(output, encoded, writer.length);
    *length = writer.length;
    return true;
}
