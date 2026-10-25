#include "ctap/ctap_attestation.h"
#include "ctap/cbor_writer.h"
#include "ctap/ctap_entities.h"

#include <string.h>

bool ctap_attestation_encode(AuthCredentialService *service,
    const AuthCredential *credential, const uint8_t public_key[65],
    const uint8_t client_data_hash[32], const uint8_t aaguid[16], bool omit, const bool *hmac_secret,
    bool user_verified, bool cred_protect_requested,
    const uint8_t *hmac_secret_mc, size_t hmac_secret_mc_length,
    uint8_t *output, size_t capacity, size_t *length)
{
    return credential != NULL && ctap_attestation_encode_id(service, credential,
        credential->credential_id, AUTH_CREDENTIAL_ID_SIZE, public_key,
        client_data_hash, aaguid, omit, hmac_secret, user_verified,
        cred_protect_requested, hmac_secret_mc, hmac_secret_mc_length,
        output, capacity, length);
}

bool ctap_attestation_encode_id(AuthCredentialService *service,
    const AuthCredential *credential, const uint8_t *id, size_t id_length,
    const uint8_t public_key[65], const uint8_t client_data_hash[32],
    const uint8_t aaguid[16], bool omit, const bool *hmac_secret,
    bool user_verified, bool cred_protect_requested,
    const uint8_t *hmac_secret_mc, size_t hmac_secret_mc_length,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (service == NULL || !auth_credential_valid(credential) || public_key == NULL ||
        public_key[0] != 4U || client_data_hash == NULL || aaguid == NULL || output == NULL || length == NULL ||
        id == NULL || !auth_credential_id_length_valid(id_length)) return false;
    if (hmac_secret_mc_length != 0U && (hmac_secret_mc == NULL ||
        (hmac_secret_mc_length != 48U && hmac_secret_mc_length != 80U))) return false;
    bool extensions = hmac_secret != NULL || cred_protect_requested || hmac_secret_mc_length != 0U;
    /* Fixed portion, extensions, and trailing clientDataHash for signing. */
    uint8_t data[336U + AUTH_CREDENTIAL_ID_MAX_SIZE - AUTH_CREDENTIAL_ID_SIZE] = {0};
    memcpy(data, credential->rp_id_hash, 32U);
    data[32] = 0x41U | (user_verified ? 4U : 0U) | (extensions ? 0x80U : 0U);
    for (size_t i = 0U; i < 4U; ++i)
        data[33U + i] = (uint8_t)(credential->signature_count >> (24U - 8U * i));
    if (!omit) memcpy(data + 37U, aaguid, 16U);
    data[53] = (uint8_t)(id_length >> 8U);
    data[54] = (uint8_t)id_length;
    memcpy(data + 55U, id, id_length);
    CborWriter cose;
    cbor_writer_init(&cose, data + 55U + id_length, 77U);
    bool ok = ctap_public_key_write(&cose, public_key);
    if (!ok) return false;
    size_t data_length = 55U + id_length + cose.length;
    if (extensions) {
        CborWriter extension; cbor_writer_init(&extension, data + data_length, sizeof data - data_length - 32U);
        bool extensions_ok = cbor_write_map(&extension, (hmac_secret != NULL ? 1U : 0U) +
            (cred_protect_requested ? 1U : 0U) + (hmac_secret_mc_length != 0U ? 1U : 0U));
        /* Both keys have 11 bytes: credProtect precedes hmac-secret. */
        if (cred_protect_requested) extensions_ok = extensions_ok && cbor_write_text(&extension, "credProtect") &&
            cbor_write_uint(&extension, credential->cred_protect);
        if (hmac_secret != NULL) extensions_ok = extensions_ok && cbor_write_text(&extension, "hmac-secret") &&
            cbor_write_bool(&extension, *hmac_secret);
        if (hmac_secret_mc_length != 0U) extensions_ok = extensions_ok && cbor_write_text(&extension, "hmac-secret-mc") &&
            cbor_write_bytes(&extension, hmac_secret_mc, hmac_secret_mc_length);
        if (!extensions_ok) return false;
        data_length += extension.length;
    }
    uint8_t signature[72], digest[32];
    size_t signature_length = 0U;
    if (!omit) {
        memcpy(data + data_length, client_data_hash, 32U);
        if (service->crypto.sha256(service->crypto.context, data, data_length + 32U, digest) != AUTH_OK ||
            service->crypto.sign_p256_digest(service->crypto.context, &credential->key,
                digest, signature, &signature_length) != AUTH_OK ||
            signature_length == 0U || signature_length > sizeof signature) return false;
    }
    uint8_t encoded[512U + AUTH_CREDENTIAL_ID_MAX_SIZE - AUTH_CREDENTIAL_ID_SIZE];
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
