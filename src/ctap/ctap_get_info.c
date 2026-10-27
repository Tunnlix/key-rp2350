#include "ctap/ctap_get_info.h"
#include "ctap/cbor_writer.h"
#include "authenticator/auth_platform.h"

#include <string.h>

bool ctap_get_info_encode(const CtapGetInfoProfile *profile,
    uint8_t *output, size_t capacity, size_t *output_length)
{
    if (profile == NULL || output == NULL || output_length == NULL ||
        profile->max_message_size == 0U || !profile->make_credential || !profile->hmac_secret || !profile->user_presence ||
        (profile->resident_credentials && !profile->pin_uv_auth) ||
        (profile->large_blobs && !profile->resident_credentials) ||
        (profile->always_uv && !profile->pin_uv_auth) ||
        (profile->min_pin_length && (profile->min_pin_length < 4U || profile->min_pin_length > 63U)) ||
        (profile->max_credential_id_length && (profile->max_credential_id_length<AUTH_CREDENTIAL_ID_SIZE ||
            profile->max_credential_id_length>AUTH_CREDENTIAL_ID_MAX_SIZE))) return false;
    /* Build locally so a failed encoding never publishes a partial reply. */
    uint8_t encoded[CTAP_GET_INFO_MAX_CBOR_SIZE];
    CborWriter writer;
    cbor_writer_init(&writer, encoded, sizeof encoded);
    bool ok = cbor_write_map(&writer, 9U + (profile->large_blobs ? 1U : 0U) + (profile->resident_credentials ? 1U : 0U) + (profile->pin_uv_auth ? 3U : 0U) +
        (profile->usb_transport ? 1U : 0U) + (profile->firmware_version ? 1U : 0U) +
        (profile->resident_credentials ? 1U : 0U)) &&
        /* Integer map keys are in increasing canonical order. */
        /* Older clients require 2.0 discovery even when newer CTAP2 versions
         * are understood. PIN protocols 1/2 are supported; CTAP1 is not. */
        cbor_write_uint(&writer, 0x01U) && cbor_write_array(&writer, 3U) &&
        cbor_write_text(&writer, "FIDO_2_0") &&
        cbor_write_text(&writer, "FIDO_2_1") &&
        cbor_write_text(&writer, "FIDO_2_3");
    if (profile->hmac_secret) ok = ok && cbor_write_uint(&writer, 0x02U) &&
        cbor_write_array(&writer, 1U + (profile->resident_credentials ? 1U : 0U) + (profile->large_blobs ? 1U : 0U) + (profile->pin_uv_auth ? 2U : 0U) + (profile->make_credential ? 1U : 0U)) &&
        cbor_write_text(&writer, "hmac-secret");
    if (profile->resident_credentials) ok = ok && cbor_write_text(&writer, "credBlob");
    if (profile->large_blobs) ok = ok && cbor_write_text(&writer, "largeBlobKey");
    if (profile->pin_uv_auth) ok = ok && cbor_write_text(&writer, "credProtect") && cbor_write_text(&writer, "minPinLength");
    if (profile->hmac_secret && profile->make_credential) ok = ok && cbor_write_text(&writer, "hmac-secret-mc");
    ok = ok && cbor_write_uint(&writer, 0x03U) &&
        cbor_write_bytes(&writer, profile->aaguid, sizeof profile->aaguid) &&
        cbor_write_uint(&writer, 0x04U) && cbor_write_map(&writer, (profile->make_credential ? 4U : 3U) +
            (profile->large_blobs ? 1U : 0U) + (profile->pin_uv_auth ? 5U : 0U) + (profile->resident_credentials ? 1U : 0U)) &&
        /* String keys sort by length, then bytes: rk, up, plat.
         * Do not use uv=false/clientPin=false: those imply supported but unset. */
        cbor_write_text(&writer, "rk") && cbor_write_bool(&writer, profile->resident_credentials) &&
        cbor_write_text(&writer, "up") && cbor_write_bool(&writer, profile->user_presence) &&
        cbor_write_text(&writer, "plat") && cbor_write_bool(&writer, false);
    if (profile->pin_uv_auth) ok = ok && cbor_write_text(&writer, "alwaysUv") && cbor_write_bool(&writer, profile->always_uv);
    if (profile->resident_credentials) ok = ok && cbor_write_text(&writer, "credMgmt") && cbor_write_bool(&writer, true);
    if (profile->pin_uv_auth) ok = ok && cbor_write_text(&writer, "authnrCfg") && cbor_write_bool(&writer, true) &&
        cbor_write_text(&writer, "clientPin") && cbor_write_bool(&writer, profile->pin_set);
    if (profile->large_blobs) ok = ok && cbor_write_text(&writer, "largeBlobs") && cbor_write_bool(&writer, true);
    if (profile->pin_uv_auth) ok = ok && cbor_write_text(&writer, "pinUvAuthToken") && cbor_write_bool(&writer, true) &&
        cbor_write_text(&writer, "setMinPINLength") && cbor_write_bool(&writer, true);
    if (profile->make_credential) ok = ok && cbor_write_text(&writer, "makeCredUvNotRqd") && cbor_write_bool(&writer, !profile->always_uv);
    ok = ok && cbor_write_uint(&writer, 0x05U) && cbor_write_uint(&writer, profile->max_message_size);
    if (profile->hmac_secret) ok = ok && cbor_write_uint(&writer, 0x06U) &&
        cbor_write_array(&writer, 2U) && cbor_write_uint(&writer, 2U) && cbor_write_uint(&writer, 1U);
    /* Maximum generated credential ID length, not the stored-credential quota.
     * Unknown IDs of other lengths remain valid input and simply do not match. */
    ok = ok && cbor_write_uint(&writer, 0x08U) && cbor_write_uint(&writer,
        profile->max_credential_id_length ? profile->max_credential_id_length : AUTH_CREDENTIAL_ID_SIZE);
    if (profile->usb_transport) ok = ok && cbor_write_uint(&writer, 0x09U) &&
        cbor_write_array(&writer, 1U) && cbor_write_text(&writer, "usb");
    if (profile->make_credential) ok = ok &&
        cbor_write_uint(&writer, 0x0AU) && cbor_write_array(&writer, profile->ed25519 ? 2U : 1U) && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "alg") && cbor_write_int(&writer, -7) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key");
    if (profile->make_credential && profile->ed25519) ok = ok && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "alg") && cbor_write_int(&writer, AUTH_COSE_ALG_EDDSA) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key");
    if (profile->large_blobs) ok = ok && cbor_write_uint(&writer, 0x0BU) && cbor_write_uint(&writer, 4096U);
    if (profile->pin_uv_auth) ok = ok && cbor_write_uint(&writer, 0x0CU) && cbor_write_bool(&writer, profile->force_pin_change) &&
        cbor_write_uint(&writer, 0x0DU) && cbor_write_uint(&writer, profile->min_pin_length ? profile->min_pin_length : 4U);
    if (profile->firmware_version) ok = ok && cbor_write_uint(&writer, 0x0EU) &&
        cbor_write_uint(&writer, profile->firmware_version);
    if (profile->resident_credentials) ok = ok && cbor_write_uint(&writer, 0x0FU) && cbor_write_uint(&writer, 32U);
    if (profile->pin_uv_auth) ok = ok && cbor_write_uint(&writer, 0x10U) && cbor_write_uint(&writer, 0U);
    if (profile->resident_credentials) ok = ok && cbor_write_uint(&writer, 0x14U) &&
        cbor_write_uint(&writer, profile->remaining_credentials);
    ok = ok && cbor_write_uint(&writer, 0x16U) && cbor_write_array(&writer, 1U) && cbor_write_text(&writer, "packed");
    if (!ok || writer.length > capacity) return false;
    memcpy(output, encoded, writer.length);
    *output_length = writer.length;
    return true;
}
