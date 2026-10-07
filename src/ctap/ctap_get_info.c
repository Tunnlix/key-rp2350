#include "ctap/ctap_get_info.h"
#include "ctap/cbor_writer.h"

#include <string.h>

bool ctap_get_info_encode(const CtapGetInfoProfile *profile,
    uint8_t *output, size_t capacity, size_t *output_length)
{
    if (profile == NULL || output == NULL || output_length == NULL ||
        profile->max_message_size == 0U || !profile->make_credential || !profile->hmac_secret || !profile->user_presence ||
        (profile->resident_credentials && !profile->pin_uv_auth)) return false;
    /* Build locally so a failed encoding never publishes a partial reply. */
    uint8_t encoded[CTAP_GET_INFO_MAX_CBOR_SIZE];
    CborWriter writer;
    cbor_writer_init(&writer, encoded, sizeof encoded);
    bool ok = cbor_write_map(&writer, 8U + (profile->pin_uv_auth ? 1U : 0U)) &&
        /* Integer map keys are in increasing canonical order. */
        cbor_write_uint(&writer, 0x01U) && cbor_write_array(&writer, 1U) &&
        cbor_write_text(&writer, "FIDO_2_3");
    if (profile->hmac_secret) ok = ok && cbor_write_uint(&writer, 0x02U) &&
        cbor_write_array(&writer, 1U + (profile->pin_uv_auth ? 1U : 0U) + (profile->make_credential ? 1U : 0U)) &&
        cbor_write_text(&writer, "hmac-secret");
    if (profile->pin_uv_auth) ok = ok && cbor_write_text(&writer, "credProtect");
    if (profile->hmac_secret && profile->make_credential) ok = ok && cbor_write_text(&writer, "hmac-secret-mc");
    ok = ok && cbor_write_uint(&writer, 0x03U) &&
        cbor_write_bytes(&writer, profile->aaguid, sizeof profile->aaguid) &&
        cbor_write_uint(&writer, 0x04U) && cbor_write_map(&writer, (profile->make_credential ? 4U : 3U) +
            (profile->pin_uv_auth ? 2U : 0U) + (profile->resident_credentials ? 1U : 0U)) &&
        /* String keys sort by length, then bytes: rk, up, plat.
         * Do not use uv=false/clientPin=false: those imply supported but unset. */
        cbor_write_text(&writer, "rk") && cbor_write_bool(&writer, profile->resident_credentials) &&
        cbor_write_text(&writer, "up") && cbor_write_bool(&writer, profile->user_presence) &&
        cbor_write_text(&writer, "plat") && cbor_write_bool(&writer, false);
    if (profile->resident_credentials) ok = ok && cbor_write_text(&writer, "credMgmt") && cbor_write_bool(&writer, true);
    if (profile->pin_uv_auth) ok = ok && cbor_write_text(&writer, "clientPin") && cbor_write_bool(&writer, profile->pin_set) &&
        cbor_write_text(&writer, "pinUvAuthToken") && cbor_write_bool(&writer, true);
    if (profile->make_credential) ok = ok && cbor_write_text(&writer, "makeCredUvNotRqd") && cbor_write_bool(&writer, true);
    ok = ok && cbor_write_uint(&writer, 0x05U) && cbor_write_uint(&writer, profile->max_message_size);
    if (profile->hmac_secret) ok = ok && cbor_write_uint(&writer, 0x06U) &&
        cbor_write_array(&writer, 1U) && cbor_write_uint(&writer, 2U);
    if (profile->make_credential) ok = ok &&
        cbor_write_uint(&writer, 0x0AU) && cbor_write_array(&writer, 1U) && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "alg") && cbor_write_int(&writer, -7) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key");
    if (profile->pin_uv_auth) ok = ok && cbor_write_uint(&writer, 0x0DU) && cbor_write_uint(&writer, 4U);
    ok = ok && cbor_write_uint(&writer, 0x16U) && cbor_write_array(&writer, 1U) && cbor_write_text(&writer, "packed");
    if (!ok || writer.length > capacity) return false;
    memcpy(output, encoded, writer.length);
    *output_length = writer.length;
    return true;
}
