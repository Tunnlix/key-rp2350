#include "ctap/ctap_entities.h"
#include "ctap/ctap_request.h"
#include <string.h>

static uint8_t name(const CborValue *map, const char *key, uint8_t out[64], uint8_t *length)
{
    CborValue value; *length = 0U; memset(out, 0, 64U);
    if (!cbor_map_text(map, key, &value)) return CTAP_STATUS_OK;
    if (value.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    size_t n = value.value > 64U ? 64U : (size_t)value.value;
    while (!auth_text_valid(value.data, n)) --n;
    memcpy(out, value.data, n); *length = (uint8_t)n; return CTAP_STATUS_OK;
}

uint8_t ctap_user_entity_parse(const CborValue *value, AuthCredential *metadata)
{
    uint8_t status = ctap_request_text_map(value); if (status != CTAP_STATUS_OK) return status;
    CborValue id;
    if (!cbor_map_text(value, "id", &id)) return CTAP_STATUS_MISSING_PARAMETER;
    if (id.major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (id.value > AUTH_USER_ID_MAX_SIZE) return CTAP_STATUS_INVALID_LENGTH;
    metadata->user_id_length = (uint8_t)id.value;
    memset(metadata->user_id, 0, sizeof metadata->user_id); memcpy(metadata->user_id, id.data, (size_t)id.value);
    status = name(value, "name", metadata->user_name, &metadata->user_name_length);
    if (status != CTAP_STATUS_OK) return status;
    return name(value, "displayName", metadata->user_display_name, &metadata->user_display_name_length);
}

uint8_t ctap_rp_entity_parse(const CborValue *value, AuthCredential *metadata)
{
    uint8_t status = ctap_request_text_map(value); if (status != CTAP_STATUS_OK) return status;
    CborValue id;
    if (!cbor_map_text(value, "id", &id)) return CTAP_STATUS_MISSING_PARAMETER;
    if (id.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (id.value == 0U || id.value > AUTH_RP_ID_MAX_SIZE) return CTAP_STATUS_INVALID_PARAMETER;
    metadata->rp_id_length = (uint16_t)id.value;
    memcpy(metadata->rp_id, id.data, (size_t)id.value);
    return name(value, "name", metadata->rp_name, &metadata->rp_name_length);
}

bool ctap_user_entity_write(CborWriter *writer, const AuthCredential *credential, bool identifying)
{
    bool user_name = identifying && credential->user_name_length != 0U;
    bool display_name = identifying && credential->user_display_name_length != 0U;
    bool ok = cbor_write_map(writer, 1U + (user_name ? 1U : 0U) + (display_name ? 1U : 0U)) &&
        cbor_write_text(writer, "id") && cbor_write_bytes(writer, credential->user_id, credential->user_id_length);
    if (user_name) ok = ok && cbor_write_text(writer, "name") &&
        cbor_write_text_bytes(writer, credential->user_name, credential->user_name_length);
    if (display_name) ok = ok && cbor_write_text(writer, "displayName") &&
        cbor_write_text_bytes(writer, credential->user_display_name, credential->user_display_name_length);
    return ok;
}

bool ctap_rp_entity_write(CborWriter *writer, const AuthCredential *credential)
{
    bool ok = cbor_write_map(writer, (credential->rp_id_length ? 1U : 0U) + (credential->rp_name_length ? 1U : 0U));
    if (credential->rp_id_length) ok = ok && cbor_write_text(writer, "id") &&
        cbor_write_text_bytes(writer, credential->rp_id, credential->rp_id_length);
    if (credential->rp_name_length) ok = ok && cbor_write_text(writer, "name") &&
        cbor_write_text_bytes(writer, credential->rp_name, credential->rp_name_length);
    return ok;
}

bool ctap_credential_descriptor_write(CborWriter *writer, const uint8_t id[32])
{
    return cbor_write_map(writer, 2U) && cbor_write_text(writer, "id") && cbor_write_bytes(writer, id, 32U) &&
        cbor_write_text(writer, "type") && cbor_write_text(writer, "public-key");
}

bool ctap_public_key_write(CborWriter *writer, const uint8_t key[65])
{
    return key[0] == 4U && cbor_write_map(writer, 5U) &&
        cbor_write_int(writer, 1) && cbor_write_int(writer, 2) && cbor_write_int(writer, 3) && cbor_write_int(writer, -7) &&
        cbor_write_int(writer, -1) && cbor_write_int(writer, 1) &&
        cbor_write_int(writer, -2) && cbor_write_bytes(writer, key + 1U, 32U) &&
        cbor_write_int(writer, -3) && cbor_write_bytes(writer, key + 33U, 32U);
}
