#include "ctap/ctap_request.h"

uint8_t ctap_request_map(const uint8_t *input, size_t length, size_t field_count,
    CborValue *fields, bool *present)
{
    if (fields == NULL || present == NULL) return CTAP_STATUS_OTHER;
    CborValue map, key, value;
    if (!cbor_read_document(input, length, &map)) return CTAP_STATUS_INVALID_CBOR;
    if (map.major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    const uint8_t *cursor = map.data, *end = map.encoded + map.encoded_length;
    for (uint64_t i = 0; i < map.value; ++i) {
        if (!cbor_read_next(&cursor, end, &key) || !cbor_read_next(&cursor, end, &value)) return CTAP_STATUS_INVALID_CBOR;
        if (key.major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (key.value < field_count) { fields[key.value] = value; present[key.value] = true; }
    }
    return CTAP_STATUS_OK;
}

uint8_t ctap_request_text_map(const CborValue *map)
{
    if (map == NULL || map->major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    const uint8_t *cursor = map->data, *end = map->encoded + map->encoded_length;
    CborValue key, value;
    for (uint64_t i = 0; i < map->value; ++i) {
        if (!cbor_read_next(&cursor, end, &key) || !cbor_read_next(&cursor, end, &value)) return CTAP_STATUS_INVALID_CBOR;
        if (key.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    return CTAP_STATUS_OK;
}

uint8_t ctap_request_descriptor(const CborValue *map, CborValue *id, CborValue *type)
{
    uint8_t status = ctap_request_text_map(map);
    if (status != CTAP_STATUS_OK) return status;
    if (!cbor_map_text(map, "id", id) || !cbor_map_text(map, "type", type) ||
        id->major != 2U || type->major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    CborValue transports, transport;
    if (cbor_map_text(map, "transports", &transports)) {
        if (transports.major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        const uint8_t *cursor = transports.data, *end = transports.encoded + transports.encoded_length;
        for (uint64_t i = 0; i < transports.value; ++i) {
            if (!cbor_read_next(&cursor, end, &transport) || transport.major != 3U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
    }
    return CTAP_STATUS_OK;
}
