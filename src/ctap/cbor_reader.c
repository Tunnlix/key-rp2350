#include "ctap/cbor_reader.h"
#include "authenticator/auth_platform.h"

#include <string.h>

bool cbor_utf8_valid(const uint8_t *data, size_t length)
{ return auth_text_valid(data, length); }

static bool key_before(const CborValue *left, const CborValue *right)
{
    /* CTAP orders major types first, then encoded length and bytes within a
     * type. Strict ordering also rejects duplicate keys before any lookup. */
    if (left->major != right->major) return left->major < right->major;
    if (left->encoded_length != right->encoded_length) return left->encoded_length < right->encoded_length;
    return memcmp(left->encoded, right->encoded, left->encoded_length) < 0;
}

static bool read_value(const uint8_t **cursor, const uint8_t *end, unsigned depth, CborValue *output)
{
    const uint8_t *start = *cursor;
    if (start >= end) return false;
    uint8_t head = *(*cursor)++, major = head >> 5, additional = head & 31U;
    if (major == 6U || additional >= 28U) return false;
    uint64_t argument = additional;
    if (additional >= 24U) {
        size_t extra = (size_t)1U << (additional - 24U);
        if (extra > (size_t)(end - *cursor)) return false;
        argument = 0U;
        for (size_t i = 0; i < extra; ++i) argument = (argument << 8) | *(*cursor)++;
        if (major != 7U && (argument < 24U || (extra > 1U && argument <= UINT8_MAX) ||
            (extra > 2U && argument <= UINT16_MAX) || (extra > 4U && argument <= UINT32_MAX))) return false;
        if (major == 7U && additional == 24U && argument < 32U) return false;
    }
    CborValue value = {start, *cursor, 0U, argument, major};
    if (major == 2U || major == 3U) {
        if (argument > (uint64_t)(end - *cursor)) return false;
        if (major == 3U && !cbor_utf8_valid(*cursor, (size_t)argument)) return false;
        *cursor += (size_t)argument;
    } else if (major == 4U || major == 5U) {
        if (depth >= 4U || argument > (uint64_t)(end - *cursor) / (major == 5U ? 2U : 1U)) return false;
        CborValue previous = {0}, child;
        for (uint64_t i = 0; i < argument; ++i) {
            if (!read_value(cursor, end, depth + 1U, &child)) return false;
            if (major == 5U) {
                if (i != 0U && !key_before(&previous, &child)) return false;
                previous = child;
                if (!read_value(cursor, end, depth + 1U, &child)) return false;
            }
        }
    }
    value.encoded_length = (size_t)(*cursor - start);
    *output = value;
    return true;
}

bool cbor_read_document(const uint8_t *input, size_t length, CborValue *value)
{
    if (input == NULL || value == NULL || length == 0U) return false;
    const uint8_t *cursor = input;
    return read_value(&cursor, input + length, 0U, value) && cursor == input + length;
}

bool cbor_read_next(const uint8_t **cursor, const uint8_t *end, CborValue *value)
{
    return cursor != NULL && *cursor != NULL && end != NULL && value != NULL &&
        read_value(cursor, end, 0U, value);
}

bool cbor_text_equal(const CborValue *value, const char *text)
{
    return value != NULL && text != NULL && value->major == 3U &&
        value->value == strlen(text) && memcmp(value->data, text, strlen(text)) == 0;
}

static bool map_lookup(const CborValue *map, uint8_t major, uint64_t number, const char *text, CborValue *output)
{
    if (map == NULL || map->major != 5U || output == NULL) return false;
    const uint8_t *cursor = map->data, *end = map->encoded + map->encoded_length;
    CborValue key, value;
    for (uint64_t i = 0; i < map->value; ++i) {
        if (!cbor_read_next(&cursor, end, &key) || !cbor_read_next(&cursor, end, &value)) return false;
        if (text == NULL ? key.major == major && key.value == number : cbor_text_equal(&key, text)) {
            *output = value;
            return true;
        }
    }
    return false;
}

bool cbor_map_uint(const CborValue *map, uint64_t key, CborValue *value)
{ return map_lookup(map, 0U, key, NULL, value); }
bool cbor_map_int(const CborValue *map, int64_t key, CborValue *value)
{ return key >= 0 ? map_lookup(map, 0U, (uint64_t)key, NULL, value) :
    map_lookup(map, 1U, (uint64_t)(-(key + 1)), NULL, value); }
bool cbor_map_text(const CborValue *map, const char *key, CborValue *value)
{ return key != NULL && map_lookup(map, 0U, 0U, key, value); }
