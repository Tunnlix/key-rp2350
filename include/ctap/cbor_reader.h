#ifndef CTAP_CBOR_READER_H
#define CTAP_CBOR_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Borrowed views into immutable input. Validate the whole document first.
 * No allocation; definite lengths, shortest integers, UTF-8, CTAP canonical
 * map order/no duplicate keys, no tags, and at most four nested containers.
 * Unknown values can be skipped, including floating point/simple values.
 * Views remain valid only while the caller retains the original input. */
typedef struct {
    const uint8_t *encoded, *data;
    size_t encoded_length;
    uint64_t value; /* integer argument, string length or collection count */
    uint8_t major;
} CborValue;

bool cbor_read_document(const uint8_t *input, size_t length, CborValue *value);
bool cbor_read_next(const uint8_t **cursor, const uint8_t *end, CborValue *value);
bool cbor_map_uint(const CborValue *map, uint64_t key, CborValue *value);
bool cbor_map_text(const CborValue *map, const char *key, CborValue *value);
bool cbor_text_equal(const CborValue *value, const char *text);

#endif
