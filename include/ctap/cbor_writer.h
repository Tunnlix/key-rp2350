#ifndef CTAP_CBOR_WRITER_H
#define CTAP_CBOR_WRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Allocation-free writer for the definite-length CBOR primitives used by CTAP.
 * Integer/length encodings are shortest-form. Callers provide valid UTF-8 text,
 * exact collection counts, and canonically ordered, nonduplicate map keys.
 * Failed writes latch failed and do not advance length. No decoder or HID I/O. */
typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t length;
    bool failed;
} CborWriter;

void cbor_writer_init(CborWriter *writer, uint8_t *buffer, size_t capacity);
bool cbor_write_uint(CborWriter *writer, uint64_t value);
bool cbor_write_int(CborWriter *writer, int64_t value);
bool cbor_write_bytes(CborWriter *writer, const uint8_t *data, size_t length);
bool cbor_write_text(CborWriter *writer, const char *text);
bool cbor_write_bool(CborWriter *writer, bool value);
bool cbor_write_array(CborWriter *writer, size_t count);
bool cbor_write_map(CborWriter *writer, size_t count);

#endif
