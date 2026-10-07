#include "ctap/cbor_writer.h"

#include <string.h>

void cbor_writer_init(CborWriter *writer, uint8_t *buffer, size_t capacity)
{
    if (writer == NULL) return;
    writer->buffer = buffer;
    writer->capacity = capacity;
    writer->length = 0U;
    writer->failed = buffer == NULL && capacity != 0U;
}

static bool append(CborWriter *writer, const uint8_t *data, size_t length)
{
    if (writer == NULL) return false;
    if (writer->failed || (length != 0U && data == NULL) ||
        length > writer->capacity - writer->length) {
        writer->failed = true;
        return false;
    }
    if (length != 0U) memcpy(writer->buffer + writer->length, data, length);
    writer->length += length;
    return true;
}

/* Major type occupies the top three bits; extra integer bytes are big-endian. */
static bool write_head(CborWriter *writer, uint8_t major, uint64_t value)
{
    uint8_t encoded[9];
    size_t extra = 0U;
    if (value < 24U) encoded[0] = (uint8_t)((major << 5) | value);
    else {
        uint8_t additional;
        if (value <= UINT8_MAX) { additional = 24U; extra = 1U; }
        else if (value <= UINT16_MAX) { additional = 25U; extra = 2U; }
        else if (value <= UINT32_MAX) { additional = 26U; extra = 4U; }
        else { additional = 27U; extra = 8U; }
        encoded[0] = (uint8_t)((major << 5) | additional);
        for (size_t i = 0; i < extra; ++i) {
            encoded[1U + i] = (uint8_t)(value >> ((extra - 1U - i) * 8U));
        }
    }
    return append(writer, encoded, 1U + extra);
}

bool cbor_write_uint(CborWriter *writer, uint64_t value)
{
    return write_head(writer, 0U, value);
}

bool cbor_write_int(CborWriter *writer, int64_t value)
{
    return value >= 0 ? write_head(writer, 0U, (uint64_t)value) :
        write_head(writer, 1U, (uint64_t)(-(value + 1)));
}

static bool write_string(CborWriter *writer, uint8_t major, const uint8_t *data, size_t length)
{
    if (writer == NULL) return false;
    if (length != 0U && data == NULL) { writer->failed = true; return false; }
    size_t previous_length = writer->length;
    if (!write_head(writer, major, length) || !append(writer, data, length)) {
        writer->length = previous_length;
        return false;
    }
    return true;
}

bool cbor_write_bytes(CborWriter *writer, const uint8_t *data, size_t length)
{
    return write_string(writer, 2U, data, length);
}

bool cbor_write_text(CborWriter *writer, const char *text)
{
    if (text == NULL) {
        if (writer != NULL) writer->failed = true;
        return false;
    }
    return write_string(writer, 3U, (const uint8_t *)text, strlen(text));
}

bool cbor_write_text_bytes(CborWriter *writer, const uint8_t *text, size_t length)
{
    return write_string(writer, 3U, text, length);
}

bool cbor_write_bool(CborWriter *writer, bool value)
{
    const uint8_t encoded = value ? 0xF5U : 0xF4U;
    return append(writer, &encoded, 1U);
}

bool cbor_write_array(CborWriter *writer, size_t count)
{
    return write_head(writer, 4U, count);
}

bool cbor_write_map(CborWriter *writer, size_t count)
{
    return write_head(writer, 5U, count);
}
