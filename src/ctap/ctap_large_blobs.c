#include "ctap/ctap_large_blobs.h"
#include "ctap/ctap_request.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/cbor_writer.h"
#include <string.h>

void ctap_large_blobs_clear(CtapLargeBlobs *blobs)
{
    if (blobs == NULL) return;
    blobs->next_offset = blobs->expected_length = 0U;
    blobs->channel = blobs->last_call_ms = 0U;
    auth_secure_zero(blobs->pending, sizeof blobs->pending);
    auth_secure_zero(blobs->fragment, sizeof blobs->fragment);
}

static uint8_t execute(CtapLargeBlobs *blobs, CtapClientPin *pin, uint32_t channel,
    const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written, uint32_t now_ms)
{
    CborValue fields[7] = {{0}}; bool present[7] = {false};
    uint8_t status = ctap_request_map(input, length, 7U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[3] || present[1] == present[2]) return CTAP_STATUS_INVALID_PARAMETER;
    if (fields[3].major != 0U || (present[1] && fields[1].major != 0U) ||
        (present[2] && fields[2].major != 2U) || (present[4] && fields[4].major != 0U) ||
        (present[5] && fields[5].major != 2U) || (present[6] && fields[6].major != 0U))
        return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[3].value > CTAP_LARGE_BLOB_CAPACITY) return CTAP_STATUS_INVALID_PARAMETER;
    size_t offset = (size_t)fields[3].value;
    if (present[1]) {
        if (present[4] || present[5] || present[6]) return CTAP_STATUS_INVALID_PARAMETER;
        if (fields[1].value > CTAP_LARGE_BLOB_FRAGMENT) return CTAP_STATUS_INVALID_LENGTH;
        size_t total = 0U;
        if (blobs->storage.read(blobs->storage.context, 0U, NULL, 0U, &total) != AUTH_OK ||
            total < 17U || total > CTAP_LARGE_BLOB_CAPACITY) return CTAP_STATUS_OTHER;
        if (offset > total) return CTAP_STATUS_INVALID_PARAMETER;
        size_t count = (size_t)fields[1].value;
        if (count > total - offset) count = total - offset;
        if (blobs->storage.read(blobs->storage.context, offset, blobs->fragment, count, &total) != AUTH_OK)
            return CTAP_STATUS_OTHER;
        CborWriter writer; cbor_writer_init(&writer, output, capacity);
        if (!cbor_write_map(&writer, 1U) || !cbor_write_uint(&writer, 1U) ||
            !cbor_write_bytes(&writer, blobs->fragment, count)) return CTAP_STATUS_OTHER;
        *written = writer.length;
        return CTAP_STATUS_OK;
    }
    if (fields[2].value > CTAP_LARGE_BLOB_FRAGMENT) return CTAP_STATUS_INVALID_LENGTH;
    if (offset == 0U) {
        if (!present[4] || fields[4].value < 17U) return CTAP_STATUS_INVALID_PARAMETER;
        if (fields[4].value > CTAP_LARGE_BLOB_CAPACITY) return CTAP_STATUS_LARGE_BLOB_STORAGE_FULL;
    } else {
        if (present[4]) return CTAP_STATUS_INVALID_PARAMETER;
        if (offset != blobs->next_offset || !blobs->expected_length || blobs->channel != channel)
            return CTAP_STATUS_INVALID_SEQUENCE;
    }
    size_t expected = offset == 0U ? (size_t)fields[4].value : blobs->expected_length;
    if (fields[2].value > expected - offset) return CTAP_STATUS_INVALID_PARAMETER;
    bool set;
    status = ctap_client_pin_status(pin, &set);
    if (status != CTAP_STATUS_OK) return status;
    if (set || pin->always_uv) {
        if (!present[5]) return CTAP_STATUS_PUAT_REQUIRED;
        if (!present[6]) return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[6].value != 1U && fields[6].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
        uint8_t protocol = (uint8_t)fields[6].value;
        if (fields[5].value != ctap_pin_protocol_auth_length(protocol)) return CTAP_STATUS_PIN_AUTH_INVALID;
        uint8_t message[70]; memset(message, 0xff, 32U);
        message[32] = 0x0cU; message[33] = 0U;
        for (size_t i = 0U; i < 4U; ++i) message[34U+i] = (uint8_t)(offset >> (8U*i));
        if (pin->service->crypto.sha256(pin->service->crypto.context, fields[2].data,
                (size_t)fields[2].value, message + 38U) != AUTH_OK) return CTAP_STATUS_OTHER;
        status = ctap_client_pin_authorize_permission(pin, protocol, CTAP_PIN_PERMISSION_LBW,
            message, sizeof message, fields[5].data, now_ms);
        auth_secure_zero(message, sizeof message);
        if (status != CTAP_STATUS_OK) return status;
    }
    if (offset == 0U) {
        ctap_large_blobs_clear(blobs);
        blobs->expected_length = expected; blobs->channel = channel;
    }
    memcpy(blobs->pending + offset, fields[2].data, (size_t)fields[2].value);
    blobs->next_offset = offset + (size_t)fields[2].value; blobs->last_call_ms = now_ms;
    *written = 0U;
    if (blobs->next_offset != expected) return CTAP_STATUS_OK;
    uint8_t digest[32] = {0};
    status = CTAP_STATUS_OTHER;
    if (pin->service->crypto.sha256(pin->service->crypto.context, blobs->pending, expected - 16U, digest) == AUTH_OK) {
        if (!ctap_pin_equal(digest, blobs->pending + expected - 16U, 16U)) status = CTAP_STATUS_INTEGRITY_FAILURE;
        else if (blobs->storage.commit(blobs->storage.context, blobs->pending, expected) == AUTH_OK)
            status = CTAP_STATUS_OK;
    }
    auth_secure_zero(digest, sizeof digest); ctap_large_blobs_clear(blobs);
    return status;
}

uint8_t ctap_large_blobs_execute(CtapLargeBlobs *blobs, CtapClientPin *pin, uint32_t channel,
    const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written, uint32_t now_ms)
{
    if (blobs == NULL || pin == NULL || output == NULL || written == NULL ||
        blobs->storage.read == NULL || blobs->storage.commit == NULL) return CTAP_STATUS_OTHER;
    if (blobs->expected_length && (blobs->channel != channel || (uint32_t)(now_ms-blobs->last_call_ms) > 30000U))
        ctap_large_blobs_clear(blobs);
    uint8_t status = execute(blobs, pin, channel, input, length, output, capacity, written, now_ms);
    auth_secure_zero(blobs->fragment, sizeof blobs->fragment);
    if (status != CTAP_STATUS_OK) ctap_large_blobs_clear(blobs);
    return status;
}
