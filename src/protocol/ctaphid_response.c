#include "protocol/ctaphid_response.h"

#include <string.h>

#define CTAPHID_INITIAL_HEADER_SIZE 7U
#define CTAPHID_CONTINUATION_HEADER_SIZE 5U
#define CTAPHID_INITIAL_MARKER 0x80U
#define CTAPHID_MAX_COMMAND 0x7FU

static CtaphidResponseResult validate_response(
    uint8_t command, const uint8_t *payload, size_t payload_length,
    CtaphidSendReport send_report
) {
    if (send_report == NULL || (payload == NULL && payload_length != 0U)) {
        return CTAPHID_RESPONSE_INVALID_ARGUMENT;
    }
    if (command > CTAPHID_MAX_COMMAND) {
        return CTAPHID_RESPONSE_INVALID_COMMAND;
    }
    if (payload_length > CTAPHID_MAX_WIRE_MESSAGE_SIZE) {
        return CTAPHID_RESPONSE_INVALID_LENGTH;
    }
    return CTAPHID_RESPONSE_OK;
}

/* Header encoding uses explicit bytes, never native struct layout. */
static void encode_channel(uint8_t *report, uint32_t channel_id)
{
    report[0] = (uint8_t)(channel_id >> 24);
    report[1] = (uint8_t)(channel_id >> 16);
    report[2] = (uint8_t)(channel_id >> 8);
    report[3] = (uint8_t)channel_id;
}

static void encode_initial_header(
    uint8_t *report, uint32_t channel_id, uint8_t command, size_t payload_length
) {
    encode_channel(report, channel_id);
    report[4] = (uint8_t)(command | CTAPHID_INITIAL_MARKER);
    report[5] = (uint8_t)(payload_length >> 8);
    report[6] = (uint8_t)payload_length;
}

static void encode_continuation_header(
    uint8_t *report, uint32_t channel_id, uint8_t sequence
) {
    encode_channel(report, channel_id);
    report[4] = sequence;
}

/* Fragment selection is independent of header encoding and transport I/O. */
static size_t fragment_length(size_t remaining, size_t capacity)
{
    return remaining < capacity ? remaining : capacity;
}

CtaphidResponseResult ctaphid_send_response(
    uint32_t channel_id,
    uint8_t command,
    const uint8_t *payload,
    size_t payload_length,
    CtaphidSendReport send_report,
    void *context
) {
    CtaphidResponseResult result = validate_response(
        command, payload, payload_length, send_report);
    if (result != CTAPHID_RESPONSE_OK) {
        return result;
    }

    /* Empty payloads still require an initial report. */
    uint8_t report[CTAPHID_REPORT_SIZE] = {0};
    encode_initial_header(report, channel_id, command, payload_length);
    size_t count = fragment_length(payload_length, CTAPHID_INITIAL_PAYLOAD_SIZE);
    if (count != 0U) {
        memcpy(report + CTAPHID_INITIAL_HEADER_SIZE, payload, count);
    }
    if (!send_report(context, report)) {
        return CTAPHID_RESPONSE_SEND_FAILED;
    }

    /* The validated wire limit guarantees that sequence never exceeds 127. */
    size_t offset = count;
    uint8_t sequence = 0U;
    while (offset < payload_length) {
        memset(report, 0, sizeof report);
        encode_continuation_header(report, channel_id, sequence);
        count = fragment_length(payload_length - offset, CTAPHID_CONTINUATION_PAYLOAD_SIZE);
        memcpy(report + CTAPHID_CONTINUATION_HEADER_SIZE, payload + offset, count);
        if (!send_report(context, report)) {
            return CTAPHID_RESPONSE_SEND_FAILED;
        }
        offset += count;
        ++sequence;
    }
    return CTAPHID_RESPONSE_OK;
}
