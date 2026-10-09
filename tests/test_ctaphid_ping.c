#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_device.h"

typedef struct {
    uint8_t reports[CTAPHID_DEVICE_RESPONSE_REPORTS][CTAPHID_REPORT_SIZE];
    size_t accepted;
    size_t attempted;
    size_t fail_at;
} PingTransport;

static bool capture_report(void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    PingTransport *transport = context;
    ++transport->attempted;
    if (transport->attempted == transport->fail_at) return false;
    assert(transport->accepted < sizeof transport->reports / sizeof transport->reports[0]);
    memcpy(transport->reports[transport->accepted++], report, CTAPHID_REPORT_SIZE);
    return true;
}

/* Build requests independently of the serializer and run them through the
 * parser/reassembler. With zero padding, a PING reply must match these reports
 * byte for byte, including CID, length, fragmentation, and sequence numbers. */
static CtaphidReassembler assemble_ping(size_t length, PingTransport *expected)
{
    CtaphidReassembler message = {0};
    size_t offset = 0U;
    size_t index = 0U;
    do {
        uint8_t report[64] = {0};
        report[0] = 0U; report[1] = 0U;
        report[2] = 0U; report[3] = 1U;
        size_t header = index == 0U ? 7U : 5U;
        if (index == 0U) {
            report[4] = 0x81U;
            report[5] = (uint8_t)(length >> 8);
            report[6] = (uint8_t)length;
        } else {
            report[4] = (uint8_t)(index - 1U);
        }
        size_t count = length - offset;
        if (count > 64U - header) count = 64U - header;
        for (size_t i = 0; i < count; ++i) {
            report[header + i] = (uint8_t)((offset + i) * 37U + 11U);
        }
        assert(capture_report(expected, report));
        CtaphidParsedPacket packet;
        assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
        CtaphidReassembleResult result = ctaphid_reassemble_packet(
            &message, &packet, (uint32_t)index);
        offset += count;
        ++index;
        if (offset < length) {
            assert(result == CTAPHID_REASSEMBLE_INCOMPLETE);
        } else {
            assert(result == CTAPHID_REASSEMBLE_COMPLETE);
        }
    } while (offset < length);
    return message;
}

static CtaphidChannelManager allocated_channels(void)
{
    CtaphidChannelManager channels = {0};
    uint32_t channel_id;
    assert(ctaphid_channels_allocate(&channels, &channel_id) == CTAPHID_CHANNEL_OK);
    assert(channel_id == 1U);
    return channels;
}

static void test_all_ping_lengths(void)
{
    for (size_t length = 0; length <= CTAPHID_MAX_MESSAGE_SIZE; ++length) {
        CtaphidChannelManager channels = allocated_channels();
        PingTransport expected = {0};
        PingTransport actual = {0};
        CtaphidReassembler message = assemble_ping(length, &expected);
        CtaphidReassembler saved = message;
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) == CTAPHID_DISPATCH_OK);
        assert(actual.accepted == expected.accepted && actual.attempted == expected.attempted);
        assert(memcmp(actual.reports, expected.reports,
            expected.accepted * CTAPHID_REPORT_SIZE) == 0);
        assert(!message.has_complete_message);
        saved.has_complete_message = false;
        assert(memcmp(&message, &saved, sizeof message) == 0);

        /* Once consumed, the same request cannot accidentally send a second reply. */
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) ==
            CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
        assert(actual.attempted == expected.attempted);
    }
}

static void test_send_failure_consumes_request(void)
{
    for (size_t fail_at = 1U; fail_at <= 4U; ++fail_at) {
        CtaphidChannelManager channels = allocated_channels();
        PingTransport expected = {0};
        PingTransport actual = {0};
        actual.fail_at = fail_at;
        CtaphidReassembler message = assemble_ping(200U, &expected);
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) ==
            CTAPHID_DISPATCH_RESPONSE_FAILED);
        assert(actual.attempted == fail_at && actual.accepted == fail_at - 1U);
        assert(!message.has_complete_message);
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) ==
            CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
        assert(actual.attempted == fail_at);
    }
}

static void test_validation_does_not_send(void)
{
    CtaphidChannelManager channels = allocated_channels();
    PingTransport expected = {0};
    PingTransport actual = {0};
    CtaphidReassembler message = assemble_ping(60U, &expected);
    CtaphidReassembler saved = message;
    assert(ctaphid_dispatch_message(&message, &channels, NULL, &actual) == CTAPHID_DISPATCH_NULL_ARGUMENT);
    assert(memcmp(&message, &saved, sizeof message) == 0);
    assert(ctaphid_dispatch_message(NULL, &channels, capture_report, &actual) == CTAPHID_DISPATCH_NULL_ARGUMENT);

    message.channel_id = 0U;
    saved = message;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) == CTAPHID_DISPATCH_INVALID_CHANNEL);
    assert(memcmp(&message, &saved, sizeof message) == 0);
    message.channel_id = UINT32_MAX;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) == CTAPHID_DISPATCH_INVALID_CHANNEL);
    message.channel_id = 1U;
    message.received_length = 59U;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) == CTAPHID_DISPATCH_INVALID_MESSAGE);
    message.received_length = 60U;
    message.is_active = true;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &actual) == CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
    assert(actual.attempted == 0U);
}

int main(void)
{
    test_all_ping_lengths();
    test_send_failure_consumes_request();
    test_validation_does_not_send();
    puts("CTAPHID PING tests passed (all configured request-to-response lengths).");
    return 0;
}
