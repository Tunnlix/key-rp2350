#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_dispatcher.h"

typedef struct {
    uint8_t report[64];
    size_t attempts;
    bool fail;
} Transport;

static bool capture_report(void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    Transport *transport = context;
    ++transport->attempts;
    memcpy(transport->report, report, sizeof transport->report);
    return !transport->fail;
}

static CtaphidChannelManager allocated_channels(void)
{
    CtaphidChannelManager channels = {0};
    uint32_t cid;
    assert(ctaphid_channels_allocate(&channels, &cid) == CTAPHID_CHANNEL_OK);
    assert(cid == 1U);
    return channels;
}

static CtaphidReassembler assemble_request(uint8_t command, size_t length)
{
    CtaphidReassembler message = {0};
    size_t offset = 0U, index = 0U;
    do {
        uint8_t report[64] = {0, 0, 0, 1};
        size_t header = index == 0U ? 7U : 5U;
        if (index == 0U) {
            report[4] = (uint8_t)(command | 0x80U);
            report[5] = (uint8_t)(length >> 8); report[6] = (uint8_t)length;
        } else {
            report[4] = (uint8_t)(index - 1U);
        }
        size_t count = length - offset;
        if (count > sizeof report - header) count = sizeof report - header;
        for (size_t i = 0; i < count; ++i) report[header + i] = (uint8_t)(offset + i);
        CtaphidParsedPacket packet;
        assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
        CtaphidReassembleResult result = ctaphid_reassemble_packet(&message, &packet, (uint32_t)index);
        offset += count;
        assert(result == (offset < length ? CTAPHID_REASSEMBLE_INCOMPLETE : CTAPHID_REASSEMBLE_COMPLETE));
        ++index;
    } while (offset < length);
    return message;
}

static void test_wink_reply(void)
{
    CtaphidChannelManager channels = allocated_channels();
    CtaphidChannelManager saved_channels = channels;
    CtaphidReassembler message = assemble_request(0x08U, 0U);
    Transport transport = {0};
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    const uint8_t expected[64] = {0, 0, 0, 1, 0x88, 0, 0};
    assert(transport.attempts == 1U);
    assert(memcmp(transport.report, expected, sizeof expected) == 0);
    assert(memcmp(&channels, &saved_channels, sizeof channels) == 0);
    assert(!message.has_complete_message);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
    assert(transport.attempts == 1U);
}

static void test_msg_rejected(void)
{
    const size_t lengths[] = {0U, 1U, 60U, 200U};
    CtaphidChannelManager channels = allocated_channels();
    CtaphidChannelManager saved_channels = channels;
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
        CtaphidReassembler message = assemble_request(0x03U, lengths[i]);
        Transport transport = {0};
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
        const uint8_t expected[64] = {0, 0, 0, 1, 0xBF, 0, 1, 0x01};
        assert(transport.attempts == 1U);
        assert(memcmp(transport.report, expected, sizeof expected) == 0);
        assert(!message.has_complete_message);
        assert(memcmp(&channels, &saved_channels, sizeof channels) == 0);
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
        assert(transport.attempts == 1U);
    }
}

static void test_validation_and_transport_failure(void)
{
    CtaphidChannelManager channels = allocated_channels();
    Transport transport = {0};
    CtaphidReassembler message = assemble_request(0x08U, 1U);
    CtaphidReassembler saved = message;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INVALID_LENGTH);
    assert(memcmp(&message, &saved, sizeof message) == 0);
    assert(transport.attempts == 0U);
    const uint8_t commands[] = {0x08U, 0x03U};
    for (size_t i = 0; i < sizeof commands; ++i) {
        message = assemble_request(commands[i], 0U);
        saved = message;
        assert(ctaphid_dispatch_message(&message, &channels, NULL, &transport) == CTAPHID_DISPATCH_NULL_ARGUMENT);
        assert(memcmp(&message, &saved, sizeof message) == 0);
        assert(transport.attempts == 0U);
        transport.fail = true;
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_RESPONSE_FAILED);
        assert(transport.attempts == 1U && !message.has_complete_message);
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
        assert(transport.attempts == 1U);
        memset(&transport, 0, sizeof transport);
    }
}

int main(void)
{
    test_wink_reply();
    test_msg_rejected();
    test_validation_and_transport_failure();
    puts("CTAPHID WINK and unsupported MSG tests passed.");
    return 0;
}
