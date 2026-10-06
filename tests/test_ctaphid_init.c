#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_dispatcher.h"

static const uint8_t nonce[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

typedef struct {
    uint8_t report[64];
    size_t attempts;
    bool fail;
} InitTransport;

static bool capture_report(void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    InitTransport *transport = context;
    ++transport->attempts;
    memcpy(transport->report, report, sizeof transport->report);
    return !transport->fail;
}

static CtaphidReassembler assemble_init(uint32_t cid, uint16_t length)
{
    uint8_t report[64] = {0};
    report[0] = (uint8_t)(cid >> 24); report[1] = (uint8_t)(cid >> 16);
    report[2] = (uint8_t)(cid >> 8); report[3] = (uint8_t)cid;
    report[4] = 0x86U;
    report[5] = (uint8_t)(length >> 8); report[6] = (uint8_t)length;
    memcpy(report + 7U, nonce, sizeof nonce);
    CtaphidParsedPacket packet;
    CtaphidReassembler message = {0};
    assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
    assert(ctaphid_reassemble_packet(&message, &packet, 0U) == CTAPHID_REASSEMBLE_COMPLETE);
    return message;
}

static void verify_init_reply(const InitTransport *transport, uint32_t request_cid, uint32_t assigned_cid)
{
    uint8_t expected[64] = {0};
    expected[0] = (uint8_t)(request_cid >> 24); expected[1] = (uint8_t)(request_cid >> 16);
    expected[2] = (uint8_t)(request_cid >> 8); expected[3] = (uint8_t)request_cid;
    expected[4] = 0x86U; expected[6] = 17U;
    memcpy(expected + 7U, nonce, sizeof nonce);
    expected[15] = (uint8_t)(assigned_cid >> 24); expected[16] = (uint8_t)(assigned_cid >> 16);
    expected[17] = (uint8_t)(assigned_cid >> 8); expected[18] = (uint8_t)assigned_cid;
    expected[19] = 2U; /* Protocol version. */
    expected[21] = 1U; /* Device version 0.1.0. */
    expected[23] = 0x09U; /* WINK | NMSG; CBOR is not advertised yet. */
    assert(transport->attempts == 1U);
    assert(memcmp(transport->report, expected, sizeof expected) == 0);
}

static void test_broadcast_allocation_and_existing_channel(void)
{
    CtaphidChannelManager channels = {0};
    for (uint32_t cid = 1U; cid <= CTAPHID_MAX_CHANNELS; ++cid) {
        CtaphidReassembler message = assemble_init(UINT32_MAX, 8U);
        InitTransport transport = {0};
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
        verify_init_reply(&transport, UINT32_MAX, cid);
        assert(ctaphid_channels_is_allocated(&channels, cid));
        assert(!message.has_complete_message);
        assert(memcmp(message.buffer, nonce, sizeof nonce) == 0);

        /* Existing CID returns itself and never consumes another allocation. */
        CtaphidChannelManager saved = channels;
        message = assemble_init(cid, 8U);
        memset(&transport, 0, sizeof transport);
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
        verify_init_reply(&transport, cid, cid);
        assert(memcmp(&channels, &saved, sizeof channels) == 0);
    }
    CtaphidChannelManager saved = channels;
    CtaphidReassembler message = assemble_init(UINT32_MAX, 8U);
    InitTransport transport = {0};
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    const uint8_t error[64] = {0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0x00, 0x01, 0x7F};
    assert(transport.attempts == 1U && !message.has_complete_message);
    assert(memcmp(transport.report, error, sizeof error) == 0);
    assert(memcmp(&channels, &saved, sizeof channels) == 0);
    message = assemble_init(UINT32_MAX, 8U);
    memset(&transport, 0, sizeof transport);
    transport.fail = true;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_RESPONSE_FAILED);
    assert(!message.has_complete_message && transport.attempts == 1U);
    assert(memcmp(&channels, &saved, sizeof channels) == 0);
}

static void test_big_endian_channel_and_id_exhaustion(void)
{
    CtaphidChannelManager channels = {0};
    /* Seed a large CID to test all four payload/header CID bytes. */
    channels.next_channel_id = 0x12345678U;
    CtaphidReassembler message = assemble_init(UINT32_MAX, 8U);
    InitTransport transport = {0};
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    verify_init_reply(&transport, UINT32_MAX, 0x12345678U);
    message = assemble_init(0x12345678U, 8U);
    memset(&transport, 0, sizeof transport);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    verify_init_reply(&transport, 0x12345678U, 0x12345678U);

    channels.next_channel_id = UINT32_MAX;
    CtaphidChannelManager saved = channels;
    message = assemble_init(UINT32_MAX, 8U);
    memset(&transport, 0, sizeof transport);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    assert(transport.report[4] == 0xBFU && transport.report[7] == 0x7FU);
    assert(memcmp(&channels, &saved, sizeof channels) == 0);
}

static void test_validation_has_no_side_effects(void)
{
    CtaphidChannelManager channels = {0};
    CtaphidChannelManager saved_channels = channels;
    InitTransport transport = {0};
    const uint16_t invalid_lengths[] = {0U, 7U, 9U};
    for (size_t i = 0; i < sizeof invalid_lengths / sizeof invalid_lengths[0]; ++i) {
        CtaphidReassembler message = assemble_init(UINT32_MAX, invalid_lengths[i]);
        CtaphidReassembler saved = message;
        assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INVALID_LENGTH);
        assert(memcmp(&message, &saved, sizeof message) == 0);
    }
    CtaphidReassembler message = assemble_init(UINT32_MAX, 8U);
    assert(ctaphid_dispatch_message(&message, &channels, NULL, &transport) == CTAPHID_DISPATCH_NULL_ARGUMENT);
    assert(message.has_complete_message);
    assert(ctaphid_dispatch_message(&message, NULL, capture_report, &transport) == CTAPHID_DISPATCH_NULL_ARGUMENT);
    message = assemble_init(0U, 8U);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INVALID_CHANNEL);
    message = assemble_init(1U, 8U);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INVALID_CHANNEL);
    assert(transport.attempts == 0U);
    assert(memcmp(&channels, &saved_channels, sizeof channels) == 0);
}

static void test_failed_reply_preserves_allocation(void)
{
    CtaphidChannelManager channels = {0};
    CtaphidReassembler message = assemble_init(UINT32_MAX, 8U);
    InitTransport transport = {0};
    transport.fail = true;
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_RESPONSE_FAILED);
    assert(!message.has_complete_message && transport.attempts == 1U);
    assert(ctaphid_channels_is_allocated(&channels, 1U));
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INCOMPLETE_MESSAGE);
    assert(transport.attempts == 1U);

    message = assemble_init(1U, 8U);
    memset(&transport, 0, sizeof transport);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    verify_init_reply(&transport, 1U, 1U);
}

static void test_init_resynchronizes_partial_reception(void)
{
    CtaphidChannelManager channels = {0};
    uint32_t cid;
    assert(ctaphid_channels_allocate(&channels, &cid) == CTAPHID_CHANNEL_OK);
    CtaphidReassembler message = {0};
    uint8_t report[64] = {0, 0, 0, 1, 0x81, 0, 100};
    CtaphidParsedPacket packet;
    assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
    assert(ctaphid_reassemble_packet(&message, &packet, 0U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    report[4] = 0x86U; report[6] = 8U;
    memcpy(report + 7U, nonce, sizeof nonce);
    assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
    assert(ctaphid_reassemble_packet(&message, &packet, 1U) == CTAPHID_REASSEMBLE_COMPLETE);
    CtaphidChannelManager saved = channels;
    InitTransport transport = {0};
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    verify_init_reply(&transport, cid, cid);
    assert(memcmp(&channels, &saved, sizeof channels) == 0);
}

static void test_allocated_channel_can_ping(void)
{
    CtaphidChannelManager channels = {0};
    InitTransport transport = {0};
    CtaphidReassembler message = assemble_init(UINT32_MAX, 8U);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    uint32_t cid = ((uint32_t)transport.report[15] << 24) |
        ((uint32_t)transport.report[16] << 16) |
        ((uint32_t)transport.report[17] << 8) | transport.report[18];
    /* Send PING using the CID obtained from the INIT reply. */
    uint8_t report[64] = {0};
    memcpy(report, transport.report + 15U, 4U);
    report[4] = 0x81U; report[6] = 3U;
    report[7] = 0xAAU; report[8] = 0xBBU; report[9] = 0xCCU;
    CtaphidParsedPacket packet;
    assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
    assert(ctaphid_reassemble_packet(&message, &packet, 10U) == CTAPHID_REASSEMBLE_COMPLETE);
    memset(&transport, 0, sizeof transport);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_OK);
    assert(transport.attempts == 1U);
    assert(memcmp(transport.report, report, sizeof report) == 0);
    assert(ctaphid_channels_is_allocated(&channels, cid));

    /* A nonzero CID that has never been allocated cannot send commands. */
    report[3] = 2U;
    assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
    assert(ctaphid_reassemble_packet(&message, &packet, 20U) == CTAPHID_REASSEMBLE_COMPLETE);
    assert(ctaphid_dispatch_message(&message, &channels, capture_report, &transport) == CTAPHID_DISPATCH_INVALID_CHANNEL);
    assert(transport.attempts == 1U);
}

int main(void)
{
    test_broadcast_allocation_and_existing_channel();
    test_big_endian_channel_and_id_exhaustion();
    test_validation_has_no_side_effects();
    test_failed_reply_preserves_allocation();
    test_init_resynchronizes_partial_reception();
    test_allocated_channel_can_ping();
    puts("CTAPHID INIT tests passed (allocation, replies, resync, and failures).");
    return 0;
}
