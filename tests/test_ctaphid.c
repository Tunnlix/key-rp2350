#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_parser.h"
#include "protocol/ctaphid_reassembler.h"

static void make_report(uint8_t report[CTAPHID_REPORT_SIZE], uint32_t channel_id,
    uint8_t command_or_sequence, uint16_t message_length, size_t payload_offset)
{
    memset(report, 0xee, CTAPHID_REPORT_SIZE);
    report[0] = (uint8_t)(channel_id >> 24);
    report[1] = (uint8_t)(channel_id >> 16);
    report[2] = (uint8_t)(channel_id >> 8);
    report[3] = (uint8_t)channel_id;
    report[4] = command_or_sequence;
    size_t header_length = 5U;
    if ((command_or_sequence & 0x80U) != 0U) {
        report[5] = (uint8_t)(message_length >> 8);
        report[6] = (uint8_t)message_length;
        header_length = 7U;
    }
    for (size_t i = header_length; i < CTAPHID_REPORT_SIZE; ++i) {
        report[i] = (uint8_t)(payload_offset + i - header_length);
    }
}

static CtaphidParsedPacket parse_report(uint32_t channel_id,
    uint8_t command_or_sequence, uint16_t message_length, size_t payload_offset)
{
    uint8_t report[CTAPHID_REPORT_SIZE];
    CtaphidParsedPacket packet;
    make_report(report, channel_id, command_or_sequence, message_length, payload_offset);
    assert(ctaphid_parse_packet(report, sizeof report, &packet) == CTAPHID_PARSE_OK);
    return packet;
}

static void test_parser(void)
{
    uint8_t report[CTAPHID_REPORT_SIZE];
    CtaphidParsedPacket output = {0};
    make_report(report, 0x12345678U, 0x86U, 8U, 0U);
    assert(ctaphid_parse_packet(report, sizeof report, &output) == CTAPHID_PARSE_OK);
    assert(output.channel_id == 0x12345678U);
    assert(output.packet_type == CTAPHID_PACKET_INITIAL);
    assert(output.command == 6U && output.sequence_number == 0U);
    assert(output.message_length == 8U && output.fragment_length == 8U);
    for (size_t i = 0; i < sizeof output.payload; ++i) {
        assert(output.payload[i] == (i < 8U ? (uint8_t)i : 0U));
    }
    output = parse_report(1U, 0x7fU, 0U, 0U);
    assert(output.packet_type == CTAPHID_PACKET_CONTINUATION);
    assert(output.sequence_number == 127U);
    assert(output.command == 0U && output.message_length == 0U);
    assert(output.fragment_length == 59U);
    for (size_t i = 0; i < sizeof output.payload; ++i) {
        assert(output.payload[i] == (uint8_t)i);
    }
    /* Unknown/vendor commands remain frame data, not parser policy. */
    output = parse_report(1U, 0xffU, CTAPHID_MAX_WIRE_MESSAGE_SIZE, 0U);
    assert(output.command == 127U && output.message_length == 7609U);
    CtaphidParsedPacket saved = output;
    make_report(report, 1U, 0x81U, 7610U, 0U);
    assert(ctaphid_parse_packet(report, sizeof report, &output) ==
        CTAPHID_PARSE_INVALID_MESSAGE_LENGTH);
    assert(memcmp(&output, &saved, sizeof output) == 0);
    make_report(report, 1U, 0x81U, UINT16_MAX, 0U);
    assert(ctaphid_parse_packet(report, sizeof report, &output) ==
        CTAPHID_PARSE_INVALID_MESSAGE_LENGTH);
    for (size_t length = 0; length < CTAPHID_REPORT_SIZE; ++length) {
        assert(ctaphid_parse_packet(report, length, &output) ==
            CTAPHID_PARSE_INVALID_REPORT_LENGTH);
    }
    assert(ctaphid_parse_packet(report, 65U, &output) == CTAPHID_PARSE_INVALID_REPORT_LENGTH);
    assert(ctaphid_parse_packet(NULL, 64U, &output) == CTAPHID_PARSE_NULL_ARGUMENT);
    assert(ctaphid_parse_packet(report, 64U, NULL) == CTAPHID_PARSE_NULL_ARGUMENT);
    assert(memcmp(&output, &saved, sizeof output) == 0);
}

static void test_all_supported_lengths(void)
{
    for (uint16_t length = 0; length <= CTAPHID_MAX_MESSAGE_SIZE; ++length) {
        CtaphidReassembler state = {0};
        CtaphidParsedPacket packet = parse_report(1U, 0x81U, length, 0U);
        CtaphidReassembleResult result = ctaphid_reassemble_packet(&state, &packet, 0U);
        size_t offset = CTAPHID_INITIAL_PAYLOAD_SIZE;
        uint8_t sequence = 0U;
        while (offset < length) {
            assert(result == CTAPHID_REASSEMBLE_INCOMPLETE && state.is_active);
            packet = parse_report(1U, sequence, 0U, offset);
            result = ctaphid_reassemble_packet(&state, &packet, (uint32_t)sequence + 1U);
            offset += CTAPHID_CONTINUATION_PAYLOAD_SIZE;
            ++sequence;
        }
        assert(result == CTAPHID_REASSEMBLE_COMPLETE && !state.is_active);
        assert(state.received_length == length && state.expected_length == length);
        assert(state.channel_id == 1U && state.command == 1U);
        for (size_t i = 0; i < length; ++i) {
            assert(state.buffer[i] == (uint8_t)i);
        }
        for (size_t i = length; i < sizeof state.buffer; ++i) {
            assert(state.buffer[i] == 0U); /* Final report padding wasn't copied. */
        }
        CtaphidReassembler saved = state;
        /* Keep this spurious packet a continuation even after sequence 127. */
        packet = parse_report(1U, sequence & 0x7FU, 0U, offset);
        assert(ctaphid_reassemble_packet(&state, &packet, 100U) == CTAPHID_REASSEMBLE_IGNORED);
        assert(memcmp(&state, &saved, sizeof state) == 0);
        packet = parse_report(2U, 0x81U, 0U, 0U);
        assert(ctaphid_reassemble_packet(&state, &packet, 10001U) == CTAPHID_REASSEMBLE_COMPLETE);
        assert(state.channel_id == 2U);
    }
}

static void test_arbitration(void)
{
    CtaphidReassembler state = {0};
    CtaphidParsedPacket packet = parse_report(1U, 0U, 0U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 0U) == CTAPHID_REASSEMBLE_IGNORED);
    packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 0U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    CtaphidReassembler saved = state;
    packet = parse_report(2U, 0U, 0U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 1U) == CTAPHID_REASSEMBLE_IGNORED);
    packet = parse_report(2U, 0x81U, 8U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 1U) == CTAPHID_REASSEMBLE_CHANNEL_BUSY);
    for (uint32_t channel = 1U; channel <= 2U; ++channel) {
        packet = parse_report(channel, 0x91U, 0U, 0U);
        assert(ctaphid_reassemble_packet(&state, &packet, 1U) == CTAPHID_REASSEMBLE_IGNORED);
    }
    assert(memcmp(&state, &saved, sizeof state) == 0);
    packet = parse_report(1U, 0x86U, 8U, 100U);
    assert(ctaphid_reassemble_packet(&state, &packet, 2U) == CTAPHID_REASSEMBLE_COMPLETE);
    assert(state.command == 6U && state.received_length == 8U && state.buffer[0] == 100U);
    ctaphid_reassembler_reset(&state);
    packet = parse_report(1U, 0x91U, 0U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 3U) == CTAPHID_REASSEMBLE_IGNORED);
    assert(!state.is_active);
}

static void test_sequence_errors(void)
{
    for (unsigned duplicate = 0; duplicate < 2U; ++duplicate) {
        CtaphidReassembler state = {0};
        CtaphidParsedPacket packet = parse_report(1U, 0x81U, 200U, 0U);
        assert(ctaphid_reassemble_packet(&state, &packet, 0U) == CTAPHID_REASSEMBLE_INCOMPLETE);
        if (duplicate != 0U) {
            packet = parse_report(1U, 0U, 0U, 57U);
            assert(ctaphid_reassemble_packet(&state, &packet, 1U) == CTAPHID_REASSEMBLE_INCOMPLETE);
        }
        uint8_t invalid_sequence = 1U;
        if (duplicate != 0U) {
            invalid_sequence = 0U;
        }
        packet = parse_report(1U, invalid_sequence, 0U, 57U);
        assert(ctaphid_reassemble_packet(&state, &packet, 2U) == CTAPHID_REASSEMBLE_INVALID_SEQUENCE);
        assert(!state.is_active && state.received_length == 0U);
    }
    CtaphidReassembler state = {0};
    CtaphidParsedPacket packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 0U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    assert(ctaphid_reassemble_packet(&state, &packet, 1U) == CTAPHID_REASSEMBLE_INVALID_SEQUENCE);
    assert(!state.is_active);
}

static void test_timeouts(void)
{
    CtaphidReassembler state = {0};
    CtaphidParsedPacket packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, UINT32_MAX - 100U) ==
        CTAPHID_REASSEMBLE_INCOMPLETE);
    packet = parse_report(2U, 0x81U, 0U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 2898U) == CTAPHID_REASSEMBLE_CHANNEL_BUSY);
    /* Exactly at expiry, B is accepted in the same call, including clock wrap. */
    assert(ctaphid_reassemble_packet(&state, &packet, 2899U) == CTAPHID_REASSEMBLE_COMPLETE);
    assert(!state.is_active && state.channel_id == 2U);
    packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 4000U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    packet = parse_report(1U, 0U, 0U, 57U);
    assert(ctaphid_reassemble_packet(&state, &packet, 6999U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    packet = parse_report(2U, 0x81U, 0U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 9998U) == CTAPHID_REASSEMBLE_CHANNEL_BUSY);
    assert(ctaphid_reassemble_packet(&state, &packet, 9999U) == CTAPHID_REASSEMBLE_COMPLETE);
    assert(state.channel_id == 2U);

    packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 10000U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    packet = parse_report(1U, 0U, 0U, 57U);
    assert(ctaphid_reassemble_packet(&state, &packet, 13000U) == CTAPHID_REASSEMBLE_IGNORED);
    assert(!state.is_active && state.channel_id == 0U && state.received_length == 0U);
}

static void test_explicit_expiry(void)
{
    CtaphidReassembler state = {0};
    CtaphidReassembler saved = state;
    assert(!ctaphid_reassembler_expire_if_timed_out(&state, 5000U));
    assert(memcmp(&state, &saved, sizeof state) == 0);

    CtaphidParsedPacket packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 100U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    saved = state;
    assert(!ctaphid_reassembler_expire_if_timed_out(&state, 3099U));
    assert(memcmp(&state, &saved, sizeof state) == 0);
    assert(ctaphid_reassembler_expire_if_timed_out(&state, 3100U));
    assert(!state.is_active && !state.has_complete_message);
    assert(state.channel_id == 0U && state.command == 0U);
    assert(state.expected_length == 0U && state.received_length == 0U);
    assert(state.expected_sequence == 0U && state.last_activity_time_ms == 0U);
    assert(memcmp(state.buffer, saved.buffer, sizeof state.buffer) == 0);
    saved = state;
    assert(!ctaphid_reassembler_expire_if_timed_out(&state, 3101U));
    assert(memcmp(&state, &saved, sizeof state) == 0);

    /* Expiry without an incoming report also handles counter wraparound. */
    assert(ctaphid_reassemble_packet(&state, &packet, UINT32_MAX - 100U) ==
        CTAPHID_REASSEMBLE_INCOMPLETE);
    assert(!ctaphid_reassembler_expire_if_timed_out(&state, 2898U));
    assert(ctaphid_reassembler_expire_if_timed_out(&state, 2899U));

    /* Valid continuation data refreshes the inactivity deadline. */
    assert(ctaphid_reassemble_packet(&state, &packet, 4000U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    packet = parse_report(1U, 0U, 0U, 57U);
    assert(ctaphid_reassemble_packet(&state, &packet, 6999U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    saved = state;
    assert(!ctaphid_reassembler_expire_if_timed_out(&state, 9998U));
    assert(memcmp(&state, &saved, sizeof state) == 0);
    assert(ctaphid_reassembler_expire_if_timed_out(&state, 9999U));

    /* Completed data remains available for dispatch, regardless of age. */
    packet = parse_report(1U, 0x81U, 3U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 10000U) == CTAPHID_REASSEMBLE_COMPLETE);
    saved = state;
    assert(!ctaphid_reassembler_expire_if_timed_out(&state, 20000U));
    assert(memcmp(&state, &saved, sizeof state) == 0);
}

static void test_expiry_continues_assembly(void)
{
    CtaphidReassembler state = {0};
    CtaphidParsedPacket packet = parse_report(1U, 0x81U, 200U, 0U);
    assert(ctaphid_reassemble_packet(&state, &packet, 0U) == CTAPHID_REASSEMBLE_INCOMPLETE);

    /* A fragmented request on another CID starts in the same call as expiry. */
    packet = parse_report(2U, 0x81U, 60U, 100U);
    assert(ctaphid_reassemble_packet(&state, &packet, 3000U) == CTAPHID_REASSEMBLE_INCOMPLETE);
    assert(state.is_active && state.channel_id == 2U && state.received_length == 57U);
    packet = parse_report(2U, 0U, 0U, 157U);
    assert(ctaphid_reassemble_packet(&state, &packet, 3001U) == CTAPHID_REASSEMBLE_COMPLETE);
    assert(state.has_complete_message && state.received_length == 60U);
    for (size_t i = 0; i < 60U; ++i) {
        assert(state.buffer[i] == (uint8_t)(100U + i));
    }
}

static void test_reassembler_validation(void)
{
    CtaphidReassembler state = {0};
    CtaphidReassembler saved = state;
    CtaphidParsedPacket packet = parse_report(1U, 0x81U, 200U, 0U);
    packet.message_length = CTAPHID_MAX_MESSAGE_SIZE + 1U;
    /* At maximum capacity, the extra byte also exceeds the wire format. */
    CtaphidReassembleResult oversized = CTAPHID_MAX_MESSAGE_SIZE < CTAPHID_MAX_WIRE_MESSAGE_SIZE
        ? CTAPHID_REASSEMBLE_MESSAGE_TOO_LARGE : CTAPHID_REASSEMBLE_INVALID_PACKET;
    assert(ctaphid_reassemble_packet(&state, &packet, 0U) == oversized);
    assert(memcmp(&state, &saved, sizeof state) == 0);
    assert(ctaphid_reassemble_packet(NULL, &packet, 0U) == CTAPHID_REASSEMBLE_NULL_ARGUMENT);
    assert(ctaphid_reassemble_packet(&state, NULL, 0U) == CTAPHID_REASSEMBLE_NULL_ARGUMENT);
    for (unsigned invalid_case = 0; invalid_case < 5U; ++invalid_case) {
        packet = parse_report(1U, 0x81U, 200U, 0U);
        switch (invalid_case) {
        case 0: packet.fragment_length = 255U; break;
        case 1: packet.packet_type = (CtaphidPacketType)2; break;
        case 2: packet.command = 128U; break;
        case 3: packet.message_length = 7610U; break;
        default:
            packet = parse_report(1U, 0U, 0U, 0U);
            packet.sequence_number = 128U;
            break;
        }
        assert(ctaphid_reassemble_packet(&state, &packet, 0U) == CTAPHID_REASSEMBLE_INVALID_PACKET);
        assert(memcmp(&state, &saved, sizeof state) == 0);
    }
    ctaphid_reassembler_reset(NULL);
}

int main(void)
{
    test_parser();
    test_all_supported_lengths();
    test_arbitration();
    test_sequence_errors();
    test_timeouts();
    test_explicit_expiry();
    test_expiry_continues_assembly();
    test_reassembler_validation();
    puts("CTAPHID parser/reassembler tests passed (all configured payload lengths).");
    return 0;
}
