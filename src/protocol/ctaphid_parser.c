#include "protocol/ctaphid_parser.h"

#define CTAPHID_INITIAL_MARKER 0x80U
#define CTAPHID_VALUE_MASK 0x7FU
#define CTAPHID_COMMAND_OR_SEQUENCE_OFFSET 4U
#define CTAPHID_LENGTH_HIGH_OFFSET 5U
#define CTAPHID_LENGTH_LOW_OFFSET 6U
#define CTAPHID_INITIAL_PAYLOAD_OFFSET 7U
#define CTAPHID_CONTINUATION_PAYLOAD_OFFSET 5U

static void ctaphid_decode_initial_packet(
    const uint8_t *packet, uint16_t message_length, CtaphidParsedPacket *output)
{
    output->packet_type = CTAPHID_PACKET_INITIAL;
    output->command = packet[CTAPHID_COMMAND_OR_SEQUENCE_OFFSET] & CTAPHID_VALUE_MASK;
    output->message_length = message_length;

    output->fragment_length = message_length < CTAPHID_INITIAL_PAYLOAD_SIZE
        ? (uint8_t)message_length : (uint8_t)CTAPHID_INITIAL_PAYLOAD_SIZE;

    for (size_t i = 0; i < output->fragment_length; ++i) {
        output->payload[i] = packet[CTAPHID_INITIAL_PAYLOAD_OFFSET + i];
    }
}

static void ctaphid_decode_continuation_packet(
    const uint8_t *packet, CtaphidParsedPacket *output)
{
    output->packet_type = CTAPHID_PACKET_CONTINUATION;
    output->sequence_number = packet[CTAPHID_COMMAND_OR_SEQUENCE_OFFSET] & CTAPHID_VALUE_MASK;
    output->fragment_length = (uint8_t)CTAPHID_CONTINUATION_PAYLOAD_SIZE;
    for (size_t i = 0; i < CTAPHID_CONTINUATION_PAYLOAD_SIZE; ++i) {
        output->payload[i] = packet[CTAPHID_CONTINUATION_PAYLOAD_OFFSET + i];
    }
}

CtaphidParseResult ctaphid_parse_packet(
    const uint8_t *packet, size_t packet_length, CtaphidParsedPacket *output)
{
    if (packet == NULL || output == NULL) {
        return CTAPHID_PARSE_NULL_ARGUMENT;
    }
    if (packet_length != CTAPHID_REPORT_SIZE) {
        return CTAPHID_PARSE_INVALID_REPORT_LENGTH;
    }
    const bool is_initial = (packet[CTAPHID_COMMAND_OR_SEQUENCE_OFFSET] & CTAPHID_INITIAL_MARKER) != 0U;
    uint16_t message_length = 0;
    if (is_initial) {
        message_length = (uint16_t)(((uint16_t)packet[CTAPHID_LENGTH_HIGH_OFFSET] << 8)
            | (uint16_t)packet[CTAPHID_LENGTH_LOW_OFFSET]);
        if (message_length > CTAPHID_MAX_WIRE_MESSAGE_SIZE) {
            return CTAPHID_PARSE_INVALID_MESSAGE_LENGTH;
        }
    }

    CtaphidParsedPacket parsed_packet;
    parsed_packet.channel_id = ((uint32_t)packet[0] << 24) | ((uint32_t)packet[1] << 16)
        | ((uint32_t)packet[2] << 8) | (uint32_t)packet[3];
    if (is_initial) {
        ctaphid_decode_initial_packet(packet, message_length, &parsed_packet);
    } else {
        ctaphid_decode_continuation_packet(packet, &parsed_packet);
    }

    *output = parsed_packet;
    return CTAPHID_PARSE_OK;
}
