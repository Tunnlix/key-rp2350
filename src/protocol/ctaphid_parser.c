#include "protocol/ctaphid_parser.h"

#include <stdbool.h>
#include <stddef.h>

#define CTAPHID_INIT_MASK 0x80
#define CTAPHID_COMMAND_OR_SEQUENCE_OFFSET 4
#define CTAPHID_BCNTH_OFFSET 5
#define CTAPHID_BCNTL_OFFSET 6
#define CTAPHID_INITIAL_PAYLOAD_OFFSET 7
#define CTAPHID_CONTINUATION_PAYLOAD_OFFSET 5

CtaphidParseResult ctaphid_parse_packet(
    const uint8_t packet[CTAPHID_REPORT_SIZE],
    CtaphidParsedPacket *parsed_packet
) {

    if(packet == NULL || parsed_packet == NULL) {
        return CTAPHID_PARSE_INVALID;
    }

    uint32_t channel_id =
    ((uint32_t)packet[0] << 24) |
    ((uint32_t)packet[1] << 16) |
    ((uint32_t)packet[2] << 8)  |
    ((uint32_t)packet[3]);

    bool is_initial_packet = (packet[CTAPHID_COMMAND_OR_SEQUENCE_OFFSET] & CTAPHID_INIT_MASK) != 0;

    parsed_packet->channel_id = channel_id;
    parsed_packet->packet_type = is_initial_packet ? CTAPHID_PACKET_INITIAL : CTAPHID_PACKET_CONTINUATION;

    if(!is_initial_packet) {
        parsed_packet->sequence_number = packet[CTAPHID_COMMAND_OR_SEQUENCE_OFFSET] & 0x7F;
        parsed_packet->command = 0;
        parsed_packet->message_length = 0;
        for(int i = 0; i < CTAPHID_CONTINUATION_PAYLOAD_SIZE; i++) {
            parsed_packet->payload[i] = packet[CTAPHID_CONTINUATION_PAYLOAD_OFFSET + i];
        }
        parsed_packet->payload_length = CTAPHID_CONTINUATION_PAYLOAD_SIZE;
        return CTAPHID_PARSE_OK;
    }

    uint16_t message_length =
    ((uint16_t)packet[CTAPHID_BCNTH_OFFSET] << 8) |
    packet[CTAPHID_BCNTL_OFFSET];

    if(message_length > CTAPHID_MAX_WIRE_MESSAGE_SIZE) {
        return CTAPHID_PARSE_INVALID;
    }

    uint8_t payload_length = message_length >= CTAPHID_INITIAL_PAYLOAD_SIZE ? CTAPHID_INITIAL_PAYLOAD_SIZE : message_length;

    parsed_packet->command = packet[CTAPHID_COMMAND_OR_SEQUENCE_OFFSET];
    parsed_packet->sequence_number = 0;
    parsed_packet->message_length = message_length;
    parsed_packet->payload_length = payload_length;

    for(int i = 0; i < payload_length; i++) {
        parsed_packet->payload[i] = packet[CTAPHID_INITIAL_PAYLOAD_OFFSET + i];
    }
    return CTAPHID_PARSE_OK;
}
