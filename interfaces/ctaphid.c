#include "ctaphid.h"

CtaphidParseResult ctaphid_process_packet(const uint8_t packet[64], CtaphidParsedPacket *parsed_packet) {

    if(packet == NULL || parsed_packet == NULL) {
        return CTAPHID_INVALID_PARSE;
    }

    uint32_t cid =
    ((uint32_t)packet[0] << 24) |
    ((uint32_t)packet[1] << 16) |
    ((uint32_t)packet[2] << 8)  |
    ((uint32_t)packet[3]);

    bool is_initial_packet = (packet[4] & CTAPHID_INIT_MASK) != 0;

    parsed_packet->cid = cid;
    parsed_packet->packet_type = is_initial_packet ? CTAPHID_PACKET_INITIAL : CTAPHID_PACKET_CONTINUATION;
    
    if(!is_initial_packet) {
        parsed_packet->sequence = packet[4] & 0x7F;
        parsed_packet->command = 0;
        parsed_packet->total_length = 0;
        for(int i = 0; i < CTAPHID_CONTINUATION_PAYLOAD_SIZE; i++) {
            parsed_packet->payload[i] = packet[CTAPHID_CONTINUATION_PAYLOAD_OFFSET + i];
        }
        parsed_packet->payload_length = CTAPHID_CONTINUATION_PAYLOAD_SIZE;
        return CTAPHID_VALID_PARSE;
    }

    uint16_t bcnt =
    ((uint16_t)packet[CTAPHID_BCNTH_OFFSET] << 8) |
    packet[CTAPHID_BCNTL_OFFSET];

    if(bcnt > CTAPHID_MAX_WIRE_MESSAGE_SIZE) {
        return CTAPHID_INVALID_PARSE;
    }

    uint8_t payload_length = bcnt >= CTAPHID_INITIAL_PAYLOAD_SIZE ? CTAPHID_INITIAL_PAYLOAD_SIZE : bcnt;

    parsed_packet->command = packet[4];
    parsed_packet->sequence = 0;
    parsed_packet->total_length = bcnt;
    parsed_packet->payload_length = payload_length;

    for(int i = 0; i < payload_length; i++) {
        parsed_packet->payload[i] = packet[CTAPHID_INITIAL_PAYLOAD_OFFSET + i];
    }
    return CTAPHID_VALID_PARSE;
}
