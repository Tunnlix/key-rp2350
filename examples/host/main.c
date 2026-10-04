#include "protocol/ctaphid_parser.h"
#include <stdio.h>

int main(void)
{

    uint8_t packet[CTAPHID_REPORT_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF,
        0x86,
        0x00, 0x08,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00
    };


    CtaphidParsedPacket parsed_packet;
    CtaphidParseResult result = ctaphid_parse_packet(packet, &parsed_packet);

    if(result == CTAPHID_PARSE_OK) {
        printf("CID: 0x%08X\n", parsed_packet.channel_id);
        printf("Packet Type: %s\n", parsed_packet.packet_type == CTAPHID_PACKET_INITIAL ? "Initial" : "Continuation");
        printf("Command: 0x%02X\n", parsed_packet.command);
        printf("Sequence: %d\n", parsed_packet.sequence_number);
        printf("Total Length: %d\n", parsed_packet.message_length);
        printf("Payload Length: %d\n", parsed_packet.payload_length);
        printf("Payload: ");
        for(int i = 0; i < parsed_packet.payload_length; i++) {
            printf("0x%02X ", parsed_packet.payload[i]);
        }
        printf("\n");
    }else {
        printf("Invalid packet\n");
    }
    return 0;
}
