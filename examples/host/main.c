#include "protocol/ctaphid_parser.h"
#include "protocol/ctaphid_reassembler.h"
#include <stdio.h>
#include <inttypes.h>

static uint64_t get_current_time_ms(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64_t)ts.tv_sec * 1000U)
         + ((uint64_t)ts.tv_nsec / 1000000U);
#endif
}

int main(void)
{
    CtaphidReassembler reassembler = {0};

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
    CtaphidParseResult result = ctaphid_parse_packet(packet, sizeof(packet), &parsed_packet);

    if(result == CTAPHID_PARSE_OK) {
        uint32_t current_time_ms = get_current_time_ms(); 
        CtaphidReassembleResult reassemble_result = ctaphid_reassemble_packet(&reassembler, &parsed_packet, current_time_ms);
    }else {
        printf("Invalid packet\n");
    }
    return 0;
}
