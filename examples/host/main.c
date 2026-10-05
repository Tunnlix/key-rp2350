#include "protocol/ctaphid_parser.h"
#include "protocol/ctaphid_reassembler.h"
#include <stdio.h>

int main(void)
{
    CtaphidReassembler reassembler;
    ctaphid_reassembler_reset(&reassembler);

    uint8_t reports[][CTAPHID_REPORT_SIZE] = {
        /* INIT: eight-byte nonce on the broadcast CID. */
        { 0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08,
          0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 },
        /* First PING: three bytes, complete in one report. */
        { 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x03, 0xAA, 0xBB, 0xCC },
        /* Second PING: 60 bytes, requiring a continuation. */
        { 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x3C },
        { 0x00, 0x00, 0x00, 0x01, 0x00, 0x39, 0x3A, 0x3B }
    };
    const char *descriptions[] = {
        "INIT", "PING 1", "PING 2 initial", "PING 2 continuation"
    };
    for (size_t i = 0; i < CTAPHID_INITIAL_PAYLOAD_SIZE; ++i) {
        reports[2][7U + i] = (uint8_t)i;
    }

    uint32_t current_time_ms = 0U;
    for (size_t i = 0; i < sizeof reports / sizeof reports[0]; ++i) {
        CtaphidParsedPacket packet;
        CtaphidParseResult parse_result = ctaphid_parse_packet(
            reports[i], sizeof reports[i], &packet);
        if (parse_result != CTAPHID_PARSE_OK) {
            printf("%s: parse status=%d\n", descriptions[i], (int)parse_result);
            return 1;
        }

        CtaphidReassembleResult status = ctaphid_reassemble_packet(
            &reassembler, &packet, current_time_ms);
        /* Status 0 = COMPLETE, 1 = INCOMPLETE; other values are in the result enum. */
        printf("%s: status=%d active_message=%s received=%u/%u\n",
            descriptions[i], (int)status, reassembler.is_active ? "true" : "false",
            (unsigned)reassembler.received_length, (unsigned)reassembler.expected_length);
        current_time_ms += 10U;
    }
    return 0;
}
