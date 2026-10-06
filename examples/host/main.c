#include "protocol/ctaphid_parser.h"
#include "protocol/ctaphid_reassembler.h"
#include "protocol/ctaphid_dispatcher.h"
#include <stdio.h>

/* Host demonstration transport. Display outgoing wire bytes; a binary pipe or
 * USB transport can replace this callback without changing the handlers. */
static bool display_response_report(
    void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    FILE *output = context;
    if (fputs("TX:", output) == EOF) return false;
    for (size_t i = 0; i < CTAPHID_REPORT_SIZE; ++i) {
        if (fprintf(output, " %02X", (unsigned int)report[i]) < 0) return false;
    }
    return fputc('\n', output) != EOF && fflush(output) == 0;
}

int main(void)
{
    CtaphidReassembler reassembler;
    ctaphid_reassembler_reset(&reassembler);
    CtaphidChannelManager channels;
    ctaphid_channels_reset(&channels);

    uint8_t reports[][CTAPHID_REPORT_SIZE] = {
        /* INIT: eight-byte nonce on the broadcast CID. */
        { 0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08,
          0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 },
        /* First PING: three bytes, complete in one report. */
        { 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x03, 0xAA, 0xBB, 0xCC },
        /* Second PING: 60 bytes, requiring a continuation. */
        { 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x3C },
        { 0x00, 0x00, 0x00, 0x01, 0x00, 0x39, 0x3A, 0x3B },
        /* WINK: identification action followed by an empty response. */
        { 0x00, 0x00, 0x00, 0x01, 0x88, 0x00, 0x00 },
        /* MSG is rejected with ERR_INVALID_CMD; no CTAP1 operation is run. */
        { 0x00, 0x00, 0x00, 0x01, 0x83, 0x00, 0x01, 0x00 }
    };
    const char *descriptions[] = {
        "INIT", "PING 1", "PING 2 initial", "PING 2 continuation", "WINK", "MSG unsupported"
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

        if (status == CTAPHID_REASSEMBLE_COMPLETE) {
            CtaphidDispatchResult result = ctaphid_dispatch_message(
                &reassembler, &channels, display_response_report, stdout);
            if (result != CTAPHID_DISPATCH_OK && result != CTAPHID_DISPATCH_NO_RESPONSE) {
                fprintf(stderr, "%s: dispatch status=%d\n", descriptions[i], (int)result);
                return 1;
            }
        } else if (status != CTAPHID_REASSEMBLE_INCOMPLETE &&
                   status != CTAPHID_REASSEMBLE_IGNORED) {
            fprintf(stderr, "%s: assembly status=%d\n", descriptions[i], (int)status);
            return 1;
        }
        current_time_ms += 10U;
    }
    return 0;
}
