#include "protocol/ctaphid_device.h"
#include <stdio.h>
#include <string.h>
#include "stdio_transport.h"
#include "host_actions.h"

/* Host demonstration transport. Display outgoing wire bytes; a binary pipe or
 * USB transport can replace this callback without changing the handlers. */
typedef struct {
    FILE *output;
    uint32_t allocated_cid;
} HostTransport;

static bool display_response_report(
    void *context, const uint8_t report[CTAPHID_REPORT_SIZE], uint64_t transfer_id)
{
    HostTransport *transport = context;
    FILE *output = transport->output;
    (void)transfer_id; /* Synchronous transport finishes before returning. */
    if (report[4] == 0x86U && report[5] == 0U && report[6] == 17U) {
        transport->allocated_cid = ((uint32_t)report[15] << 24) |
            ((uint32_t)report[16] << 16) | ((uint32_t)report[17] << 8) | report[18];
    }
    if (fputs("TX:", output) == EOF) return false;
    for (size_t i = 0; i < CTAPHID_REPORT_SIZE; ++i) {
        if (fprintf(output, " %02X", (unsigned int)report[i]) < 0) return false;
    }
    return fputc('\n', output) != EOF && fflush(output) == 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--stdio") == 0) return ctaphid_host_run_stdio();
    if (argc != 1) {
        fprintf(stderr, "Usage: %s [--stdio]\n", argv[0]);
        return 2;
    }
    HostTransport transport = {stdout, 0U};
    CtaphidDeviceConfig config = {0};
    config.submit_report = display_response_report;
    config.transport_context = &transport;
    config.wink_action = ctaphid_host_wink;
    CtaphidDevice device;
    if (ctaphid_device_init(&device, &config) != CTAPHID_DEVICE_OK) return 1;

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
        /* Host uses the actual CID from INIT, rather than assuming allocation 1. */
        if (i != 0U) {
            reports[i][0] = (uint8_t)(transport.allocated_cid >> 24);
            reports[i][1] = (uint8_t)(transport.allocated_cid >> 16);
            reports[i][2] = (uint8_t)(transport.allocated_cid >> 8);
            reports[i][3] = (uint8_t)transport.allocated_cid;
        }
        CtaphidDeviceResult result = ctaphid_device_receive_report(
            &device, reports[i], sizeof reports[i], current_time_ms);
        if (result != CTAPHID_DEVICE_OK && result != CTAPHID_DEVICE_IGNORED) {
            fprintf(stderr, "%s: receive status=%d\n", descriptions[i], (int)result);
            return 1;
        }
        if (ctaphid_device_poll(&device, current_time_ms) != CTAPHID_DEVICE_OK) return 1;
        current_time_ms += 10U;
    }
    return 0;
}
