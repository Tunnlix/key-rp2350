#include "protocol/ctaphid_device.h"
#include "protocol/ctaphid_ctap_backend.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "stdio_transport.h"
#include "host_actions.h"
#include "host_clock.h"
#include "host_presence.h"
#include "host_storage.h"

/* Host demonstration transport. Display outgoing wire bytes; a binary pipe or
 * USB transport can replace this callback without changing the handlers. */
typedef struct {
    FILE *output;
    uint32_t allocated_cid;
    bool compact_keepalive;
    uint8_t last_keepalive_status, last_ctap_status;
} HostTransport;

static bool display_response_report(
    void *context, const uint8_t report[CTAPHID_REPORT_SIZE], uint64_t transfer_id)
{
    HostTransport *transport = context;
    FILE *output = transport->output;
    (void)transfer_id; /* Synchronous transport finishes before returning. */
    if (report[4] == 0x90U && report[6] != 0U) transport->last_ctap_status = report[7];
    if (transport->compact_keepalive && report[4] == 0xBBU) {
        if (transport->last_keepalive_status != report[7]) {
            transport->last_keepalive_status = report[7];
            if (fprintf(output, "KEEPALIVE: %s\n", report[7] == 2U ? "UPNEEDED (waiting for touch)" : "PROCESSING") < 0) return false;
        }
        return fflush(output) == 0;
    }
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
    uint32_t powered_at_ms = ctaphid_host_now_ms();
    bool reset_demo = false, presence_demo = false, stdio_mode = false;
    const char *control_directory = NULL, *storage_directory = NULL;
    uint32_t auto_touch_ms = UINT32_MAX;
    for (int argument = 1; argument < argc; ++argument) {
        if (strcmp(argv[argument], "--stdio") == 0) stdio_mode = true;
        else if (strcmp(argv[argument], "--presence-demo") == 0) presence_demo = true;
        else if (strcmp(argv[argument], "--reset-demo") == 0) { reset_demo = true; presence_demo = true; }
        else if (strcmp(argv[argument], "--store-dir") == 0 && argument + 1 < argc) storage_directory = argv[++argument];
        else if (strcmp(argv[argument], "--presence-control") == 0 && argument + 1 < argc) control_directory = argv[++argument];
        else if (strcmp(argv[argument], "--auto-touch-ms") == 0 && argument + 1 < argc) {
            char *end;
            unsigned long delay = strtoul(argv[++argument], &end, 10);
            if (end == argv[argument] || *end != '\0' || delay > INT32_MAX) return 2;
            auto_touch_ms = (uint32_t)delay;
        } else {
            fprintf(stderr, "Usage: %s [--stdio | --presence-demo | --reset-demo] [--store-dir DIR] [--presence-control DIR] [--auto-touch-ms N]\n", argv[0]);
            return 2;
        }
    }
    if ((stdio_mode && presence_demo) || (!stdio_mode && control_directory != NULL) ||
        (!presence_demo && auto_touch_ms != UINT32_MAX)) return 2;
    if (stdio_mode) return ctaphid_host_run_stdio(control_directory, storage_directory);
    HostTransport transport = {0};
    transport.output = stdout;
    transport.compact_keepalive = presence_demo;
    transport.last_ctap_status = 0xFFU;
    CtaphidDeviceConfig config = {0};
    config.submit_report = display_response_report;
    config.transport_context = &transport;
    config.wink_action = ctaphid_host_wink;
    CtapGetInfoProfile profile = {0}; /* Development AAGUID. */
    profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE;
    profile.user_presence = presence_demo;
    HostPresence simulation;
    if (!ctaphid_host_presence_init(&simulation, NULL, presence_demo, auto_touch_ms)) return 1;
    CtaphidCtapBackend backend;
    if (!ctaphid_ctap_backend_init(&backend, &profile)) return 1;
    HostStorage storage;
    if (!ctaphid_host_storage_init(&storage, NULL, storage_directory) ||
        !ctaphid_ctap_backend_configure_reset(&backend, powered_at_ms, ctaphid_host_storage_reset, &storage)) return 1;
    if (profile.user_presence && !ctaphid_ctap_backend_configure_credentials(&backend, &storage.credentials)) return 1;
    config.start_cbor = ctaphid_ctap_backend_start;
    config.abort_cbor = ctaphid_ctap_backend_abort;
    config.cbor_context = &backend;
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
        { 0x00, 0x00, 0x00, 0x01, 0x83, 0x00, 0x01, 0x00 },
        /* CTAPHID_CBOR wraps CTAP authenticatorGetInfo (0x04). */
        { 0x00, 0x00, 0x00, 0x01, 0x90, 0x00, 0x01, 0x04 },
        /* Optional manual demo: authenticatorSelection asks for a fresh touch. */
        { 0x00, 0x00, 0x00, 0x01, 0x90, 0x00, 0x01, 0x0B }
    };
    const char *descriptions[] = {
        "INIT", "PING 1", "PING 2 initial", "PING 2 continuation", "WINK", "MSG unsupported", "GetInfo", "Selection"
    };
    for (size_t i = 0; i < CTAPHID_INITIAL_PAYLOAD_SIZE; ++i) {
        reports[2][7U + i] = (uint8_t)i;
    }

    uint32_t current_time_ms = 0U;
    size_t report_count = sizeof reports / sizeof reports[0];
    if (reset_demo) {
        reports[report_count - 1U][7] = CTAP_COMMAND_RESET;
        descriptions[report_count - 1U] = "Reset";
    }
    if (!presence_demo) --report_count;
    for (size_t i = 0; i < report_count; ++i) {
        if (presence_demo) current_time_ms = ctaphid_host_now_ms();
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
        if (ctaphid_ctap_backend_poll(&backend, &device, current_time_ms) != CTAPHID_DEVICE_OK) return 1;
        if (presence_demo && !ctaphid_host_presence_poll(&simulation, &backend, current_time_ms)) return 1;
        if (ctaphid_ctap_backend_poll(&backend, &device, current_time_ms) != CTAPHID_DEVICE_OK) return 1;
        if (ctaphid_device_poll(&device, current_time_ms) != CTAPHID_DEVICE_OK) return 1;
        current_time_ms += 10U;
    }
    while (presence_demo && device.phase != CTAPHID_DEVICE_IDLE) {
        uint32_t now = ctaphid_host_now_ms();
        if (ctaphid_device_poll(&device, now) != CTAPHID_DEVICE_OK) return 1;
        if (ctaphid_ctap_backend_poll(&backend, &device, now) != CTAPHID_DEVICE_OK) return 1;
        if (!ctaphid_host_presence_poll(&simulation, &backend, now)) return 1;
        if (simulation.cancel_requested) {
            simulation.cancel_requested = false;
            uint32_t cid = transport.allocated_cid;
            uint8_t cancel[64] = {(uint8_t)(cid >> 24), (uint8_t)(cid >> 16),
                (uint8_t)(cid >> 8), (uint8_t)cid, 0x91U};
            if (ctaphid_device_receive_report(&device, cancel, sizeof cancel, now) != CTAPHID_DEVICE_OK) return 1;
        }
        if (ctaphid_ctap_backend_poll(&backend, &device, now) != CTAPHID_DEVICE_OK) return 1;
        if (ctaphid_device_poll(&device, now) != CTAPHID_DEVICE_OK) return 1;
        ctaphid_host_sleep_ms(10U);
    }
    if (presence_demo) printf("%s result: 0x%02X (00=confirmed, 27=denied, 2D=cancelled, 2F=timed out, 30=outside reset window)\n",
        reset_demo ? "Reset" : "Selection",
        (unsigned int)transport.last_ctap_status);
    if (reset_demo) {
        PcAuthenticatorState state = pc_authenticator_state(storage.authenticator);
        printf("PC vault: generation=%u, credentials=%zu, keys=%zu\n", (unsigned int)state.generation,
            state.credential_count, state.key_count);
    }
    ctaphid_host_storage_close(&storage);
    return 0;
}
