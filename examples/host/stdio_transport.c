#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "stdio_transport.h"
#include "host_actions.h"
#include "host_clock.h"
#include "host_presence.h"
#include "protocol/ctaphid_device.h"
#include "protocol/ctaphid_ctap_backend.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#endif

typedef enum { INPUT_DATA, INPUT_WAIT, INPUT_EOF, INPUT_ERROR } InputResult;

/* Nonblocking input availability keeps device_poll running during silence.
 * Reads may be shorter than a report; the loop accumulates exactly 64 bytes. */
static InputResult read_available(uint8_t *destination, size_t capacity, size_t *received)
{
    *received = 0U;
#ifdef _WIN32
    HANDLE input = (HANDLE)_get_osfhandle(_fileno(stdin));
    DWORD kind = GetFileType(input);
    if (kind == FILE_TYPE_PIPE) {
        DWORD available = 0U;
        if (!PeekNamedPipe(input, NULL, 0U, NULL, &available, NULL)) {
            return GetLastError() == ERROR_BROKEN_PIPE ? INPUT_EOF : INPUT_ERROR;
        }
        if (available == 0U) {
            Sleep(10U);
            return INPUT_WAIT;
        }
        if (capacity > available) capacity = available;
    } else if (kind != FILE_TYPE_DISK) {
        fprintf(stderr, "--stdio requires piped or file input\n");
        return INPUT_ERROR;
    }
    DWORD count = 0U;
    if (!ReadFile(input, destination, (DWORD)capacity, &count, NULL)) {
        return GetLastError() == ERROR_BROKEN_PIPE ? INPUT_EOF : INPUT_ERROR;
    }
    *received = count;
#else
    struct pollfd input = {STDIN_FILENO, POLLIN, 0};
    int ready = poll(&input, 1U, 10);
    if (ready < 0) return errno == EINTR ? INPUT_WAIT : INPUT_ERROR;
    if (ready == 0) return INPUT_WAIT;
    ssize_t count = read(STDIN_FILENO, destination, capacity);
    if (count < 0) return errno == EINTR ? INPUT_WAIT : INPUT_ERROR;
    *received = (size_t)count;
#endif
    return *received == 0U ? INPUT_EOF : INPUT_DATA;
}

static bool send_binary_report(void *context,
    const uint8_t report[CTAPHID_REPORT_SIZE], uint64_t transfer_id)
{
    FILE *output = context;
    (void)transfer_id; /* Synchronous pipe write; no async USB completion event. */
    return fwrite(report, 1U, CTAPHID_REPORT_SIZE, output) == CTAPHID_REPORT_SIZE &&
        fflush(output) == 0;
}

int ctaphid_host_run_stdio(const char *presence_control_directory)
{
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
        _setmode(_fileno(stdout), _O_BINARY) == -1) {
        fprintf(stderr, "Cannot enable binary stdio\n");
        return 1;
    }
#endif
    CtaphidDeviceConfig config = {0};
    config.submit_report = send_binary_report;
    config.transport_context = stdout;
    config.wink_action = ctaphid_host_wink;
    CtapGetInfoProfile profile = {0}; /* Development AAGUID, not a production model identity. */
    profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE;
    profile.user_presence = presence_control_directory != NULL;
    HostPresence simulation;
    if (!ctaphid_host_presence_init(&simulation, presence_control_directory, false, UINT32_MAX)) return 1;
    CtaphidCtapBackend backend;
    if (!ctaphid_ctap_backend_init(&backend, &profile)) return 1;
    config.start_cbor = ctaphid_ctap_backend_start;
    config.abort_cbor = ctaphid_ctap_backend_abort;
    config.cbor_context = &backend;
    CtaphidDevice device;
    if (ctaphid_device_init(&device, &config) != CTAPHID_DEVICE_OK) return 1;

    uint8_t report[CTAPHID_REPORT_SIZE];
    size_t filled = 0U;
    for (;;) {
        uint32_t now_ms = ctaphid_host_now_ms();
        CtaphidDeviceResult polled = ctaphid_device_poll(&device, now_ms);
        if (polled != CTAPHID_DEVICE_OK && polled != CTAPHID_DEVICE_QUEUE_FULL) {
            fprintf(stderr, "Device poll failed: %d\n", (int)polled);
            return 1;
        }
        /* Complete prepared CTAP work outside coordinator callbacks, then let
         * the coordinator serialize/transmit its final response. */
        CtaphidDeviceResult completed = ctaphid_ctap_backend_poll(&backend, &device, now_ms);
        if (completed != CTAPHID_DEVICE_OK && completed != CTAPHID_DEVICE_IGNORED) return 1;
        if (!ctaphid_host_presence_poll(&simulation, &backend, now_ms)) return 1;
        completed = ctaphid_ctap_backend_poll(&backend, &device, now_ms);
        if (completed != CTAPHID_DEVICE_OK && completed != CTAPHID_DEVICE_IGNORED) return 1;
        if (ctaphid_device_poll(&device, now_ms) != CTAPHID_DEVICE_OK) return 1;
        size_t received;
        InputResult input = read_available(report + filled, sizeof report - filled, &received);
        if (input == INPUT_WAIT) continue;
        if (input == INPUT_EOF) {
            if (filled == 0U) return 0;
            fprintf(stderr, "Truncated input report: %zu/64 bytes\n", filled);
            return 1;
        }
        if (input == INPUT_ERROR) {
            fprintf(stderr, "Failed to read report input\n");
            return 1;
        }
        filled += received;
        if (filled == sizeof report) {
            CtaphidDeviceResult result = ctaphid_device_receive_report(
                &device, report, sizeof report, ctaphid_host_now_ms());
            /* Backpressure preserves this report for retry after output drains. */
            while (result == CTAPHID_DEVICE_QUEUE_FULL) {
                if (ctaphid_device_poll(&device, ctaphid_host_now_ms()) != CTAPHID_DEVICE_OK) return 1;
                result = ctaphid_device_receive_report(&device, report, sizeof report, ctaphid_host_now_ms());
            }
            if (result != CTAPHID_DEVICE_OK && result != CTAPHID_DEVICE_IGNORED) {
                fprintf(stderr, "Report receive failed: %d\n", (int)result);
                return 1;
            }
            filled = 0U;
        }
    }
}
