#include "host_presence.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <conio.h>
#else
#include <poll.h>
#include <termios.h>
#include <unistd.h>
#endif

bool ctaphid_host_presence_init(HostPresence *simulation, const char *directory,
    bool console_mode, uint32_t auto_touch_ms)
{
    memset(simulation, 0, sizeof *simulation);
    simulation->console_mode = console_mode;
    simulation->auto_touch_ms = auto_touch_ms;
    if (directory == NULL) return true;
    simulation->file_mode = true;
    int request = snprintf(simulation->request_path, sizeof simulation->request_path, "%s/request", directory);
    int temporary = snprintf(simulation->temporary_path, sizeof simulation->temporary_path, "%s/request.tmp", directory);
    int event = snprintf(simulation->event_path, sizeof simulation->event_path, "%s/event", directory);
    return request >= 0 && (size_t)request < sizeof simulation->request_path &&
        temporary >= 0 && (size_t)temporary < sizeof simulation->temporary_path &&
        event >= 0 && (size_t)event < sizeof simulation->event_path;
}

static void discard_console_input(void)
{
#ifdef _WIN32
    while (_kbhit()) (void)_getch();
#else
    if (isatty(STDIN_FILENO)) (void)tcflush(STDIN_FILENO, TCIFLUSH);
#endif
}

static int console_key(void)
{
#ifdef _WIN32
    return _kbhit() ? _getch() : -1;
#else
    struct pollfd input = {STDIN_FILENO, POLLIN, 0};
    char key;
    return poll(&input, 1U, 0) > 0 && read(STDIN_FILENO, &key, 1U) == 1 ? (unsigned char)key : -1;
#endif
}

bool ctaphid_host_presence_poll(HostPresence *simulation,
    CtaphidCtapBackend *backend, uint32_t now_ms)
{
    if (backend->presence.result != CTAP_PRESENCE_WAITING || !backend->pending) {
        if (simulation->file_mode && simulation->notified_operation != 0U) {
            (void)remove(simulation->request_path);
            (void)remove(simulation->event_path);
        }
        simulation->notified_operation = 0U;
        return true;
    }
    uint64_t operation = backend->presence.operation_id;
    if (simulation->notified_operation != operation) {
        if (simulation->console_mode) {
            discard_console_input();
            fprintf(stderr, "Presence request %" PRIu64 ": Enter=touch, d=deny, c=cancel (30-second timeout)\n", operation);
        }
        if (simulation->file_mode) {
            (void)remove(simulation->request_path);
            (void)remove(simulation->event_path); /* Drop pre-request events. */
            FILE *request = fopen(simulation->temporary_path, "w");
            if (request == NULL) return false;
            bool written = fprintf(request, "%" PRIu64 "\n", operation) > 0;
            if (fclose(request) != 0) written = false;
            if (!written || rename(simulation->temporary_path, simulation->request_path) != 0) return false;
        }
        simulation->notified_operation = operation;
    }
    if (simulation->auto_touch_ms != UINT32_MAX &&
        (uint32_t)(now_ms - backend->presence.started_ms) >= simulation->auto_touch_ms) {
        (void)ctaphid_ctap_backend_signal_presence(backend, operation, true, now_ms);
    }
    if (simulation->console_mode) {
        int key = console_key();
        if (key == '\r' || key == '\n' || key == 'd' || key == 'D') {
            (void)ctaphid_ctap_backend_signal_presence(backend, operation, key == '\r' || key == '\n', now_ms);
        } else if (key == 'c' || key == 'C') simulation->cancel_requested = true;
    }
    if (simulation->file_mode) {
        FILE *event = fopen(simulation->event_path, "r");
        if (event != NULL) {
            uint64_t event_operation;
            char action[8], extra;
            int fields = fscanf(event, "%" SCNu64 " %7s %c", &event_operation, action, &extra);
            fclose(event);
            (void)remove(simulation->event_path);
            if (fields == 2 && (strcmp(action, "touch") == 0 || strcmp(action, "deny") == 0)) {
                (void)ctaphid_ctap_backend_signal_presence(backend, event_operation,
                    strcmp(action, "touch") == 0, now_ms);
            }
        }
    }
    return true;
}
