#ifndef CTAPHID_HOST_PRESENCE_H
#define CTAPHID_HOST_PRESENCE_H

#include "protocol/ctaphid_ctap_backend.h"

/* Test-only presence provider. A private directory contains request/event files;
 * binary report stdin/stdout are untouched. Console mode uses Enter/d/c. */
typedef struct {
    char request_path[1024], temporary_path[1024], event_path[1024];
    bool file_mode, console_mode, cancel_requested;
    uint64_t notified_operation;
    uint32_t auto_touch_ms; /* UINT32_MAX disables automatic test confirmation. */
} HostPresence;

bool ctaphid_host_presence_init(HostPresence *simulation, const char *directory,
    bool console_mode, uint32_t auto_touch_ms);
bool ctaphid_host_presence_poll(HostPresence *simulation,
    CtaphidCtapBackend *backend, uint32_t now_ms);

#endif
