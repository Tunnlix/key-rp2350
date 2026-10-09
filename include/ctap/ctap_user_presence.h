#ifndef CTAP_USER_PRESENCE_H
#define CTAP_USER_PRESENCE_H

#include <stdbool.h>
#include <stdint.h>
#include "ctap_config.h"

#define CTAP_USER_PRESENCE_MIN_TIMEOUT_MS 10000U
#define CTAP_USER_PRESENCE_DEFAULT_TIMEOUT_MS CTAP_TOUCH_TIMEOUT_MS

typedef enum {
    CTAP_PRESENCE_IDLE = 0,
    CTAP_PRESENCE_WAITING,
    CTAP_PRESENCE_CONFIRMED,
    CTAP_PRESENCE_DENIED,
    CTAP_PRESENCE_TIMED_OUT
} CtapPresenceResult;

/* Fresh, single-operation user presence. No cached presses, GPIO, console, HID,
 * or user verification. Platform events must be marshalled into the main loop.
 * Initialize with {0}; do not edit fields. Use a shared monotonic uint32_t clock
 * and unique operation IDs supplied by the coordinator. */
typedef struct {
    CtapPresenceResult result;
    uint64_t operation_id;
    uint32_t started_ms;
    uint32_t timeout_ms;
} CtapUserPresence;

/* CTAP 2.3 section 5: user-action waits must last at least 10 seconds.
 * Rejects operation ID zero, an already active wait, or invalid timeouts without
 * changing state. Durations are bounded below half the counter cycle. */
bool ctap_user_presence_begin(CtapUserPresence *presence, uint64_t operation_id,
    uint32_t now_ms, uint32_t timeout_ms);
CtapPresenceResult ctap_user_presence_poll(CtapUserPresence *presence, uint32_t now_ms);

/* Only a matching, currently waiting operation may consume a fresh event.
 * Expiry wins at the exact deadline. Late, duplicate, stale, or pre-request
 * events return false and cannot confirm a later operation. */
bool ctap_user_presence_signal(CtapUserPresence *presence, uint64_t operation_id,
    bool confirmed, uint32_t now_ms);
void ctap_user_presence_abort(CtapUserPresence *presence, uint64_t operation_id);

#endif
