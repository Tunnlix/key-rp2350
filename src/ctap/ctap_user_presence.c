#include "ctap/ctap_user_presence.h"

#include <stddef.h>
#include <string.h>

bool ctap_user_presence_begin(CtapUserPresence *presence, uint64_t operation_id,
    uint32_t now_ms, uint32_t timeout_ms)
{
    if (presence == NULL || operation_id == 0U || presence->result == CTAP_PRESENCE_WAITING ||
        timeout_ms < CTAP_USER_PRESENCE_MIN_TIMEOUT_MS || timeout_ms > INT32_MAX) return false;
    presence->result = CTAP_PRESENCE_WAITING;
    presence->operation_id = operation_id;
    presence->started_ms = now_ms;
    presence->timeout_ms = timeout_ms;
    return true;
}

CtapPresenceResult ctap_user_presence_poll(CtapUserPresence *presence, uint32_t now_ms)
{
    if (presence == NULL) return CTAP_PRESENCE_IDLE;
    if (presence->result == CTAP_PRESENCE_WAITING &&
        (uint32_t)(now_ms - presence->started_ms) >= presence->timeout_ms) {
        presence->result = CTAP_PRESENCE_TIMED_OUT;
    }
    return presence->result;
}

bool ctap_user_presence_signal(CtapUserPresence *presence, uint64_t operation_id,
    bool confirmed, uint32_t now_ms)
{
    if (presence == NULL || presence->operation_id != operation_id ||
        (uint32_t)(now_ms - presence->started_ms) > INT32_MAX ||
        ctap_user_presence_poll(presence, now_ms) != CTAP_PRESENCE_WAITING) return false;
    presence->result = confirmed ? CTAP_PRESENCE_CONFIRMED : CTAP_PRESENCE_DENIED;
    return true;
}

void ctap_user_presence_abort(CtapUserPresence *presence, uint64_t operation_id)
{
    if (presence != NULL && presence->operation_id == operation_id) {
        memset(presence, 0, sizeof *presence);
    }
}
