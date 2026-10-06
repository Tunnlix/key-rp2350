#include "ctap/ctap_reset.h"

#include <stddef.h>
#include <string.h>

void ctap_reset_init(CtapReset *reset, uint32_t powered_at_ms,
    CtapResetStorage reset_storage, void *storage_context)
{
    if (reset == NULL) return;
    memset(reset, 0, sizeof *reset);
    reset->powered_at_ms = powered_at_ms;
    reset->reset_storage = reset_storage;
    reset->storage_context = storage_context;
}

uint8_t ctap_reset_authorize(CtapReset *reset, uint64_t operation_id,
    uint32_t received_at_ms)
{
    if (reset == NULL || reset->reset_storage == NULL || operation_id == 0U ||
        reset->authorized_operation != 0U) return CTAP_STATUS_OPERATION_DENIED;
    if (reset->window_closed || (uint32_t)(received_at_ms - reset->powered_at_ms) > CTAP_RESET_POWER_ON_WINDOW_MS) {
        return CTAP_STATUS_NOT_ALLOWED;
    }
    reset->authorized_operation = operation_id;
    return CTAP_STATUS_OK;
}

void ctap_reset_poll(CtapReset *reset, uint32_t now_ms)
{
    if (reset != NULL && (uint32_t)(now_ms - reset->powered_at_ms) > CTAP_RESET_POWER_ON_WINDOW_MS) {
        reset->window_closed = true;
    }
}

uint8_t ctap_reset_commit(CtapReset *reset, uint64_t operation_id,
    const CtapUserPresence *presence)
{
    if (reset == NULL || presence == NULL || reset->reset_storage == NULL ||
        operation_id == 0U || reset->authorized_operation != operation_id ||
        presence->operation_id != operation_id || presence->result != CTAP_PRESENCE_CONFIRMED) {
        return CTAP_STATUS_OPERATION_DENIED;
    }
    /* Consume authorization before the side effect, even if storage fails. */
    reset->authorized_operation = 0U;
    return reset->reset_storage(reset->storage_context) ? CTAP_STATUS_OK : CTAP_STATUS_OTHER;
}

void ctap_reset_abort(CtapReset *reset, uint64_t operation_id)
{
    if (reset != NULL && reset->authorized_operation == operation_id) reset->authorized_operation = 0U;
}
