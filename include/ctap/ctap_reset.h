#ifndef CTAP_RESET_H
#define CTAP_RESET_H

#include "ctap/ctap.h"
#include "ctap/ctap_user_presence.h"

#define CTAP_RESET_POWER_ON_WINDOW_MS 10000U

/* Application-owned factory reset. Return true only after a complete durable
 * reset; false must not be reported as success. Use atomic/fail-closed storage.
 * Responsibilities include invalidating all generated credentials (including
 * non-discoverable key handles), erasing stored credentials/PIN/PUAT state,
 * resetting supported blob/configuration state, and rotating device identifier
 * and credential-store state with fresh 128-bit cryptographic randomness.
 * Erase provider-owned credential secrets and regenerate the hmac-secret key
 * agreement key when that provider is bound (also for profiles without PIN).
 * Preserve model identity/AAGUID and factory attestation identity as applicable.
 * Callback must be bounded and must not reenter protocol APIs. It is the commit
 * point: cancellation cannot undo a successfully committed factory reset. */
typedef bool (*CtapResetStorage)(void *context);

/* No-display reset policy. Clock/window are independent of HID allocations.
 * Initialize once per actual power-on with its original clock timestamp; factory
 * reset and INIT must never reinitialize/reopen this window. */
typedef struct {
    uint32_t powered_at_ms;
    bool window_closed;
    CtapResetStorage reset_storage;
    void *storage_context;
    uint64_t authorized_operation;
} CtapReset;

void ctap_reset_init(CtapReset *reset, uint32_t powered_at_ms,
    CtapResetStorage reset_storage, void *storage_context);

/* Uses request arrival time, not later processing/confirmation time. Disabled
 * transport returns OPERATION_DENIED; arrival after 10s returns NOT_ALLOWED.
 * Exactly 10s remains in the window (the specification says "after 10 seconds").
 * Success reserves a single operation but performs no storage write. */
uint8_t ctap_reset_authorize(CtapReset *reset, uint64_t operation_id,
    uint32_t received_at_ms);

/* Latch expiry permanently so uint32_t clock wrap cannot reopen the window.
 * Call regularly, after authorizing any newly arrived pending request. */
void ctap_reset_poll(CtapReset *reset, uint32_t now_ms);

/* Commit once, only for the authorized operation's confirmed presence.
 * Unconfirmed/wrong-operation/duplicate commits do not invoke storage. */
uint8_t ctap_reset_commit(CtapReset *reset, uint64_t operation_id,
    const CtapUserPresence *presence);
void ctap_reset_abort(CtapReset *reset, uint64_t operation_id);

#endif
