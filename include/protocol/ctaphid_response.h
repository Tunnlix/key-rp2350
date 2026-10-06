#ifndef CTAPHID_RESPONSE_H
#define CTAPHID_RESPONSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol/ctaphid_framing.h"

/* Transport boundary: accept one complete 64-byte report, in call order.
 * Return true after sending or copying it; false on failure.
 * report is borrowed only during this call. An asynchronous queue must copy it.
 * context is passed through unchanged and may be NULL. */
typedef bool (*CtaphidSendReport)(
    void *context,
    const uint8_t report[CTAPHID_REPORT_SIZE]
);

typedef enum {
    CTAPHID_RESPONSE_OK = 0,
    CTAPHID_RESPONSE_INVALID_ARGUMENT,
    CTAPHID_RESPONSE_INVALID_COMMAND,
    CTAPHID_RESPONSE_INVALID_LENGTH,
    CTAPHID_RESPONSE_SEND_FAILED
} CtaphidResponseResult;

/* Fragment a complete response payload and encode it as HID reports.
 * command is a decoded seven-bit value (PING = 0x01, ERROR = 0x3F).
 * payload is immutable and must remain valid until this function returns.
 * NULL payload is allowed only for zero length; send_report must not be NULL.
 * Length is limited by wire framing, not the reassembler's receive buffer.
 * All arguments are validated before any callback. Empty responses still emit
 * one initial report. Padding is zeroed; no allocation or retained state is used.
 *
 * OK means every report was accepted by the callback, not that asynchronous
 * transmission has finished. SEND_FAILED stops immediately; earlier reports
 * may already have been sent. No retry or rollback is performed.
 *
 * Handlers construct payloads (including CTAP status/CBOR bytes). The coordinator
 * selects the response CID/command, validates allocated channels, prevents
 * replies to CANCEL, and owns transaction lifetime. This function performs
 * framing only: it does not validate command-specific payloads or send USB data.
 */
CtaphidResponseResult ctaphid_send_response(
    uint32_t channel_id,
    uint8_t command,
    const uint8_t *payload,
    size_t payload_length,
    CtaphidSendReport send_report,
    void *context
);

#endif
