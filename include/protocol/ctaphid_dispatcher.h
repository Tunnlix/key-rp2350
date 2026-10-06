#ifndef CTAPHID_DISPATCHER_H
#define CTAPHID_DISPATCHER_H

#include "protocol/ctaphid_reassembler.h"
#include "protocol/ctaphid_response.h"

#define CTAPHID_COMMAND_PING       0x01U
#define CTAPHID_COMMAND_MSG        0x03U
#define CTAPHID_COMMAND_LOCK       0x04U
#define CTAPHID_COMMAND_INIT       0x06U
#define CTAPHID_COMMAND_WINK       0x08U
#define CTAPHID_COMMAND_CBOR       0x10U
#define CTAPHID_COMMAND_CANCEL     0x11U
#define CTAPHID_COMMAND_KEEPALIVE  0x3BU
#define CTAPHID_COMMAND_ERROR      0x3FU

typedef enum {
    CTAPHID_DISPATCH_OK = 0,
    CTAPHID_DISPATCH_NO_RESPONSE,
    CTAPHID_DISPATCH_NULL_ARGUMENT,
    CTAPHID_DISPATCH_INCOMPLETE_MESSAGE,
    CTAPHID_DISPATCH_INVALID_MESSAGE,
    CTAPHID_DISPATCH_INVALID_COMMAND,
    CTAPHID_DISPATCH_UNSUPPORTED_COMMAND,
    CTAPHID_DISPATCH_INVALID_LENGTH,
    CTAPHID_DISPATCH_INVALID_PARAMETER,
    CTAPHID_DISPATCH_INVALID_CHANNEL,
    CTAPHID_DISPATCH_RESPONSE_FAILED
} CtaphidDispatchResult;

/* Validate a complete message and call its handler. Validation failure leaves
 * the message unchanged. Routing consumes has_complete_message, including when
 * PING returns RESPONSE_FAILED: some reports may already have been delivered,
 * so retrying dispatch must not resend a partial response.
 * PING requires send_report; transport_context is passed through unchanged and
 * may be NULL. Other handlers remain logging stubs and do not use the callback.
 * This module has no channel table or transaction state. MSG is unsupported;
 * KEEPALIVE/ERROR are response-only.
 * CANCEL must never receive a HID reply, even when malformed. Its case returns
 * NO_RESPONSE. Real cancellation eligibility belongs to transaction coordination;
 * the current reassembler ignores CANCEL because no operation is running there.
 */
CtaphidDispatchResult ctaphid_dispatch_message(
    CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
);

#endif
