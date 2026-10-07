#ifndef CTAPHID_DISPATCHER_H
#define CTAPHID_DISPATCHER_H

#include "protocol/ctaphid_reassembler.h"
#include "protocol/ctaphid_response.h"
#include "protocol/ctaphid_channels.h"

#define CTAPHID_COMMAND_PING       0x01U
#define CTAPHID_COMMAND_MSG        0x03U
#define CTAPHID_COMMAND_LOCK       0x04U
#define CTAPHID_COMMAND_INIT       0x06U
#define CTAPHID_COMMAND_WINK       0x08U
#define CTAPHID_COMMAND_CBOR       0x10U
#define CTAPHID_COMMAND_CANCEL     0x11U
#define CTAPHID_COMMAND_KEEPALIVE  0x3BU
#define CTAPHID_COMMAND_ERROR      0x3FU

#define CTAPHID_CAPABILITY_WINK 0x01U
#define CTAPHID_CAPABILITY_CBOR 0x04U
#define CTAPHID_CAPABILITY_NMSG 0x08U

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

/* Direct synchronous routing assumes the caller performs the WINK platform
 * action. Prefer ctaphid_device for integrated routing and capability selection.
 * Validate a complete message and call its handler. Validation failure leaves
 * the message unchanged. Routing consumes has_complete_message, including when
 * a response returns RESPONSE_FAILED: some reports may already have been delivered,
 * so retrying dispatch must not resend a partial response.
 * INIT/PING/WINK and MSG rejection require send_report; transport_context is
 * passed through unchanged and may be NULL. CBOR execution and CANCEL belong
 * to the device/backend; optional LOCK is unsupported.
 * channels is borrowed device-owned allocation state and must not be NULL.
 * Broadcast INIT allocates a CID; existing-channel INIT preserves that CID and
 * the allocated range. Other requests require an allocated CID. Allocation
 * exhaustion sends ERR_OTHER and consumes the request. An allocated CID remains
 * allocated even if its INIT reply fails to send: it may have reached the host.
 * Transaction resynchronization belongs to the reassembler/coordinator, not to
 * channel allocation. This module has no processing/transaction state.
 * MSG is intentionally unsupported: sends ERR_INVALID_CMD and consumes the
 * request. OK means the error reply was delivered successfully, not MSG support.
 * KEEPALIVE/ERROR are response-only.
 * CANCEL must never receive a HID reply. It returns NO_RESPONSE here because
 * no asynchronous operation runs in this dispatcher. Eligibility belongs to coordination;
 * the current reassembler ignores CANCEL because no operation is running there.
 */
CtaphidDispatchResult ctaphid_dispatch_message(
    CtaphidReassembler *message,
    CtaphidChannelManager *channels,
    CtaphidSendReport send_report,
    void *transport_context
);

/* Device coordinator variant: advertise configured capabilities. Always uses
 * NMSG; only the WINK/CBOR capability bits are accepted from capabilities.
 * The caller performs the WINK action before routing its valid request. CBOR
 * execution belongs to the backend, not this synchronous dispatcher. */
CtaphidDispatchResult ctaphid_dispatch_message_with_capabilities(
    CtaphidReassembler *message,
    CtaphidChannelManager *channels,
    uint8_t capabilities,
    CtaphidSendReport send_report,
    void *transport_context
);

#endif
