#ifndef CTAPHID_HANDLERS_H
#define CTAPHID_HANDLERS_H

#include "protocol/ctaphid_reassembler.h"
#include "protocol/ctaphid_response.h"

/* Inputs are borrowed, immutable, and validated by the dispatcher.
 * INIT constructs its reply using the CID selected by the dispatcher; it does
 * not allocate channels or reset transaction state. PING echoes the payload.
 * WINK sends an empty reply after the caller's platform identification action.
 * These handlers return serialization/transport status without modifying the
 * request. CBOR execution and cancellation belong to the device/backend;
 * optional LOCK remains unsupported.
 */
CtaphidResponseResult ctaphid_handle_init(
    const CtaphidReassembler *message,
    uint32_t allocated_channel_id,
    uint8_t capabilities,
    CtaphidSendReport send_report,
    void *transport_context
);
CtaphidResponseResult ctaphid_handle_ping(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
);
CtaphidResponseResult ctaphid_handle_wink(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
);

#endif
