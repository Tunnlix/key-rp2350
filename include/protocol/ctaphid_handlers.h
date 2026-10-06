#ifndef CTAPHID_HANDLERS_H
#define CTAPHID_HANDLERS_H

#include "protocol/ctaphid_reassembler.h"
#include "protocol/ctaphid_response.h"

/* Inputs are borrowed, immutable, and validated by the dispatcher.
 * INIT constructs its reply using the CID selected by the dispatcher; it does
 * not allocate channels or reset transaction state. PING echoes the payload.
 * WINK performs the host identification action and sends an empty reply.
 * These handlers return serialization/transport status without modifying the
 * request. CBOR, LOCK, and CANCEL remain development-only logging stubs.
 */
CtaphidResponseResult ctaphid_handle_init(
    const CtaphidReassembler *message,
    uint32_t allocated_channel_id,
    CtaphidSendReport send_report,
    void *transport_context
);
CtaphidResponseResult ctaphid_handle_ping(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
);
void ctaphid_handle_cbor(const CtaphidReassembler *message);
void ctaphid_handle_lock(const CtaphidReassembler *message);
CtaphidResponseResult ctaphid_handle_wink(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
);
void ctaphid_handle_cancel(uint32_t channel_id);

#endif
