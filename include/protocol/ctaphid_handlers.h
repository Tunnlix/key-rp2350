#ifndef CTAPHID_HANDLERS_H
#define CTAPHID_HANDLERS_H

#include "protocol/ctaphid_reassembler.h"
#include "protocol/ctaphid_response.h"

/* Inputs are borrowed, immutable, and validated by the dispatcher.
 * PING echoes the complete payload through the response serializer. Its return
 * value reports serialization/transport failure; it does not modify the request.
 * Other handlers remain development-only logging stubs.
 */
void ctaphid_handle_init(const CtaphidReassembler *message);
CtaphidResponseResult ctaphid_handle_ping(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
);
void ctaphid_handle_cbor(const CtaphidReassembler *message);
void ctaphid_handle_lock(const CtaphidReassembler *message);
void ctaphid_handle_wink(const CtaphidReassembler *message);
void ctaphid_handle_cancel(uint32_t channel_id);

#endif
