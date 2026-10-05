#ifndef CTAPHID_HANDLERS_H
#define CTAPHID_HANDLERS_H

#include "protocol/ctaphid_reassembler.h"

/* Development-only host handlers: print the validated request. No protocol
 * operation or response is implemented. Replace this module for embedded use;
 * the dispatcher itself has no terminal or OS dependency. Inputs are borrowed
 * for the duration of the call, immutable, and validated by the dispatcher.
 */
void ctaphid_handle_init(const CtaphidReassembler *message);
void ctaphid_handle_ping(const CtaphidReassembler *message);
void ctaphid_handle_cbor(const CtaphidReassembler *message);
void ctaphid_handle_lock(const CtaphidReassembler *message);
void ctaphid_handle_wink(const CtaphidReassembler *message);
void ctaphid_handle_cancel(uint32_t channel_id);

#endif
