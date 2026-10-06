#include "protocol/ctaphid_handlers.h"
#include "protocol/ctaphid_dispatcher.h"

#include <inttypes.h>
#include <stdio.h>

void ctaphid_handle_init(const CtaphidReassembler *message)
{
    printf("INIT: %u bytes\n", (unsigned int)message->received_length);
}

CtaphidResponseResult ctaphid_handle_ping(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
)
{
    /* PING's response is the exact request payload. The serializer owns all
     * fragmentation/header encoding; the callback owns report delivery. */
    return ctaphid_send_response(
        message->channel_id,
        CTAPHID_COMMAND_PING,
        message->buffer,
        message->received_length,
        send_report,
        transport_context
    );
}

void ctaphid_handle_cbor(const CtaphidReassembler *message)
{
    printf("CBOR: %u bytes\n", (unsigned int)message->received_length);
}

void ctaphid_handle_lock(const CtaphidReassembler *message)
{
    printf("LOCK: %u seconds\n", (unsigned int)message->buffer[0]);
}

void ctaphid_handle_wink(const CtaphidReassembler *message)
{
    printf("WINK: %u bytes\n", (unsigned int)message->received_length);
}

void ctaphid_handle_cancel(uint32_t channel_id)
{
    printf("CANCEL: CID 0x%08" PRIX32 "\n", channel_id);
}
