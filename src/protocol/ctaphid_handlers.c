#include "protocol/ctaphid_handlers.h"

#include <inttypes.h>
#include <stdio.h>

void ctaphid_handle_init(const CtaphidReassembler *message)
{
    printf("INIT: %u bytes\n", (unsigned int)message->received_length);
}

void ctaphid_handle_ping(const CtaphidReassembler *message)
{
    printf("PING: %u bytes\n", (unsigned int)message->received_length);
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
