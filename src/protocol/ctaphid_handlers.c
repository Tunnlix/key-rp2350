#include "protocol/ctaphid_handlers.h"
#include "protocol/ctaphid_dispatcher.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* Advertise only implemented behavior. MSG is intentionally unsupported;
 * CBOR remains a stub, so its capability bit stays clear. */
#define CTAPHID_PROTOCOL_VERSION 2U
#define CTAPHID_DEVICE_VERSION_MAJOR 0U
#define CTAPHID_DEVICE_VERSION_MINOR 1U
#define CTAPHID_DEVICE_VERSION_BUILD 0U
#define CTAPHID_CAPABILITY_NMSG 0x08U
#define CTAPHID_CAPABILITY_WINK 0x01U

CtaphidResponseResult ctaphid_handle_init(
    const CtaphidReassembler *message,
    uint32_t allocated_channel_id,
    CtaphidSendReport send_report,
    void *transport_context
)
{
    /* Payload: nonce[8], assigned CID[4], protocol[1], device version[3], flags[1].
     * The response header uses the request CID, including broadcast allocation. */
    uint8_t response[17] = {0};
    memcpy(response, message->buffer, 8U);
    response[8] = (uint8_t)(allocated_channel_id >> 24);
    response[9] = (uint8_t)(allocated_channel_id >> 16);
    response[10] = (uint8_t)(allocated_channel_id >> 8);
    response[11] = (uint8_t)allocated_channel_id;
    response[12] = CTAPHID_PROTOCOL_VERSION;
    response[13] = CTAPHID_DEVICE_VERSION_MAJOR;
    response[14] = CTAPHID_DEVICE_VERSION_MINOR;
    response[15] = CTAPHID_DEVICE_VERSION_BUILD;
    response[16] = CTAPHID_CAPABILITY_NMSG | CTAPHID_CAPABILITY_WINK;
    return ctaphid_send_response(message->channel_id, CTAPHID_COMMAND_INIT,
        response, sizeof response, send_report, transport_context);
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

CtaphidResponseResult ctaphid_handle_wink(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
)
{
    /* Host identification action. A firmware port can replace this action with
     * an LED indication. Diagnostics stay off the response transport. */
    fprintf(stderr, "WINK: identify authenticator on CID 0x%08" PRIX32 "\n",
        message->channel_id);
    return ctaphid_send_response(message->channel_id, CTAPHID_COMMAND_WINK,
        NULL, 0U, send_report, transport_context);
}

void ctaphid_handle_cancel(uint32_t channel_id)
{
    printf("CANCEL: CID 0x%08" PRIX32 "\n", channel_id);
}
