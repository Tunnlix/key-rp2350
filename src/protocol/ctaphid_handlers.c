#include "protocol/ctaphid_handlers.h"
#include "protocol/ctaphid_dispatcher.h"
#include "ctap_device_version.h"

#include <string.h>

/* Device version is vendor-defined; CTAP 2.3 still uses HID protocol version 2.
 * Capability selection belongs to routing/device configuration. */
#define CTAPHID_PROTOCOL_VERSION 2U

CtaphidResponseResult ctaphid_handle_init(
    const CtaphidReassembler *message,
    uint32_t allocated_channel_id,
    uint8_t capabilities,
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
    response[13] = CTAP_DEVICE_VERSION_MAJOR;
    response[14] = CTAP_DEVICE_VERSION_MINOR;
    response[15] = CTAP_DEVICE_VERSION_BUILD;
    response[16] = capabilities;
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

CtaphidResponseResult ctaphid_handle_wink(
    const CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
)
{
    /* The caller performs the platform identification action. This handler
     * only builds the protocol acknowledgement; it has no console/LED dependency. */
    return ctaphid_send_response(message->channel_id, CTAPHID_COMMAND_WINK,
        NULL, 0U, send_report, transport_context);
}
