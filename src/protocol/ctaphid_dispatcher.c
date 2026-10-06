#include "protocol/ctaphid_dispatcher.h"
#include "protocol/ctaphid_handlers.h"

#define CTAPHID_INIT_NONCE_LENGTH 8U
#define CTAPHID_LOCK_PAYLOAD_LENGTH 1U
#define CTAPHID_MAX_LOCK_SECONDS 10U

CtaphidDispatchResult ctaphid_dispatch_message(
    CtaphidReassembler *message,
    CtaphidSendReport send_report,
    void *transport_context
)
{
    if (message == NULL) {
        return CTAPHID_DISPATCH_NULL_ARGUMENT;
    }
    if (!message->has_complete_message || message->is_active) {
        return CTAPHID_DISPATCH_INCOMPLETE_MESSAGE;
    }
    if (message->expected_length > sizeof(message->buffer)
        || message->received_length != message->expected_length) {
        return CTAPHID_DISPATCH_INVALID_MESSAGE;
    }
    if (message->channel_id == 0U || (message->channel_id == CTAPHID_BROADCAST_CHANNEL_ID
        && message->command != CTAPHID_COMMAND_INIT)) {
        return CTAPHID_DISPATCH_INVALID_CHANNEL;
    }

    switch (message->command) {
    case CTAPHID_COMMAND_INIT:
        if (message->received_length != CTAPHID_INIT_NONCE_LENGTH) {
            return CTAPHID_DISPATCH_INVALID_LENGTH;
        }
        ctaphid_handle_init(message);
        break;

    case CTAPHID_COMMAND_PING: {
        if (send_report == NULL) {
            return CTAPHID_DISPATCH_NULL_ARGUMENT;
        }
        CtaphidResponseResult response = ctaphid_handle_ping(
            message, send_report, transport_context);
        /* Sending may have partially succeeded. Consume once, even on failure. */
        message->has_complete_message = false;
        return response == CTAPHID_RESPONSE_OK
            ? CTAPHID_DISPATCH_OK : CTAPHID_DISPATCH_RESPONSE_FAILED;
    }

    case CTAPHID_COMMAND_CBOR:
        if (message->received_length == 0U) {
            return CTAPHID_DISPATCH_INVALID_LENGTH;
        }
        ctaphid_handle_cbor(message);
        break;

    case CTAPHID_COMMAND_CANCEL:
        /* Log a valid CANCEL at this stage; send no response to this request. */
        if (message->received_length == 0U) {
            ctaphid_handle_cancel(message->channel_id);
        }
        message->has_complete_message = false;
        return CTAPHID_DISPATCH_NO_RESPONSE;

    case CTAPHID_COMMAND_LOCK:
        if (message->received_length != CTAPHID_LOCK_PAYLOAD_LENGTH) {
            return CTAPHID_DISPATCH_INVALID_LENGTH;
        }
        if (message->buffer[0] > CTAPHID_MAX_LOCK_SECONDS) {
            return CTAPHID_DISPATCH_INVALID_PARAMETER;
        }
        ctaphid_handle_lock(message);
        break;

    case CTAPHID_COMMAND_WINK:
        if (message->received_length != 0U) {
            return CTAPHID_DISPATCH_INVALID_LENGTH;
        }
        ctaphid_handle_wink(message);
        break;

    case CTAPHID_COMMAND_MSG:
        return CTAPHID_DISPATCH_UNSUPPORTED_COMMAND;

    case CTAPHID_COMMAND_KEEPALIVE:
    case CTAPHID_COMMAND_ERROR:
    default:
        return CTAPHID_DISPATCH_INVALID_COMMAND;
    }

    message->has_complete_message = false;
    return CTAPHID_DISPATCH_OK;
}
