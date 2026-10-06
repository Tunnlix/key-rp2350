#include "protocol/ctaphid_reassembler.h"

#include <string.h>

#define CTAPHID_COMMAND_INIT 0x06U
#define CTAPHID_COMMAND_CANCEL 0x11U
#define CTAPHID_MAX_FIELD_VALUE 0x7FU

static bool ctaphid_reassembler_packet_is_valid(const CtaphidParsedPacket *packet)
{
    if (packet->packet_type == CTAPHID_PACKET_INITIAL) {
        /* The parser removes the marker bit; this does not validate command support. */
        if (packet->command > CTAPHID_MAX_FIELD_VALUE ||
                packet->message_length > CTAPHID_MAX_WIRE_MESSAGE_SIZE) {
            return false;
        }

        uint16_t expected_fragment_length = packet->message_length;
        if (expected_fragment_length > CTAPHID_INITIAL_PAYLOAD_SIZE) {
            expected_fragment_length = CTAPHID_INITIAL_PAYLOAD_SIZE;
        }
        return packet->fragment_length == expected_fragment_length;
    }
    if (packet->packet_type == CTAPHID_PACKET_CONTINUATION) {
        /* All 59 bytes are decoded; useful data length is known only during assembly. */
        return packet->sequence_number <= CTAPHID_MAX_FIELD_VALUE &&
            packet->fragment_length == CTAPHID_CONTINUATION_PAYLOAD_SIZE;
    }
    return false;
}

static bool ctaphid_reassembler_is_timed_out(
    const CtaphidReassembler *reassembler,
    uint32_t current_time_ms
);

static void ctaphid_reassembler_copy_fragment(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet
);

static CtaphidReassembleResult ctaphid_reassembler_start_message(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet,
    uint32_t current_time_ms
);

CtaphidReassembleResult ctaphid_reassemble_packet(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet,
    uint32_t current_time_ms
) {
    if (reassembler == NULL || packet == NULL) {
        return CTAPHID_REASSEMBLE_NULL_ARGUMENT;
    }

    if (!ctaphid_reassembler_packet_is_valid(packet)) {
        return CTAPHID_REASSEMBLE_INVALID_PACKET;
    }

    /* Discard expired assembly, then continue processing the incoming packet. */
    (void)ctaphid_reassembler_expire_if_timed_out(reassembler, current_time_ms);

    /* No CBOR operation is processed here; the caller handles processing-time CANCEL. */
    if (packet->packet_type == CTAPHID_PACKET_INITIAL &&
            packet->command == CTAPHID_COMMAND_CANCEL) {
        return CTAPHID_REASSEMBLE_IGNORED;
    }

    /* Continuations without an active message are spurious. */
    if (!reassembler->is_active) {
        if (packet->packet_type == CTAPHID_PACKET_CONTINUATION) {
            return CTAPHID_REASSEMBLE_IGNORED;
        }

        return ctaphid_reassembler_start_message(
            reassembler,
            packet,
            current_time_ms
        );
    }

    /* Other channels cannot interrupt an active message. */
    if (reassembler->channel_id != packet->channel_id) {
        if (packet->packet_type == CTAPHID_PACKET_CONTINUATION) {
            return CTAPHID_REASSEMBLE_IGNORED;
        }

        return CTAPHID_REASSEMBLE_CHANNEL_BUSY;
    }

    /* INIT on the active CID aborts and resynchronizes the message. */
    if (packet->packet_type == CTAPHID_PACKET_INITIAL) {
        if (packet->command == CTAPHID_COMMAND_INIT) {
            ctaphid_reassembler_reset(reassembler);

            return ctaphid_reassembler_start_message(
                reassembler,
                packet,
                current_time_ms
            );
        }

        ctaphid_reassembler_reset(reassembler);

        return CTAPHID_REASSEMBLE_INVALID_SEQUENCE;
    }

    if (packet->sequence_number != reassembler->expected_sequence) {
        ctaphid_reassembler_reset(reassembler);

        return CTAPHID_REASSEMBLE_INVALID_SEQUENCE;
    }

    ctaphid_reassembler_copy_fragment(
        reassembler,
        packet
    );

    reassembler->expected_sequence++;
    reassembler->last_activity_time_ms = current_time_ms;

    if (reassembler->received_length == reassembler->expected_length) {
        reassembler->is_active = false;
        reassembler->has_complete_message = true;
        return CTAPHID_REASSEMBLE_COMPLETE;
    }

    return CTAPHID_REASSEMBLE_INCOMPLETE;
}

void ctaphid_reassembler_reset(
    CtaphidReassembler *reassembler
) {
    if (reassembler == NULL) {
        return;
    }

    reassembler->is_active = false;
    reassembler->has_complete_message = false;

    reassembler->channel_id = 0U;
    reassembler->command = 0U;

    reassembler->expected_length = 0U;
    reassembler->received_length = 0U;

    reassembler->expected_sequence = 0U;

    reassembler->last_activity_time_ms = 0U;
}

static CtaphidReassembleResult ctaphid_reassembler_start_message(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet,
    uint32_t current_time_ms
) {
    if (packet->message_length > CTAPHID_MAX_MESSAGE_SIZE) {
        return CTAPHID_REASSEMBLE_MESSAGE_TOO_LARGE;
    }

    reassembler->is_active = true;
    reassembler->has_complete_message = false;

    reassembler->channel_id = packet->channel_id;
    reassembler->command = packet->command;

    reassembler->expected_length = packet->message_length;
    reassembler->received_length = 0U;

    reassembler->expected_sequence = 0U;

    reassembler->last_activity_time_ms = current_time_ms;

    ctaphid_reassembler_copy_fragment(
        reassembler,
        packet
    );

    if (reassembler->received_length == reassembler->expected_length) {
        reassembler->is_active = false;
        reassembler->has_complete_message = true;
        return CTAPHID_REASSEMBLE_COMPLETE;
    }

    return CTAPHID_REASSEMBLE_INCOMPLETE;
}

static bool ctaphid_reassembler_is_timed_out(
    const CtaphidReassembler *reassembler,
    uint32_t current_time_ms
) {
    if (!reassembler->is_active) {
        return false;
    }

    return (
        current_time_ms -
        reassembler->last_activity_time_ms
    ) >= CTAPHID_TRANSACTION_TIMEOUT_MS;
}

bool ctaphid_reassembler_expire_if_timed_out(
    CtaphidReassembler *reassembler,
    uint32_t current_time_ms
) {
    if (ctaphid_reassembler_is_timed_out(reassembler, current_time_ms)) {
        ctaphid_reassembler_reset(reassembler);
        return true;
    }
    return false;
}

static void ctaphid_reassembler_copy_fragment(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet
) {
    uint16_t remaining =
        reassembler->expected_length -
        reassembler->received_length;

    uint16_t copy_length =
        packet->fragment_length < remaining
            ? packet->fragment_length
            : remaining;

    if (copy_length == 0U) {
        return;
    }

    memcpy(
        reassembler->buffer + reassembler->received_length,
        packet->payload,
        copy_length
    );

    reassembler->received_length += copy_length;
}
