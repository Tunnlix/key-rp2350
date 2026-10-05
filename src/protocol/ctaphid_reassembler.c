#include "protocol/ctaphid_reassembler.h"

#include <string.h>

#define CTAPHID_COMMAND_INIT 0x06U

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

    /*
     * An incomplete transaction must eventually expire.
     *
     * If it has expired, discard the stale partial message and process
     * the newly received packet as if the reassembler were idle.
     */
    if (ctaphid_reassembler_is_timed_out(
            reassembler,
            current_time_ms
        )) {
        ctaphid_reassembler_reset(reassembler);
    }

    /*
     * No message is currently being assembled.
     *
     * A continuation packet without a preceding initial packet is
     * spurious and must be ignored.
     */
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

    /*
     * A partial message is active.
     *
     * Continuation packets from another channel are spurious for the
     * active message and are ignored.
     *
     * A new initial packet from another channel attempts to start
     * another transaction while this one is active, so report busy.
     */
    if (reassembler->channel_id != packet->channel_id) {
        if (packet->packet_type == CTAPHID_PACKET_CONTINUATION) {
            return CTAPHID_REASSEMBLE_IGNORED;
        }

        return CTAPHID_REASSEMBLE_CHANNEL_BUSY;
    }

    /*
     * An initial packet arrived on the same CID while a fragmented
     * message is already being assembled.
     *
     * CTAPHID_INIT is special: on the active CID it aborts and
     * re-synchronizes the current transaction.
     */
    if (packet->packet_type == CTAPHID_PACKET_INITIAL) {
        if (packet->command == CTAPHID_COMMAND_INIT) {
            ctaphid_reassembler_reset(reassembler);

            return ctaphid_reassembler_start_message(
                reassembler,
                packet,
                current_time_ms
            );
        }

        /*
         * Any other new initial packet cannot be used as the expected
         * continuation of the current fragmented message.
         */
        ctaphid_reassembler_reset(reassembler);

        return CTAPHID_REASSEMBLE_INVALID_SEQUENCE;
    }

    /*
     * From here the packet is a continuation packet belonging to the
     * active CID.
     */
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