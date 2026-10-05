#include "protocol/ctaphid_reassembler.h"

static void ctaphid_reassembler_reset(CtaphidReassembler *reassembler);
static bool ctaphid_reassembler_is_timed_out(
    const CtaphidReassembler *reassembler,
    uint32_t current_time_ms
);
static void ctaphid_reassembler_copy_fragment(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet
);

CtaphidReassembleResult ctaphid_reassemble_packet(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet,
    uint32_t current_time_ms
) {
    if (reassembler == NULL || packet == NULL) {
        return CTAPHID_REASSEMBLE_NULL_ARGUMENT;
    }

    if(ctaphid_reassembler_is_timed_out(reassembler, current_time_ms)) {
        ctaphid_reassembler_reset(reassembler);
    }

    if(reassembler->is_active && reassembler->channel_id != packet->channel_id) {
        return CTAPHID_REASSEMBLE_CHANNEL_BUSY;
    }

    if(packet->message_length > CTAPHID_MAX_MESSAGE_SIZE) {
        ctaphid_reassembler_reset(reassembler);
        return CTAPHID_REASSEMBLE_MESSAGE_TOO_LARGE;
    }

    if(!reassembler->is_active && packet->packet_type != CTAPHID_PACKET_INITIAL) {
        return CTAPHID_REASSEMBLE_IGNORED;
    }

    if(!reassembler->is_active) {
        reassembler->is_active = true;
        reassembler->channel_id = packet->channel_id;
        reassembler->command = packet->command;
        reassembler->expected_length = packet->message_length;
        reassembler->received_length = 0;
        reassembler->expected_sequence = 0;
        reassembler->last_activity_time_ms = current_time_ms;
        ctaphid_reassembler_copy_fragment(reassembler, packet);
        
        if(reassembler->received_length == reassembler->expected_length) {
            return CTAPHID_REASSEMBLE_COMPLETE;
        }
        return CTAPHID_REASSEMBLE_INCOMPLETE;
    }

    if(reassembler->expected_sequence != packet->sequence_number) {
        ctaphid_reassembler_reset(reassembler);
        return CTAPHID_REASSEMBLE_INVALID_SEQUENCE;
    }

    if(reassembler->received_length + packet->fragment_length > CTAPHID_MAX_MESSAGE_SIZE) {
        ctaphid_reassembler_reset(reassembler);
        return CTAPHID_REASSEMBLE_MESSAGE_TOO_LARGE;
    }

    reassembler->expected_sequence++;
    reassembler->last_activity_time_ms = current_time_ms;
    ctaphid_reassembler_copy_fragment(reassembler, packet);

    if(reassembler->received_length == reassembler->expected_length) {
        return CTAPHID_REASSEMBLE_COMPLETE;
    }

    return CTAPHID_REASSEMBLE_INCOMPLETE;
}

static void ctaphid_reassembler_reset(CtaphidReassembler *reassembler) {
    reassembler->is_active = false;
    reassembler->channel_id = 0;
    reassembler->command = 0;
    reassembler->expected_length = 0;
    reassembler->received_length = 0;
    reassembler->expected_sequence = 0;
    reassembler->last_activity_time_ms = 0;
}

static bool ctaphid_reassembler_is_timed_out(
    const CtaphidReassembler *reassembler,
    uint32_t current_time_ms
) {
    if (reassembler == NULL) {
        return false;
    }

    if(reassembler->is_active == false) {
        return false;
    }

    return (current_time_ms - reassembler->last_activity_time_ms) >= CTAPHID_TRANSACTION_TIMEOUT_MS;
}

static uint16_t ctaphid_reassembler_copy_fragment(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet
) {
    uint16_t remaining =
        reassembler->expected_length - reassembler->received_length;

    uint16_t copy_length =
        packet->fragment_length < remaining
            ? packet->fragment_length
            : remaining;

    memcpy(
        reassembler->buffer + reassembler->received_length,
        packet->payload,
        copy_length
    );

    reassembler->received_length += copy_length;

    return copy_length;
}