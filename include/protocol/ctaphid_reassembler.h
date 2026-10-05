#ifndef CTAPHID_REASSEMBLER_H
#define CTAPHID_REASSEMBLER_H

#include <stdbool.h>
#include <stdint.h>

#include "protocol/ctaphid_parser.h"

#define CTAPHID_MAX_MESSAGE_SIZE 1024U
#define CTAPHID_TRANSACTION_TIMEOUT_MS 3000U

typedef struct {
    bool is_active;
    uint32_t channel_id;
    uint8_t command;
    uint16_t expected_length;
    uint16_t received_length;

    uint8_t expected_sequence;

    uint32_t last_activity_time_ms;
    uint8_t buffer[CTAPHID_MAX_MESSAGE_SIZE];
} CtaphidReassembler;

typedef enum {
    CTAPHID_REASSEMBLE_COMPLETE = 0,
    CTAPHID_REASSEMBLE_INCOMPLETE,
    CTAPHID_REASSEMBLE_IGNORED,
    CTAPHID_REASSEMBLE_CHANNEL_BUSY,
    CTAPHID_REASSEMBLE_INVALID_SEQUENCE,
    CTAPHID_REASSEMBLE_MESSAGE_TOO_LARGE,
    CTAPHID_REASSEMBLE_NULL_ARGUMENT,
    CTAPHID_REASSEMBLE_INVALID_PACKET
} CtaphidReassembleResult;

/* Initialize before first use. Discards message metadata; buffer contents are
 * invalid after reset and are not erased. Do not modify state fields directly. */
void ctaphid_reassembler_reset(
    CtaphidReassembler *reassembler
);

/* Assemble host-to-authenticator request reports decoded by the parser.
 * Input and state storage must not overlap. INVALID_PACKET leaves state intact.
 * COMPLETE ends assembly and preserves metadata and buffer[0..received_length)
 * until reset or a new accepted initial packet. Consume/copy data before then.
 * Expired partial messages are reset before processing the incoming packet.
 * Time is a monotonic millisecond counter; uint32_t wrap is supported when
 * elapsed intervals are shorter than one counter cycle.
 *
 * This module owns only request assembly. The caller must arbitrate processing
 * and response transmission until the transaction ends, validate allocated CIDs
 * and command-specific lengths, and route CANCEL to a running CBOR operation.
 * CANCEL reaching this module is ignored: no operation is being processed here. */
CtaphidReassembleResult ctaphid_reassemble_packet(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet,
    uint32_t current_time_ms
);

#endif
