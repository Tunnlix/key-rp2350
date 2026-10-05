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
    CTAPHID_REASSEMBLE_NULL_ARGUMENT
} CtaphidReassembleResult;

void ctaphid_reassembler_reset(
    CtaphidReassembler *reassembler
);

CtaphidReassembleResult ctaphid_reassemble_packet(
    CtaphidReassembler *reassembler,
    const CtaphidParsedPacket *packet,
    uint32_t current_time_ms
);

#endif