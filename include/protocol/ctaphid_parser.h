/*
 * CTAPHID USB HID report parser.
 * Reference: FIDO CTAP 2.2 specification, section 11.2 (USB HID).
 * https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid
 * Decodes individual 64-byte initial and continuation reports.
 */

#ifndef CTAPHID_PARSER_H
#define CTAPHID_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "protocol/ctaphid_framing.h"

typedef enum {
    CTAPHID_PARSE_OK = 0,
    CTAPHID_PARSE_NULL_ARGUMENT,
    CTAPHID_PARSE_INVALID_REPORT_LENGTH,
    CTAPHID_PARSE_INVALID_MESSAGE_LENGTH
} CtaphidParseResult;

typedef enum {
    CTAPHID_PACKET_INITIAL,
    CTAPHID_PACKET_CONTINUATION
} CtaphidPacketType;

typedef struct {
    uint32_t channel_id;
    CtaphidPacketType packet_type;
    uint8_t command;
    uint8_t sequence_number;
    uint16_t message_length;
    uint8_t payload[CTAPHID_CONTINUATION_PAYLOAD_SIZE];
    /* Initial: actual data bytes; continuation: all 59 bytes, including padding. */
    uint8_t fragment_length;
} CtaphidParsedPacket;

/*
 * Decode exactly one 64-byte CTAPHID report. Input is not modified. The caller
 * owns both buffers, which must not overlap, and provides packet_length readable
 * input bytes. No allocation, platform I/O or persistent parser state is used.
 *
 * Failure leaves output unchanged. Success initializes every field and zeros
 * unused payload storage. command is the decoded seven-bit value (INIT = 0x06).
 * For an initial report, sequence_number is zero. For a continuation report,
 * command and message_length are zero, and fragment_length includes padding.
 * Report decoding alone cannot determine a continuation's useful data length
 * or establish whether its channel and sequence belong to a valid message.
 * Unknown command values are decoded without executing or rejecting commands.
 */
CtaphidParseResult ctaphid_parse_packet(
    const uint8_t *packet,
    size_t packet_length,
    CtaphidParsedPacket *parsed_packet
);

#endif
