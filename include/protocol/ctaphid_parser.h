#ifndef CTAPHID_PARSER_H
#define CTAPHID_PARSER_H

#include <stdint.h>

#define CTAPHID_MAX_WIRE_MESSAGE_SIZE 7609
#define CTAPHID_REPORT_SIZE 64

#define CTAPHID_INITIAL_PAYLOAD_SIZE 57
#define CTAPHID_CONTINUATION_PAYLOAD_SIZE 59

typedef enum {
    CTAPHID_PARSE_OK,
    CTAPHID_PARSE_INVALID
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
    uint8_t payload_length;
} CtaphidParsedPacket;

/*
 * Decode one complete report. packet must point to CTAPHID_REPORT_SIZE readable
 * bytes; the array parameter does not validate the supplied buffer size.
 * The caller owns both buffers. Neither buffer may overlap the other.
 *
 * command retains the initial-packet marker bit. Continuation packets report
 * the full continuation payload capacity; message_length is zero for them.
 * Only payload[0..payload_length) is written on success. The rest is unchanged.
 * Output may be partially modified on failure and must then be ignored.
 */
CtaphidParseResult ctaphid_parse_packet(
    const uint8_t packet[CTAPHID_REPORT_SIZE],
    CtaphidParsedPacket *parsed_packet
);

#endif
