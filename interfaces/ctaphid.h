#ifndef CTAPHID_H
#define CTAPHID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CTAPHID_MAX_WIRE_MESSAGE_SIZE 7609
#define CTAPHID_REPORT_SIZE 64

#define CTAPHID_INIT_MASK 0x80
#define CTAPHID_INITIAL_HEADER_SIZE 7
#define CTAPHID_CONTINUATION_HEADER_SIZE 5

#define CTAPHID_INITIAL_PAYLOAD_SIZE 57
#define CTAPHID_CONTINUATION_PAYLOAD_SIZE 59

#define CTAPHID_CID_OFFSET 0
#define CTAPHID_COMMAND_OR_SEQUENCE_OFFSET 4
#define CTAPHID_BCNTH_OFFSET 5
#define CTAPHID_BCNTL_OFFSET 6
#define CTAPHID_INITIAL_PAYLOAD_OFFSET 7
#define CTAPHID_CONTINUATION_PAYLOAD_OFFSET 5

typedef enum {
    CTAPHID_VALID_PARSE,
    CTAPHID_INVALID_PARSE
} CtaphidParseResult;

typedef enum {
    CTAPHID_PACKET_INITIAL,
    CTAPHID_PACKET_CONTINUATION
} CtaphidPacketType;

typedef struct {
    uint32_t cid;

    CtaphidPacketType packet_type;

    uint8_t command;
    uint8_t sequence;

    uint16_t total_length;

    uint8_t payload[59];
    uint8_t payload_length;
} CtaphidParsedPacket;

CtaphidParseResult ctaphid_process_packet(const uint8_t packet[64], CtaphidParsedPacket *parsed_packet);

#endif