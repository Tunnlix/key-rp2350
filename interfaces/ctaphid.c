#include "ctaphid.h"
#include <inttypes.h>
#include <stdio.h>
// INITIAL PACKET

// Offset  Size   Field
// 0       4      CID
// 4       1      CMD
// 5       1      BCNTH
// 6       1      BCNTL
// 7       57     DATA

// CONTINUATION PACKET

// Offset  Size   Field
// 0       4      CID
// 4       1      SEQ
// 5       59     DATA
// SEQ
//     bit 7 is 0
//     starts at 0
//     then 1, 2, 3...


// CID
//     4-byte channel ID

// CMD
//     bit 7 is always 1 for an initial packet

// BCNTH + BCNTL
//     total payload length

// payload_length =
//     (BCNTH << 8) | BCNTL

// DATA
//     first part of message payload
void ctaphid_process_packet(uint8_t packet[64]) {
    uint32_t cid =
    ((uint32_t)packet[0] << 24) |
    ((uint32_t)packet[1] << 16) |
    ((uint32_t)packet[2] << 8)  |
    ((uint32_t)packet[3]);
    uint8_t is_initial_packet = (packet[4] >> 7) & 1;

    printf("CID:%" PRIu32 "\n", cid);

    if(is_initial_packet) {
        printf("Initial Packet\n");
        printf("Command: %s\n", ctaphid_command_name(packet[4]));

    } else {
        printf("Continuation Packet\n");
    }
    
}

const char *ctaphid_command_name(uint8_t cmd)
{
     switch (cmd) {
        case 0x81: return "CTAPHID_PING";
        case 0x83: return "CTAPHID_MSG";
        case 0x84: return "CTAPHID_LOCK";
        case 0x86: return "CTAPHID_INIT";
        case 0x88: return "CTAPHID_WINK";
        case 0x90: return "CTAPHID_CBOR";
        case 0x91: return "CTAPHID_CANCEL";
        case 0xBB: return "CTAPHID_KEEPALIVE";
        case 0xBF: return "CTAPHID_ERROR";

        default:   return "CTAPHID_UNKNOWN";
    }
}
