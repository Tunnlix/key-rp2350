#ifndef CTAPHID_FRAMING_H
#define CTAPHID_FRAMING_H

/* Shared wire limits for the 64-byte HID report format. These describe framing,
 * independent of command behavior and the reassembler's storage capacity. */
#define CTAPHID_REPORT_SIZE 64U
#define CTAPHID_INITIAL_PAYLOAD_SIZE 57U
#define CTAPHID_CONTINUATION_PAYLOAD_SIZE 59U
#define CTAPHID_MAX_WIRE_MESSAGE_SIZE 7609U

#endif
