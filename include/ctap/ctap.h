#ifndef CTAP_H
#define CTAP_H

#include "ctap/ctap_get_info.h"

#define CTAP_COMMAND_GET_INFO 0x04U
#define CTAP_COMMAND_SELECTION 0x0BU
#define CTAP_STATUS_OK 0x00U
#define CTAP_STATUS_INVALID_COMMAND 0x01U
#define CTAP_STATUS_INVALID_LENGTH 0x03U
#define CTAP_STATUS_OTHER 0x7FU
#define CTAP_STATUS_OPERATION_DENIED 0x27U
#define CTAP_STATUS_USER_ACTION_TIMEOUT 0x2FU
#define CTAP_MAX_RESPONSE_SIZE (1U + CTAP_GET_INFO_MAX_CBOR_SIZE)

typedef enum {
    CTAP_EXECUTION_ERROR = 0,
    CTAP_EXECUTION_RESPONSE_READY,
    CTAP_EXECUTION_WAIT_USER_PRESENCE
} CtapExecutionResult;

/* Execute a CTAP command payload and return status byte followed by CBOR data.
 * ERROR is local API failure and leaves output/length unchanged. Protocol errors
 * are RESPONSE_READY with a one-byte error reply. WAIT_USER_PRESENCE validates
 * Selection but leaves output/length unchanged; the backend must collect a fresh
 * event before completing it. Output must not overlap input/profile.
 * No HID, channel, timing, or platform dependencies. GetInfo takes exactly its
 * command byte; trailing data is rejected. Selection also takes no inputs and
 * is supported only with profile.user_presence. Remaining commands are unsupported.
 */
CtapExecutionResult ctap_execute(const CtapGetInfoProfile *profile,
    const uint8_t *request, size_t request_length,
    uint8_t *response, size_t capacity, size_t *response_length);

#endif
