#ifndef CTAP_H
#define CTAP_H

#include "ctap/ctap_get_info.h"
#include "ctap_config.h"

#define CTAP_COMMAND_MAKE_CREDENTIAL 0x01U
#define CTAP_COMMAND_GET_ASSERTION 0x02U
#define CTAP_COMMAND_GET_INFO 0x04U
#define CTAP_COMMAND_CLIENT_PIN 0x06U
#define CTAP_COMMAND_RESET 0x07U
#define CTAP_COMMAND_SELECTION 0x0BU
#define CTAP_COMMAND_GET_NEXT_ASSERTION 0x08U
#define CTAP_COMMAND_CREDENTIAL_MANAGEMENT 0x0AU
#define CTAP_COMMAND_LARGE_BLOBS 0x0CU
#define CTAP_COMMAND_AUTHENTICATOR_CONFIG 0x0DU
#define CTAP_STATUS_OK 0x00U
#define CTAP_STATUS_INVALID_COMMAND 0x01U
#define CTAP_STATUS_INVALID_PARAMETER 0x02U
#define CTAP_STATUS_INVALID_LENGTH 0x03U
#define CTAP_STATUS_INVALID_SEQUENCE 0x04U
#define CTAP_STATUS_CBOR_UNEXPECTED_TYPE 0x11U
#define CTAP_STATUS_INVALID_CBOR 0x12U
#define CTAP_STATUS_MISSING_PARAMETER 0x14U
#define CTAP_STATUS_LIMIT_EXCEEDED 0x15U
#define CTAP_STATUS_LARGE_BLOB_STORAGE_FULL 0x18U
#define CTAP_STATUS_CREDENTIAL_EXCLUDED 0x19U
#define CTAP_STATUS_UNSUPPORTED_ALGORITHM 0x26U
#define CTAP_STATUS_KEY_STORE_FULL 0x28U
#define CTAP_STATUS_UNSUPPORTED_OPTION 0x2BU
#define CTAP_STATUS_INVALID_OPTION 0x2CU
#define CTAP_STATUS_NO_CREDENTIALS 0x2EU
#define CTAP_STATUS_OTHER 0x7FU
#define CTAP_STATUS_OPERATION_DENIED 0x27U
#define CTAP_STATUS_USER_ACTION_TIMEOUT 0x2FU
#define CTAP_STATUS_NOT_ALLOWED 0x30U
#define CTAP_STATUS_PIN_INVALID 0x31U
#define CTAP_STATUS_PIN_BLOCKED 0x32U
#define CTAP_STATUS_PIN_AUTH_INVALID 0x33U
#define CTAP_STATUS_PIN_AUTH_BLOCKED 0x34U
#define CTAP_STATUS_PIN_NOT_SET 0x35U
#define CTAP_STATUS_PUAT_REQUIRED 0x36U
#define CTAP_STATUS_PIN_POLICY_VIOLATION 0x37U
#define CTAP_STATUS_INTEGRITY_FAILURE 0x3DU
#define CTAP_STATUS_INVALID_SUBCOMMAND 0x3EU
#define CTAP_STATUS_UNAUTHORIZED_PERMISSION 0x40U
#define CTAP_MAX_RESPONSE_SIZE CTAP_MESSAGE_CAPACITY

typedef enum {
    CTAP_EXECUTION_ERROR = 0,
    CTAP_EXECUTION_RESPONSE_READY,
    CTAP_EXECUTION_WAIT_USER_PRESENCE,
    CTAP_EXECUTION_WAIT_FACTORY_RESET
} CtapExecutionResult;

/* Execute a CTAP command payload and return status byte followed by CBOR data.
 * ERROR is local API failure and leaves output/length unchanged. Protocol errors
 * are RESPONSE_READY with a one-byte error reply. WAIT_USER_PRESENCE validates
 * Selection but leaves output/length unchanged; the backend must collect a fresh
 * event before completing it. WAIT_FACTORY_RESET additionally requires the reset
 * policy/storage callback. Neither waiting result modifies output/length.
 * Output must not overlap input/profile.
 * No HID, channel, timing, or platform dependencies. GetInfo takes exactly its
 * command byte; trailing data is rejected. Selection also takes no inputs and
 * is supported only with profile.user_presence. Reset also takes no inputs and
 * returns OPERATION_DENIED when user interaction cannot be collected. Remaining
 * commands are unsupported by this stateless entry point. MakeCredential and
 * GetAssertion use their prepare/finish handlers with the bound credential service.
 * ClientPIN is routed by the backend's optional secret/PIN providers.
 */
CtapExecutionResult ctap_execute(const CtapGetInfoProfile *profile,
    const uint8_t *request, size_t request_length,
    uint8_t *response, size_t capacity, size_t *response_length);

#endif
