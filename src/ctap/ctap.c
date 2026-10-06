#include "ctap/ctap.h"

#include <string.h>

CtapExecutionResult ctap_execute(const CtapGetInfoProfile *profile,
    const uint8_t *request, size_t request_length,
    uint8_t *response, size_t capacity, size_t *response_length)
{
    if (profile == NULL || profile->max_message_size == 0U || request == NULL ||
        response == NULL || response_length == NULL || capacity == 0U) return CTAP_EXECUTION_ERROR;
    uint8_t encoded[CTAP_MAX_RESPONSE_SIZE];
    size_t length = 1U;
    if (request_length == 0U) encoded[0] = CTAP_STATUS_INVALID_LENGTH;
    else if (request[0] == CTAP_COMMAND_RESET) {
        if (request_length != 1U) encoded[0] = CTAP_STATUS_INVALID_LENGTH;
        else if (!profile->user_presence) encoded[0] = CTAP_STATUS_OPERATION_DENIED;
        else return CTAP_EXECUTION_WAIT_FACTORY_RESET;
    }
    else if (request[0] == CTAP_COMMAND_SELECTION) {
        if (!profile->user_presence) encoded[0] = CTAP_STATUS_INVALID_COMMAND;
        else if (request_length != 1U) encoded[0] = CTAP_STATUS_INVALID_LENGTH;
        else return CTAP_EXECUTION_WAIT_USER_PRESENCE;
    }
    else if (request[0] != CTAP_COMMAND_GET_INFO) encoded[0] = CTAP_STATUS_INVALID_COMMAND;
    else if (request_length != 1U) encoded[0] = CTAP_STATUS_INVALID_LENGTH;
    else {
        size_t info_length;
        encoded[0] = CTAP_STATUS_OK;
        if (!ctap_get_info_encode(profile, encoded + 1U, sizeof encoded - 1U, &info_length)) {
            return CTAP_EXECUTION_ERROR;
        }
        length += info_length;
    }
    if (length > capacity) return CTAP_EXECUTION_ERROR;
    memcpy(response, encoded, length);
    *response_length = length;
    return CTAP_EXECUTION_RESPONSE_READY;
}
