#include "ctap/ctap_authenticator_config.h"
#include "ctap/ctap_request.h"
#include "ctap/ctap_pin_protocol.h"
#include <string.h>

uint8_t ctap_authenticator_config_execute(CtapClientPin *pin, const uint8_t *input, size_t length, uint32_t now_ms)
{
    CborValue fields[5] = {{0}};
    bool present[5] = {false};
    uint8_t status = ctap_request_map(input, length, 5U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[1]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[1].major != 0U || (present[2] && fields[2].major != 5U) ||
        (present[3] && fields[3].major != 0U) || (present[4] && fields[4].major != 2U))
        return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (fields[1].value != 2U && fields[1].value != 3U) return CTAP_STATUS_INVALID_PARAMETER;
    bool set;
    status = ctap_client_pin_status(pin, &set);
    if (status != CTAP_STATUS_OK) return status;
    if (set || (pin->always_uv && fields[1].value != 2U)) {
        if (!present[4]) return CTAP_STATUS_PUAT_REQUIRED;
        if (!present[3]) return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[3].value != 1U && fields[3].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
        uint8_t protocol = (uint8_t)fields[3].value;
        if (fields[4].value != ctap_pin_protocol_auth_length(protocol)) return CTAP_STATUS_PIN_AUTH_INVALID;
        /* Authenticate the exact canonical parameter encoding, including its map
         * header; omitted params contribute no bytes. Input is message-bounded. */
        uint8_t message[34U + CTAP_MESSAGE_CAPACITY];
        size_t params = present[2] ? fields[2].encoded_length : 0U;
        if (params > CTAP_MESSAGE_CAPACITY) return CTAP_STATUS_INVALID_LENGTH;
        memset(message, 0xff, 32U); message[32] = 0x0dU; message[33] = (uint8_t)fields[1].value;
        if (params != 0U) memcpy(message + 34U, fields[2].encoded, params);
        status = ctap_client_pin_authorize_permission(pin, protocol, CTAP_PIN_PERMISSION_CONFIG,
            message, 34U + params, fields[4].data, now_ms);
        auth_secure_zero(message, sizeof message);
        if (status != CTAP_STATUS_OK) return status;
    }
    uint8_t minimum = 0U;
    bool force = false;
    if (fields[1].value == 3U && present[2]) {
        CborValue value;
        if (cbor_map_uint(&fields[2], 1U, &value)) {
            if (value.major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            if (value.value < 4U || value.value > 63U) return CTAP_STATUS_PIN_POLICY_VIOLATION;
            minimum = (uint8_t)value.value;
        }
        if (cbor_map_uint(&fields[2], 2U, &value)) {
            if (value.major != 4U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            if (value.value != 0U) return CTAP_STATUS_LIMIT_EXCEEDED;
        }
        if (cbor_map_uint(&fields[2], 3U, &value)) {
            if (value.major != 7U || (value.encoded[0] != 0xf4U && value.encoded[0] != 0xf5U))
                return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            force = value.encoded[0] == 0xf5U;
        }
    }
    return ctap_client_pin_configure(pin, (uint8_t)fields[1].value, minimum, force);
}
