#ifndef CTAP_AUTHENTICATOR_CONFIG_H
#define CTAP_AUTHENTICATOR_CONFIG_H
#include "ctap/ctap_client_pin.h"
/* Serialized application context only; never invoke persistence in HID callbacks.
 * No configurable RP disclosure list: maxRPIDsForSetMinPINLength is zero and
 * minPinLength produces no RP output. Configuration follows CTAP §6.11. */
uint8_t ctap_authenticator_config_execute(CtapClientPin *, const uint8_t *, size_t, uint32_t now_ms);
#endif
