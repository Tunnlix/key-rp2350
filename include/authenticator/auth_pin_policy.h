#ifndef AUTH_PIN_POLICY_H
#define AUTH_PIN_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifndef CTAP_PIN_COMPLEXITY
#define CTAP_PIN_COMPLEXITY 1
#endif
#if CTAP_PIN_COMPLEXITY != 0 && CTAP_PIN_COMPLEXITY != 1
#error "CTAP_PIN_COMPLEXITY must be 0 or 1"
#endif
/* Additional checks only; caller validates UTF-8, length and embedded NUL.
 * The input is never modified, stored, logged or sent over a network. */
bool auth_pin_policy_accepts(const uint8_t *pin, size_t length);
#endif
