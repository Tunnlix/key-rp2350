#include "authenticator/auth_pin_policy.h"
#include <string.h>

#if CTAP_PIN_COMPLEXITY
/* Project-maintained whole-value blocklist, MIT licensed with this file.
 * Auditable policy choices informed by NIST SP 800-63B-4 section 3.2.10;
 * NIST does not prescribe this list. ASCII matching is case-insensitive;
 * Unicode is compared exactly. Never trim or normalize the actual PIN. */
static const char *const blocked[] = {
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "654321", "123123", "123321", "112233", "121212", "159753",
    "123654", "qwerty", "qwerty123", "password", "password1",
    "abc123", "iloveyou", "letmein", "welcome", "admin123"
};
#endif

bool auth_pin_policy_accepts(const uint8_t *pin, size_t length)
{
    if (pin == NULL || length == 0U || length > 63U) return false;
#if CTAP_PIN_COMPLEXITY
    size_t width = 1U;
    while (width < length && (pin[width] & 0xc0U) == 0x80U) ++width;
    bool repeated = length % width == 0U;
    for (size_t i = width; i < length; ++i)
        if (pin[i] != pin[i % width]) repeated = false;
    if (repeated) return false;
    for (size_t i = 0U; i < sizeof blocked / sizeof blocked[0]; ++i) {
        if (strlen(blocked[i]) != length) continue;
        bool match = true;
        for (size_t j = 0U; j < length; ++j) {
            uint8_t c = pin[j];
            if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + ('a' - 'A'));
            if (c != (uint8_t)blocked[i][j]) match = false;
        }
        if (match) return false;
    }
#endif
    return true;
}
