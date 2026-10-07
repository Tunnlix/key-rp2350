#include "authenticator/auth_platform.h"

bool auth_text_valid(const uint8_t *data, size_t length)
{
    if (data == NULL && length != 0U) return false;
    for (size_t i = 0; i < length;) {
        uint8_t first = data[i++];
        if (first < 0x80U) continue;
        unsigned extra;
        uint32_t code, minimum;
        if (first >= 0xC2U && first <= 0xDFU) { extra = 1U; code = first & 31U; minimum = 0x80U; }
        else if (first >= 0xE0U && first <= 0xEFU) { extra = 2U; code = first & 15U; minimum = 0x800U; }
        else if (first >= 0xF0U && first <= 0xF4U) { extra = 3U; code = first & 7U; minimum = 0x10000U; }
        else return false;
        if (extra > length - i) return false;
        while (extra-- != 0U) {
            uint8_t next = data[i++];
            if ((next & 0xC0U) != 0x80U) return false;
            code = (code << 6) | (next & 63U);
        }
        if (code < minimum || code > 0x10FFFFU || (code >= 0xD800U && code <= 0xDFFFU)) return false;
    }
    return true;
}

