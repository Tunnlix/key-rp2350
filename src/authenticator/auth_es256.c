#include "authenticator/auth_es256.h"
#include <string.h>

static size_t encode_integer(const uint8_t *number, uint8_t *output)
{
    size_t first = 0U;
    while (first < 32U && number[first] == 0U) ++first;
    if (first == 32U) return 0U;
    size_t bytes = 32U - first;
    bool padding = (number[first] & 0x80U) != 0U;
    output[0] = 0x02U;
    output[1] = (uint8_t)(bytes + (padding ? 1U : 0U));
    if (padding) output[2] = 0U;
    memcpy(output + 2U + (padding ? 1U : 0U), number + first, bytes);
    return 2U + bytes + (padding ? 1U : 0U);
}

bool auth_es256_signature_to_der(const uint8_t raw[64], uint8_t *der,
    size_t capacity, size_t *length)
{
    if (raw == NULL || der == NULL || length == NULL) return false;
    uint8_t encoded[72];
    size_t r = encode_integer(raw, encoded + 2U);
    if (r == 0U) return false;
    size_t s = encode_integer(raw + 32U, encoded + 2U + r);
    if (s == 0U || 2U + r + s > capacity) return false;
    encoded[0] = 0x30U;
    encoded[1] = (uint8_t)(r + s);
    memcpy(der, encoded, 2U + r + s);
    *length = 2U + r + s;
    return true;
}
