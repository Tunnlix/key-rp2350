#include "authenticator/auth_pin.h"
#include <string.h>

bool auth_pin_record_valid(const AuthPinRecord *record)
{
    if (record == NULL || record->retries > AUTH_PIN_MAX_RETRIES ||
        (record->min_length != 0U && (record->min_length < 4U || record->min_length > 63U)) ||
        (record->force_change && !record->set) || record->min_length_rp_count > AUTH_PIN_MAX_RP_IDS) return false;
    for (size_t i = 0U; i < AUTH_PIN_MAX_RP_IDS; ++i) {
        if (i >= record->min_length_rp_count) {
            for (size_t j = 0U; j < 32U; ++j)
                if (record->min_length_rp_hashes[i][j] != 0U) return false;
        } else for (size_t j = 0U; j < i; ++j)
            if (memcmp(record->min_length_rp_hashes[i], record->min_length_rp_hashes[j], 32U) == 0) return false;
    }
    if (record->set) return record->code_points >= 4U && record->code_points <= 63U;
    if (record->code_points != 0U || record->retries != AUTH_PIN_MAX_RETRIES) return false;
    for (size_t i = 0U; i < sizeof record->hash; ++i) if (record->hash[i] != 0U) return false;
    return true;
}
