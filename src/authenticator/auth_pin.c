#include "authenticator/auth_pin.h"
#include <string.h>

bool auth_pin_record_valid(const AuthPinRecord *record)
{
    if (record == NULL || record->retries > AUTH_PIN_MAX_RETRIES ||
        (record->pin_complexity && !record->policy_initialized) ||
        (record->policy_initialized && record->legacy_pin_complexity) ||
        (record->min_length != 0U && (record->min_length < 4U || record->min_length > 63U)) ||
        (record->force_change && !record->set) || record->min_length_rp_count > AUTH_PIN_MAX_RP_IDS) return false;
    uint8_t enterprise_nonzero = 0U;
    for (size_t i = 0U; i < 32U; ++i) enterprise_nonzero |= record->enterprise_fingerprint[i];
    if (record->enterprise_enabled != (enterprise_nonzero != 0U)) return false;
    uint8_t token_nonzero = 0U;
    for (size_t i = 0U; i < 32U; ++i) token_nonzero |= record->persistent_token[i];
    if (record->persistent_token_present ? !token_nonzero : token_nonzero != 0U) return false;
    if (record->persistent_readonly && (!record->set || !record->persistent_token_present || record->force_change)) return false;
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
