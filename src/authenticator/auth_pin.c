#include "authenticator/auth_pin.h"

bool auth_pin_record_valid(const AuthPinRecord *record)
{
    if (record == NULL || record->retries > AUTH_PIN_MAX_RETRIES) return false;
    if (record->set) return record->code_points >= 4U && record->code_points <= 63U;
    if (record->code_points != 0U || record->retries != AUTH_PIN_MAX_RETRIES) return false;
    for (size_t i = 0U; i < sizeof record->hash; ++i) if (record->hash[i] != 0U) return false;
    return true;
}
