#include "authenticator/auth_platform.h"

static bool nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0U;
    for (size_t i = 0; i < length; ++i) combined |= bytes[i];
    return combined != 0U;
}

bool auth_key_handle_valid(const AuthKeyHandle *key)
{
    return key != NULL && nonzero(key->bytes, sizeof key->bytes);
}

bool auth_credential_valid(const AuthCredential *credential)
{
    return credential != NULL && credential->algorithm == AUTH_COSE_ALG_ES256 &&
        credential->user_id_length > 0U && credential->user_id_length <= AUTH_USER_ID_MAX_SIZE &&
        auth_key_handle_valid(&credential->key) &&
        nonzero(credential->credential_id, sizeof credential->credential_id);
}
