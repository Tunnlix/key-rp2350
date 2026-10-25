#include "authenticator/auth_platform.h"

bool auth_credential_id_length_valid(size_t length)
{
    return length != 0U && length <= AUTH_CREDENTIAL_ID_MAX_SIZE;
}

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
        credential->user_id_length <= AUTH_USER_ID_MAX_SIZE &&
        credential->rp_id_length <= AUTH_RP_ID_MAX_SIZE &&
        credential->rp_name_length <= AUTH_ENTITY_NAME_MAX_SIZE &&
        credential->user_name_length <= AUTH_ENTITY_NAME_MAX_SIZE &&
        credential->user_display_name_length <= AUTH_ENTITY_NAME_MAX_SIZE &&
        auth_text_valid(credential->rp_id, credential->rp_id_length) &&
        auth_text_valid(credential->rp_name, credential->rp_name_length) &&
        auth_text_valid(credential->user_name, credential->user_name_length) &&
        auth_text_valid(credential->user_display_name, credential->user_display_name_length) &&
        credential->cred_protect >= 1U && credential->cred_protect <= 3U &&
        auth_key_handle_valid(&credential->key) &&
        nonzero(credential->credential_id, sizeof credential->credential_id);
}
