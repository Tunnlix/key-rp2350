#include "authenticator/auth_secret_crypto.h"

bool auth_secret_crypto_valid(const AuthSecretCrypto *crypto)
{
    return crypto != NULL && crypto->key_agreement != NULL && crypto->ecdh != NULL &&
        crypto->hmac_sha256 != NULL && crypto->aes256_cbc != NULL &&
        crypto->credential_supported != NULL && crypto->credential_hmac != NULL;
}

void auth_secure_zero(void *buffer, size_t length)
{
    volatile uint8_t *cursor = buffer;
    if (cursor == NULL) return;
    while (length-- != 0U) *cursor++ = 0U;
}
