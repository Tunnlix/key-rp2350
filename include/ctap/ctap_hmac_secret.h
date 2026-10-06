#ifndef CTAP_HMAC_SECRET_H
#define CTAP_HMAC_SECRET_H

#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"
#include "authenticator/auth_credentials.h"

#define CTAP_HMAC_SECRET_MAX_ENCRYPTED_SIZE 80U

/* Only public/ciphertext request data is retained while waiting for UP. */
typedef struct {
    bool requested;
    uint8_t peer_public[65], salt_enc[80], salt_auth[32];
    size_t salt_enc_length, salt_auth_length;
} CtapHmacSecret;

/* Structural validation only. Supports protocol 2 (explicit field 4 required).
 * Crypto authentication/decryption/evaluation is deferred until fresh UP. */
uint8_t ctap_hmac_secret_parse(const CborValue *input, CtapHmacSecret *request);

/* Caller establishes fresh UP and passes an RP-bound credential. Return the
 * encrypted one/two HMAC outputs, or length=0 for a legacy key without secrets.
 * Failure leaves output/length untouched. Transient Z, shared keys, salts and
 * plaintext HMAC results are cleared on all paths. UV selection is explicit;
 * current authenticator always passes false because it has no UV provider. */
uint8_t ctap_hmac_secret_evaluate(AuthCredentialService *service,
    const AuthCredential *credential, const CtapHmacSecret *request, bool user_verified,
    uint8_t output[80], size_t *length);

/* Minimal ClientPIN support for hmac-secret: protocol 2 getKeyAgreement only.
 * Produces response CBOR without status. No PIN/token/UV features are enabled. */
uint8_t ctap_hmac_secret_key_agreement(AuthCredentialService *service,
    const uint8_t *input, size_t input_length, uint8_t *output, size_t capacity, size_t *length);

#endif
