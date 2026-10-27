#ifndef CTAP_HMAC_SECRET_H
#define CTAP_HMAC_SECRET_H

#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"
#include "authenticator/auth_credentials.h"

#define CTAP_HMAC_SECRET_MAX_ENCRYPTED_SIZE 80U

/* Only public/ciphertext request data is retained while waiting for UP. */
typedef struct {
    bool requested;
    uint8_t protocol; /* Parsed 1/2; zero retains the former internal protocol-2 default. */
    uint8_t peer_public[65], salt_enc[80], salt_auth[32];
    size_t salt_enc_length, salt_auth_length;
} CtapHmacSecret;

/* Structural validation only. Protocol 1 is the wire default when field 4 is absent.
 * Crypto authentication/decryption/evaluation is deferred until fresh UP. */
uint8_t ctap_hmac_secret_parse(const CborValue *input, CtapHmacSecret *request);

/* After UP, validate encrypted salts before creating/replacing a credential.
 * Transient shared keys and decrypted salts are erased before returning. */
uint8_t ctap_hmac_secret_validate(AuthCredentialService *service, const CtapHmacSecret *request);

/* Caller establishes fresh UP and passes an RP-bound credential. Return the
 * encrypted one/two HMAC outputs, or length=0 for a legacy key without secrets.
 * Failure leaves output/length untouched. Transient Z, shared keys, salts and
 * plaintext HMAC results are cleared on all paths. UV selection is explicit;
 * caller passes true only after successful PIN token authorization. */
uint8_t ctap_hmac_secret_evaluate(AuthCredentialService *service,
    const AuthCredential *credential, const CtapHmacSecret *request, bool user_verified,
    uint8_t output[80], size_t *length);

/* Key-agreement-only adapter for a service without the complete PIN binding.
 * Produces response CBOR without status; full ClientPIN uses ctap_client_pin. */
uint8_t ctap_hmac_secret_key_agreement(AuthCredentialService *service,
    const uint8_t *input, size_t input_length, uint8_t *output, size_t capacity, size_t *length);

#endif
