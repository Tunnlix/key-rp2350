#ifndef CTAP_ATTESTATION_H
#define CTAP_ATTESTATION_H

#include "authenticator/auth_credentials.h"

/* Serialize registration authenticatorData and a CTAP response. UP=1, AT=1,
 * UV=0, signCount=0, EC2/P-256 COSE key. Packed self-attestation signs
 * SHA256(authenticatorData || clientDataHash) with this credential's opaque key.
 * none emits an empty attStmt and zero AAGUID. No certificates or private keys
 * are handled here; the credential has already been authorized and persisted.
 * Failure leaves output/length untouched; caller owns rollback on failure. */
bool ctap_attestation_encode(AuthCredentialService *service,
    const AuthCredential *credential, const uint8_t public_key[65],
    const uint8_t client_data_hash[32], const uint8_t aaguid[16], bool omit,
    uint8_t *output, size_t capacity, size_t *length);

#endif
