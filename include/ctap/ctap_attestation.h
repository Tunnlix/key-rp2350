#ifndef CTAP_ATTESTATION_H
#define CTAP_ATTESTATION_H

#include "authenticator/auth_credentials.h"

/* Serialize registration authenticatorData and a CTAP response. UP=1, AT=1,
 * UV=user_verified, signCount from credential (zero for new resident keys),
 * EC2/P-256 COSE key. Requested hmac-secret and
 * credProtect and encrypted hmac-secret-mc outputs form a canonical signed
 * extension map and set ED.
 * Omitted extension inputs produce no unsolicited outputs.
 * Packed self-attestation signs
 * SHA256(authenticatorData || clientDataHash) with this credential's opaque key.
 * none emits an empty attStmt and zero AAGUID. No certificates or private keys
 * are handled here; the credential has already been authorized and its key may
 * be staged pending metadata commit. The caller must not publish before commit.
 * Failure leaves output/length untouched; caller owns rollback on failure. */
bool ctap_attestation_encode(AuthCredentialService *service,
    const AuthCredential *credential, const uint8_t public_key[65],
    const uint8_t client_data_hash[32], const uint8_t aaguid[16], bool omit, const bool *hmac_secret,
    bool user_verified, bool cred_protect_requested,
    const uint8_t *hmac_secret_mc, size_t hmac_secret_mc_length,
    uint8_t *output, size_t capacity, size_t *length);

/* Same encoding with an explicit wire ID. Stored metadata retains its compact
 * locator; sealed IDs are opaque bytes owned by the provider, never private
 * material interpreted by this encoder. ID length must be 1..256 bytes. */
bool ctap_attestation_encode_id(AuthCredentialService *service,
    const AuthCredential *credential, const uint8_t *id, size_t id_length,
    const uint8_t public_key[65], const uint8_t client_data_hash[32],
    const uint8_t aaguid[16], bool omit, const bool *hmac_secret,
    bool user_verified, bool cred_protect_requested,
    const uint8_t *hmac_secret_mc, size_t hmac_secret_mc_length,
    uint8_t *output, size_t capacity, size_t *length);

#endif
