#ifndef AUTH_ENTERPRISE_H
#define AUTH_ENTERPRISE_H
#include "authenticator/auth_platform.h"
#define AUTH_ENTERPRISE_MAX_CERTIFICATES 2U
#define AUTH_ENTERPRISE_MAX_CHAIN_BYTES 1024U
#define AUTH_ENTERPRISE_MAX_RPS 8U
/* Optional model/batch identity for ordinary packed full attestation. It must
 * not identify an individual enterprise unit or reuse its certificate/key.
 * sign_digest returns a DER ES256 signature; buffers live for the service lifetime. */
typedef struct {
    void *context;
    AuthStatus (*sign_digest)(void *,const uint8_t[32],uint8_t[72],size_t *);
    const uint8_t *certificates[AUTH_ENTERPRISE_MAX_CERTIFICATES];
    size_t certificate_lengths[AUTH_ENTERPRISE_MAX_CERTIFICATES];
    size_t certificate_count;
} AuthBatchAttestation;
bool auth_batch_valid(const AuthBatchAttestation *);
/* Optional immutable, provisioned identity. No credential private key is used.
 * Caller retains certificate/policy storage for the service lifetime. sign_digest
 * returns a DER ES256 signature using a separately provisioned attestation key.
 * fingerprint binds the leaf identity AND routing policy; enabled consent must
 * be renewed when either changes. Serialized callbacks cannot reenter the core. */
typedef struct {
    void *context;
    AuthStatus (*sign_digest)(void *,const uint8_t[32],uint8_t[72],size_t *);
    const uint8_t *certificates[AUTH_ENTERPRISE_MAX_CERTIFICATES];
    size_t certificate_lengths[AUTH_ENTERPRISE_MAX_CERTIFICATES];
    size_t certificate_count;
    const uint8_t (*rp_hashes)[32];
    size_t rp_count;
    bool platform_managed;
    uint8_t fingerprint[32];
} AuthEnterpriseAttestation;
bool auth_enterprise_valid(const AuthEnterpriseAttestation *);
#endif
