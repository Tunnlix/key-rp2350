#include "enterprise_attestation.h"
#include <string.h>
#ifdef RP2350_ENTERPRISE_IDENTITY
#include "enterprise_identity_private.h"
static AuthStatus sign_enterprise(void *ctx,const uint8_t digest[32],uint8_t signature[72],size_t *length) {
    return rp2350_crypto_sign_attestation_internal(ctx,enterprise_scalar,digest,signature,length);
}
#endif
bool rp2350_enterprise_configure_internal(AuthCredentialService *service,Rp2350Crypto *crypto) {
    if(!service || !crypto) return false;
#ifdef RP2350_ENTERPRISE_IDENTITY
    AuthEnterpriseAttestation ep={.context=crypto,.sign_digest=sign_enterprise,
        .certificates={enterprise_certificate},.certificate_lengths={sizeof(enterprise_certificate)},.certificate_count=1U,
        .rp_hashes=enterprise_rps,.rp_count=ENTERPRISE_RP_COUNT,.platform_managed=ENTERPRISE_PLATFORM_MANAGED};
    memcpy(ep.fingerprint,enterprise_fingerprint,32U);
    return auth_credentials_configure_enterprise(service,&ep);
#else
    return true;
#endif
}

#ifdef RP2350_BATCH_IDENTITY
#include "batch_identity_private.h"
static AuthStatus sign_batch(void *ctx,const uint8_t digest[32],uint8_t signature[72],size_t *length) {
    return rp2350_crypto_sign_attestation_internal(ctx,batch_scalar,digest,signature,length);
}
#endif
bool rp2350_batch_configure_internal(AuthCredentialService *service,Rp2350Crypto *crypto) {
    if(!service || !crypto) return false;
#ifdef RP2350_BATCH_IDENTITY
    AuthBatchAttestation batch={.context=crypto,.sign_digest=sign_batch,
        .certificates={batch_certificate},.certificate_lengths={sizeof(batch_certificate)},.certificate_count=1U};
    return auth_credentials_configure_batch(service,&batch);
#else
    return true;
#endif
}
