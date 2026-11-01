#ifndef RP2350_ENTERPRISE_ATTESTATION_H
#define RP2350_ENTERPRISE_ATTESTATION_H
#include "authenticator/auth_credentials.h"
#include "crypto.h"
/* No identity configured: successful no-op, ordinary passkeys remain available. */
bool rp2350_batch_configure_internal(AuthCredentialService *,Rp2350Crypto *);
bool rp2350_enterprise_configure_internal(AuthCredentialService *,Rp2350Crypto *);
#endif
