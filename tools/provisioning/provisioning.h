#ifndef RP2350_PROVISIONING_H
#define RP2350_PROVISIONING_H
#include "storage_provider_internal.h"
#include "storage_reset_flow_internal.h"
#include "ctap/ctap_client_pin.h"

/* Explicit one-shot factory setup. All objects are static and disjoint;
 * the caller supplies fresh physical authorization before destructive IO. */
typedef struct {
    Rp2350StoreResetFlow flow;
    Rp2350StoreResetFlowWorkspace reset;
    Rp2350StoreProvider store;
    Rp2350StoreProviderWorkspace store_workspace;
    AuthCredentialService service;
    CtapClientPin pin;
    Rp2350Crypto *crypto;
    Rp2350Flash flash;
    Rp2350StoreBootConfig config;
    AuthCrypto base;
    AuthSecretCrypto primitives;
    Rp2350StoreResetAuthorize authorize;
    void *authorization_context;
    bool attempted;
} Rp2350Provisioning;

AuthStatus rp2350_provisioning_init(Rp2350Provisioning *,const Rp2350Flash *,
    Rp2350Crypto *,Rp2350StoreResetAuthorize,void *);
AuthStatus rp2350_provisioning_run(Rp2350Provisioning *);
void rp2350_provisioning_close(Rp2350Provisioning *);
#endif
