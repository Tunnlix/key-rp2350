#ifndef RP2350_RUNTIME_RESET_INTERNAL_H
#define RP2350_RUNTIME_RESET_INTERNAL_H
#include "storage_reset_flow_internal.h"
#include "storage_provider_internal.h"
#include "protocol/ctaphid_ctap_backend.h"
typedef struct {
    Rp2350StoreResetFlow flow;
    Rp2350StoreResetFlowWorkspace *workspace;
    Rp2350StoreProvider *store;
    Rp2350StoreProviderWorkspace *store_workspace;
    Rp2350Crypto *crypto;
    AuthCredentialService *service;
    CtapClientPin *pin;
    CtaphidCtapBackend *backend;
    Rp2350Flash flash;
    Rp2350StoreBootConfig config;
    uint64_t denied_operation,consumed_operation;
    bool nonresident_enabled;
} Rp2350RuntimeReset;
/* Configure after store/service/PIN initialization, before binding backend
 * credentials/PIN. All calls are serialized; poll runs outside device callbacks.
 * Provider scratch may be exactly workspace->phase.provider; other contexts
 * must be disjoint. powered_at_ms is real power-on, not a USB session timestamp.
 * Reset consumes fresh presence, locks keys, clears session/cache state, commits
 * persistent reset and reinitializes services before enabling key operations.
 * A storage, RNG or subsequent token-renewal failure keeps service locked.
 * Route start/abort/resync through these adapters; never bypass the lock gate. */
bool rp2350_runtime_reset_configure_internal(Rp2350RuntimeReset *,Rp2350StoreResetFlowWorkspace *,
    Rp2350StoreProvider *,Rp2350StoreProviderWorkspace *,Rp2350Crypto *,AuthCredentialService *,
    CtapClientPin *,CtaphidCtapBackend *,uint32_t powered_at_ms);
bool rp2350_runtime_ready_internal(const Rp2350RuntimeReset *);
void rp2350_runtime_start_internal(void *,uint64_t,const uint8_t *,size_t);
void rp2350_runtime_abort_internal(void *,uint64_t);
void rp2350_runtime_resync_internal(void *,uint32_t);
CtaphidDeviceResult rp2350_runtime_poll_internal(Rp2350RuntimeReset *,CtaphidDevice *,uint32_t);
#endif
