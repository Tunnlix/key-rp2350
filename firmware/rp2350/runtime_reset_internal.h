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
/* Development runtime binding for native tests and the board application.
 * The caller supplies USB transport and verified physical flash separately.
 * Static, mutually disjoint objects; provider scratch may either be disjoint
 * or exactly workspace->phase.provider (serialized lifecycle sharing).
 * Initialize provider, service,
 * PIN and backend first, then configure this Reset binding BEFORE backend
 * credentials/PIN binding. powered_at_ms is real power-on and is never reset
 * by this module. Configure device start/abort/resync to the adapters below;
 * call runtime_poll outside device callbacks after device_poll. No direct
 * backend_start/poll bypass while locked. Capacity-specific full RAM/stack
 * qualification is required before any target application instantiation.
 * Callback runs only through the core's consumed-operation/fresh-presence
 * authorization. It clears actual tokens, credential scratch, assertions,
 * management snapshots and provider keys/cache, then runs verified persistent
 * Reset and initializes actual service/PIN callbacks on the new empty epoch.
 * Key service enables only after reinitialization; later backend token-renewal
 * or RNG errors revoke the provider and runtime readiness. No automatic repair
 * or recovery authorization. A LOCKED runtime requires separately authorized
 * physical recovery flow; this module does not invent that consent source. */
bool rp2350_runtime_reset_configure_internal(Rp2350RuntimeReset *,Rp2350StoreResetFlowWorkspace *,
    Rp2350StoreProvider *,Rp2350StoreProviderWorkspace *,Rp2350Crypto *,AuthCredentialService *,
    CtapClientPin *,CtaphidCtapBackend *,uint32_t powered_at_ms);
bool rp2350_runtime_ready_internal(const Rp2350RuntimeReset *);
void rp2350_runtime_start_internal(void *,uint64_t,const uint8_t *,size_t);
void rp2350_runtime_abort_internal(void *,uint64_t);
void rp2350_runtime_resync_internal(void *,uint32_t);
CtaphidDeviceResult rp2350_runtime_poll_internal(Rp2350RuntimeReset *,CtaphidDevice *,uint32_t);
#endif
