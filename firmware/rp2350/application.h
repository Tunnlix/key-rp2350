#ifndef RP2350_APPLICATION_H
#define RP2350_APPLICATION_H
#include "runtime_reset_internal.h"
#include "presence.h"
#include "firmware_update.h"
#include "blob_store.h"
typedef struct {
    void *context;
    uint32_t (*now_ms)(void *);
    bool (*pressed)(void *);
    CtaphidSubmitReport submit;
    CtaphidAbortReport abort;
    bool asynchronous;
    bool usb_transport;
    bool (*cancel_requested)(void *, uint64_t);
} Rp2350ApplicationIo;
typedef struct Rp2350Application {
    Rp2350RuntimeReset runtime;
    Rp2350StoreResetFlowWorkspace reset_workspace;
    Rp2350StoreProvider store;
    AuthCredentialService service;
    CtapClientPin pin;
    CtaphidCtapBackend backend;
    CtaphidDevice device;
    Rp2350Presence presence;
    Rp2350FirmwareUpdate update;
    Rp2350BlobStore blobs;
    Rp2350Crypto *crypto;
    AuthCrypto base;
    AuthSecretCrypto primitives;
    Rp2350ApplicationIo io;
    bool initialized,busy;
} Rp2350Application;
/* Development binding, not production qualification or a USB driver.
 * Zero-initialized static/disjoint application, crypto and verified flash
 * contexts. Caller initializes real entropy/crypto and verifies the flash first.
 * Recover existing authenticated storage only: no factory formatting, implicit
 * physical recovery or diagnostic consent. Preserve actual power-on timestamp.
 * All entry points and IO callbacks serialized on one owner; no reentry. IO
 * clock is monotonic modulo uint32 milliseconds; pressed samples real hardware
 * in normal firmware. Only isolated tests may simulate it. Transport callbacks
 * use the coordinator's copied-report/abort contract.
 * Synchronous provider latency/keepalive responsiveness remains unqualified. */
AuthStatus rp2350_application_init(Rp2350Application *,Rp2350Crypto *,const Rp2350Flash *,
    const Rp2350ApplicationIo *,const uint8_t aaguid[16],uint32_t powered_at_ms);
AuthStatus rp2350_application_configure_blobs(Rp2350Application *,const Rp2350Flash *);
bool rp2350_application_ready(const Rp2350Application *);
CtaphidDeviceResult rp2350_application_receive(Rp2350Application *,const uint8_t *,size_t);
CtaphidDeviceResult rp2350_application_poll(Rp2350Application *);
CtaphidDeviceResult rp2350_application_report_sent(Rp2350Application *,uint64_t,bool);
void rp2350_application_close(Rp2350Application *);
/* Transport has quiesced transfers. Discard USB-session state and touch consent
 * without erasing credentials, reopening flash or restarting the Reset window. */
bool rp2350_application_disconnect(Rp2350Application *);
#endif
