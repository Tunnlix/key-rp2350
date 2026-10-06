#ifndef CTAPHID_HOST_STORAGE_H
#define CTAPHID_HOST_STORAGE_H

#include "pc_authenticator.h"
#include "authenticator/auth_credentials.h"
#include "ctap/ctap_client_pin.h"

/* PC application binding, not embedded storage. Optional --store-dir persists
 * across runs; otherwise a private temporary vault is used for testing. */
typedef struct {
    PcAuthenticator *authenticator;
    AuthCredentialService credentials;
    CtapClientPin pin;
    char vault_directory[1024], snapshot_path[1024], temporary_path[1024];
    bool owns_temporary_directory;
} HostStorage;

bool ctaphid_host_storage_init(HostStorage *storage, const char *control_directory,
    const char *storage_directory);
void ctaphid_host_storage_close(HostStorage *storage);
bool ctaphid_host_storage_reset(void *context);

#endif
