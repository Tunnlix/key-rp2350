#ifndef PC_AUTHENTICATOR_H
#define PC_AUTHENTICATOR_H

#include "authenticator/auth_platform.h"

/* Current PC platform: Windows CNG + user-scoped DPAPI. Credentials and provider
 * private keys persist in a versioned, authenticated encrypted file. Private
 * material never crosses AuthCrypto. This development provider is not a secure
 * element or a protection against whole-file rollback by its owning OS user.
 * Do not copy the provider/file format into RP2350 firmware. */
typedef struct PcAuthenticator PcAuthenticator;

typedef struct {
    size_t credential_count, key_count;
    uint32_t generation;
    uint8_t device_identifier[16], credential_store_state[16];
} PcAuthenticatorState;

/* Caller creates the parent directory. The provider creates directory if needed,
 * exclusively locks this vault, and fails closed on corrupt/undecryptable files.
 * Missing file initializes a new empty vault; existing files are never silently
 * replaced on read error. Failure leaves *output unchanged. */
AuthStatus pc_authenticator_open(const char *directory, PcAuthenticator **output);
AuthStatus pc_authenticator_random(uint8_t *output, size_t length);
void pc_authenticator_close(PcAuthenticator *authenticator);
AuthCrypto pc_authenticator_crypto(PcAuthenticator *authenticator);
AuthStorage pc_authenticator_storage(PcAuthenticator *authenticator);
PcAuthenticatorState pc_authenticator_state(const PcAuthenticator *authenticator);

/* Combined atomic key/metadata reset compatible with CtapResetStorage callback.
 * Rotates identifiers and preserves provider/transport configuration. */
bool pc_authenticator_factory_reset(void *context);

#endif
