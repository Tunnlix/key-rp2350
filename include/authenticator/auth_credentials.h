#ifndef AUTH_CREDENTIALS_H
#define AUTH_CREDENTIALS_H

#include "authenticator/auth_platform.h"
#include "authenticator/auth_secret_crypto.h"

/* Private workspace for resident creation; handles never contain private keys. */
typedef struct {
    AuthCredential created, found;
    AuthKeyHandle old_key;
    uint8_t old_id[32], store_state[16], public_key[65];
} AuthResidentScratch;

/* Pure core composition; no files, OS, heap, or private-key access. Allocate
 * the service in persistent caller-owned RAM, not on a command's stack.
 * Serialize calls and provider callbacks for each instance. Scratch is internal:
 * callers must not use it as API input/output or retain pointers into it. */
typedef struct {
    AuthCrypto crypto; AuthStorage storage; AuthSecretCrypto secrets;
    uint64_t metadata_revision; /* Invalidates enumeration snapshots after mutations. */
    AuthResidentScratch resident_scratch;
    bool resident_busy;
} AuthCredentialService;

bool auth_credentials_init(AuthCredentialService *service,
    const AuthCrypto *crypto, const AuthStorage *storage);

/* Optional provider binding before accepting requests. All callbacks are
 * required together. The provider generates/stores randoms with credential keys;
 * core metadata never contains their bytes. Bind once after service init. */
bool auth_credentials_configure_secrets(AuthCredentialService *service,
    const AuthSecretCrypto *secrets);

/* Store a new non-discoverable credential with a random ID and P-256 key.
 * discoverable must be false; resident creation requires the metadata-aware
 * create_resident APIs below, including atomic overwrite/store-state handling.
 * Output
 * is published only after metadata persistence succeeds. On insert failure the
 * new key is destroyed; cleanup failure returns IO_ERROR and requires provider
 * recovery/garbage collection. No automatic credential overwrites or retries.
 * user_id may be empty (valid in CTAP 2.3); NULL is allowed only with length 0. */
AuthStatus auth_credentials_create(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, AuthCredential *credential, uint8_t public_key[65]);
/* Same atomic creation, with explicit CTAP credential protection policy. The
 * original entry point uses policy 1. Policy is committed with initial metadata. */
AuthStatus auth_credentials_create_protected(AuthCredentialService *service,
    const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_length,
    bool discoverable, uint8_t cred_protect, AuthCredential *credential, uint8_t public_key[65]);
bool auth_credentials_resident_supported(const AuthCredentialService *service);
/* Metadata template contains only RP/user fields and policy. Replaces a
 * discoverable credential for the same RP hash and user ID atomically, retaining
 * the old credential on any pre-commit failure. Cleanup failure returns IO_ERROR.
 * Never publishes a successful CTAP reply on cleanup failure. */
AuthStatus auth_credentials_create_resident(AuthCredentialService *service,
    const AuthCredential *metadata, AuthCredential *credential, uint8_t public_key[65]);
/* Run preparation against the new, provider-owned key BEFORE committing metadata
 * or deleting the old key. The callback must not mutate credential storage and
 * must not publish its response until this function succeeds. A callback failure
 * destroys only the staged key. Callback arguments are borrowed for the call;
 * do not retain them or reenter resident creation on this service. Its workspace
 * is wiped on every completed call. No private-key export is involved. */
typedef AuthStatus (*AuthCredentialPrepare)(void *context, const AuthCredential *credential,
    const uint8_t public_key[65]);
AuthStatus auth_credentials_create_resident_prepared(AuthCredentialService *service,
    const AuthCredential *metadata, AuthCredentialPrepare prepare, void *context,
    AuthCredential *credential, uint8_t public_key[65]);
AuthStatus auth_credentials_enumerate(AuthCredentialService *service, size_t index, AuthCredential *credential);
AuthStatus auth_credentials_update_user(AuthCredentialService *service,
    const AuthCredential *credential);

/* RP binding is checked before returning metadata or signing. This does not
 * establish UP/UV itself: the CTAP handler must authorize the operation. */
AuthStatus auth_credentials_get(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], AuthCredential *credential);
AuthStatus auth_credentials_sign_digest(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], const uint8_t digest[32],
    uint8_t signature[72], size_t *signature_length);

/* Commit the next counter before building/signing authenticatorData. Failures
 * must abort assertion generation. Skipped counters are allowed; wrap is not. */
AuthStatus auth_credentials_next_counter(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32], uint32_t *counter);

/* Erase metadata before destroying its key so failures cannot leave usable
 * credential metadata pointing at a missing/reused key. A deletion failure may
 * leave an unreferenced key; it must not be interpreted as a successful delete. */
AuthStatus auth_credentials_delete(AuthCredentialService *service,
    const uint8_t id[32], const uint8_t rp_hash[32]);

#endif
