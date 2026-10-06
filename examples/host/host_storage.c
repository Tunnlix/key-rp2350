#include "host_storage.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

/* Private diagnostic IPC only. Credential/key bytes are never included. */
static bool publish_snapshot(const HostStorage *storage)
{
    if (storage->snapshot_path[0] == '\0') return true;
    PcAuthenticatorState state = pc_authenticator_state(storage->authenticator);
    FILE *file = fopen(storage->temporary_path, "w");
    if (file == NULL) return false;
    bool ok = fprintf(file, "{\"generation\":%" PRIu32 ",\"credential_count\":%zu,\"key_count\":%zu,\"device_identifier\":\"",
        state.generation, state.credential_count, state.key_count) > 0;
    for (size_t i = 0; i < 16U; ++i) if (fprintf(file, "%02x", (unsigned int)state.device_identifier[i]) < 0) ok = false;
    if (fputs("\",\"credential_store_state\":\"", file) == EOF) ok = false;
    for (size_t i = 0; i < 16U; ++i) if (fprintf(file, "%02x", (unsigned int)state.credential_store_state[i]) < 0) ok = false;
    if (fputs("\"}\n", file) == EOF) ok = false;
    if (fclose(file) != 0) ok = false;
    if (!ok) return false;
#ifdef _WIN32
    return MoveFileExA(storage->temporary_path, storage->snapshot_path, MOVEFILE_REPLACE_EXISTING) != 0;
#else
    return rename(storage->temporary_path, storage->snapshot_path) == 0;
#endif
}

bool ctaphid_host_storage_init(HostStorage *storage, const char *control_directory,
    const char *storage_directory)
{
    memset(storage, 0, sizeof *storage);
    int directory;
    if (storage_directory != NULL) {
        directory = snprintf(storage->vault_directory, sizeof storage->vault_directory, "%s", storage_directory);
    } else if (control_directory != NULL) {
        directory = snprintf(storage->vault_directory, sizeof storage->vault_directory, "%s/vault", control_directory);
    } else {
#ifdef _WIN32
        char temporary[512], identifier[33];
        uint8_t random[16];
        DWORD count = GetTempPathA(sizeof temporary, temporary);
        if (count == 0U || count >= sizeof temporary || pc_authenticator_random(random, sizeof random) != AUTH_OK) return false;
        for (size_t i = 0; i < 16U; ++i) snprintf(identifier + 2U * i, 3U, "%02x", (unsigned int)random[i]);
        directory = snprintf(storage->vault_directory, sizeof storage->vault_directory, "%sctaphid-vault-%s", temporary, identifier);
        storage->owns_temporary_directory = true;
#else
        return false; /* Current PC provider is Windows-specific; core is portable. */
#endif
    }
    if (directory < 0 || (size_t)directory >= sizeof storage->vault_directory) return false;
#ifdef _WIN32
    if (storage->owns_temporary_directory && !CreateDirectoryA(storage->vault_directory, NULL)) return false;
#endif
    if (control_directory != NULL) {
        int snapshot = snprintf(storage->snapshot_path, sizeof storage->snapshot_path, "%s/factory-state", control_directory);
        int temporary = snprintf(storage->temporary_path, sizeof storage->temporary_path, "%s/factory-state.tmp", control_directory);
        if (snapshot < 0 || (size_t)snapshot >= sizeof storage->snapshot_path ||
            temporary < 0 || (size_t)temporary >= sizeof storage->temporary_path) return false;
    }
    AuthStatus opened = pc_authenticator_open(storage->vault_directory, &storage->authenticator);
    if (opened != AUTH_OK) {
        fprintf(stderr, "Cannot open PC credential vault (status %d)\n", (int)opened);
        ctaphid_host_storage_close(storage);
        return false;
    }
    AuthCrypto crypto = pc_authenticator_crypto(storage->authenticator);
    AuthStorage provider = pc_authenticator_storage(storage->authenticator);
    if (!auth_credentials_init(&storage->credentials, &crypto, &provider) ||
        !publish_snapshot(storage)) { ctaphid_host_storage_close(storage); return false; }
    return true;
}

void ctaphid_host_storage_close(HostStorage *storage)
{
    if (storage == NULL) return;
    pc_authenticator_close(storage->authenticator);
    storage->authenticator = NULL;
#ifdef _WIN32
    if (storage->owns_temporary_directory) {
        char file[1100];
        snprintf(file, sizeof file, "%s/credentials.vault", storage->vault_directory);
        DeleteFileA(file);
        snprintf(file, sizeof file, "%s/credentials.tmp", storage->vault_directory);
        DeleteFileA(file);
        RemoveDirectoryA(storage->vault_directory); /* Only this provider's private temporary directory. */
    }
#endif
}

bool ctaphid_host_storage_reset(void *context)
{
    HostStorage *storage = context;
    if (!pc_authenticator_factory_reset(storage->authenticator)) return false;
    if (!publish_snapshot(storage)) fprintf(stderr, "Reset committed, but diagnostic snapshot publication failed\n");
    PcAuthenticatorState state = pc_authenticator_state(storage->authenticator);
    fprintf(stderr, "PC vault factory reset committed (generation %" PRIu32 ")\n", state.generation);
    return true;
}
