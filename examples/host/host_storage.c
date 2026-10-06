#include "host_storage.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

static bool random_bytes(uint8_t *output, size_t length)
{
#ifdef _WIN32
    return length <= ULONG_MAX && BCryptGenRandom(NULL, output, (ULONG)length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    FILE *random = fopen("/dev/urandom", "rb");
    if (random == NULL) return false;
    bool ok = fread(output, 1U, length, random) == length;
    if (fclose(random) != 0) ok = false;
    return ok;
#endif
}

/* Private test-only snapshot, never a CTAP response. Publish before committing
 * RAM state so a snapshot/RNG failure cannot produce a successful reset. */
static bool publish_snapshot(const HostStorage *storage)
{
    if (storage->snapshot_path[0] == '\0') return true;
    FILE *file = fopen(storage->temporary_path, "w");
    if (file == NULL) return false;
    bool ok = fprintf(file, "{\"generation\":%" PRIu32 ",\"mock_credential_count\":%" PRIu32
        ",\"mock_pin_set\":%s,\"device_identifier\":\"",
        storage->generation, storage->mock_credential_count, storage->mock_pin_set ? "true" : "false") > 0;
    for (size_t i = 0; i < 16U; ++i) if (fprintf(file, "%02x", (unsigned int)storage->device_identifier[i]) < 0) ok = false;
    if (fputs("\",\"credential_store_state\":\"", file) == EOF) ok = false;
    for (size_t i = 0; i < 16U; ++i) if (fprintf(file, "%02x", (unsigned int)storage->credential_store_state[i]) < 0) ok = false;
    if (fputs("\"}\n", file) == EOF) ok = false;
    if (fclose(file) != 0) ok = false;
    if (!ok) return false;
#ifdef _WIN32
    return MoveFileExA(storage->temporary_path, storage->snapshot_path, MOVEFILE_REPLACE_EXISTING) != 0;
#else
    return rename(storage->temporary_path, storage->snapshot_path) == 0;
#endif
}

bool ctaphid_host_storage_init(HostStorage *storage, const char *control_directory)
{
    memset(storage, 0, sizeof *storage);
    if (control_directory != NULL) {
        int snapshot = snprintf(storage->snapshot_path, sizeof storage->snapshot_path, "%s/factory-state", control_directory);
        int temporary = snprintf(storage->temporary_path, sizeof storage->temporary_path, "%s/factory-state.tmp", control_directory);
        if (snapshot < 0 || (size_t)snapshot >= sizeof storage->snapshot_path ||
            temporary < 0 || (size_t)temporary >= sizeof storage->temporary_path) return false;
    }
    memset(storage->mock_records, 0xA5, sizeof storage->mock_records);
    memset(storage->mock_pin_verifier, 0x5A, sizeof storage->mock_pin_verifier);
    storage->mock_credential_count = 2U;
    storage->mock_pin_set = true;
    if (!random_bytes(storage->device_identifier, sizeof storage->device_identifier) ||
        !random_bytes(storage->credential_store_state, sizeof storage->credential_store_state)) return false;
    return publish_snapshot(storage);
}

bool ctaphid_host_storage_reset(void *context)
{
    HostStorage *storage = context;
    HostStorage next = *storage;
    if (!random_bytes(next.device_identifier, sizeof next.device_identifier) ||
        !random_bytes(next.credential_store_state, sizeof next.credential_store_state)) return false;
    memset(next.mock_records, 0, sizeof next.mock_records);
    memset(next.mock_pin_verifier, 0, sizeof next.mock_pin_verifier);
    next.mock_credential_count = 0U;
    next.mock_pin_set = false;
    ++next.generation;
    if (!publish_snapshot(&next)) return false;
    *storage = next;
    fprintf(stderr, "Mock factory reset committed (generation %" PRIu32 ")\n", storage->generation);
    return true;
}
