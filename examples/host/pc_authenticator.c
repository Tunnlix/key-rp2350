#include "pc_authenticator.h"
#include "authenticator/auth_es256.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#define PC_CAPACITY 16U
#define PC_PRIVATE_BLOB_SIZE 104U
#define PC_PLAIN_SIZE (40U + PC_CAPACITY * 137U + PC_CAPACITY * 168U)
#define PC_SEALED_MAX 65536U

typedef struct { bool used; AuthKeyHandle handle; uint8_t blob[104]; } PcKey;
typedef struct { bool used; AuthCredential credential; } PcRecord;
typedef struct {
    uint32_t generation;
    uint8_t device_identifier[16], credential_store_state[16];
    PcKey keys[PC_CAPACITY];
    PcRecord records[PC_CAPACITY];
} PcState;

struct PcAuthenticator {
    char file[1024], temporary[1024];
    HANDLE lock;
    BCRYPT_ALG_HANDLE ec, sha;
    PcState state;
    bool faulted;
};

static AuthStatus crypto_random(void *context, uint8_t *output, size_t length)
{
    (void)context;
    if ((output == NULL && length != 0U) || length > ULONG_MAX) return AUTH_INVALID_ARGUMENT;
    if (length == 0U) return AUTH_OK;
    return BCryptGenRandom(NULL, output, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? AUTH_OK : AUTH_CRYPTO_ERROR;
}

AuthStatus pc_authenticator_random(uint8_t *output, size_t length)
{
    return crypto_random(NULL, output, length);
}

static AuthStatus crypto_sha256(void *context, const uint8_t *data, size_t length, uint8_t digest[32])
{
    PcAuthenticator *pc = context;
    if (pc == NULL || digest == NULL || (data == NULL && length != 0U) || length > ULONG_MAX) return AUTH_INVALID_ARGUMENT;
    BCRYPT_HASH_HANDLE hash = NULL;
    uint8_t result[32];
    NTSTATUS status = BCryptCreateHash(pc->sha, &hash, NULL, 0U, NULL, 0U, 0U);
    if (status == 0 && length != 0U) status = BCryptHashData(hash, (PUCHAR)data, (ULONG)length, 0U);
    if (status == 0) status = BCryptFinishHash(hash, result, sizeof result, 0U);
    if (hash != NULL) BCryptDestroyHash(hash);
    if (status != 0) return AUTH_CRYPTO_ERROR;
    memcpy(digest, result, 32U);
    return AUTH_OK;
}

/* Stable explicit big-endian scalar encoding. Never dump native structs. */
static void write_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static uint32_t read_u32(const uint8_t *input)
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) | ((uint32_t)input[2] << 8) | input[3];
}

static void encode_state(const PcState *state, uint8_t plain[PC_PLAIN_SIZE])
{
    uint8_t *cursor = plain;
    memcpy(cursor, "ACP1", 4U); cursor += 4U;
    write_u32(cursor, state->generation); cursor += 4U;
    memcpy(cursor, state->device_identifier, 16U); cursor += 16U;
    memcpy(cursor, state->credential_store_state, 16U); cursor += 16U;
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        const PcKey *key = &state->keys[i];
        *cursor++ = key->used ? 1U : 0U;
        memcpy(cursor, key->handle.bytes, 32U); cursor += 32U;
        memcpy(cursor, key->blob, 104U); cursor += 104U;
    }
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        const PcRecord *record = &state->records[i];
        const AuthCredential *credential = &record->credential;
        *cursor++ = record->used ? 1U : 0U;
        *cursor++ = record->used ? 1U : 0U; /* Format v1 algorithm code: ES256. */
        memcpy(cursor, credential->credential_id, 32U); cursor += 32U;
        memcpy(cursor, credential->rp_id_hash, 32U); cursor += 32U;
        memcpy(cursor, credential->key.bytes, 32U); cursor += 32U;
        *cursor++ = credential->user_id_length;
        memcpy(cursor, credential->user_id, 64U); cursor += 64U;
        write_u32(cursor, credential->signature_count); cursor += 4U;
        *cursor++ = credential->discoverable ? 1U : 0U;
    }
}

static int key_index(const PcState *state, const AuthKeyHandle *handle)
{
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        if (state->keys[i].used && memcmp(state->keys[i].handle.bytes, handle->bytes, 32U) == 0) return (int)i;
    }
    return -1;
}

static int record_index(const PcState *state, const uint8_t id[32])
{
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        if (state->records[i].used && memcmp(state->records[i].credential.credential_id, id, 32U) == 0) return (int)i;
    }
    return -1;
}

static bool decode_state(const uint8_t *plain, size_t length, PcState *state)
{
    if (length != PC_PLAIN_SIZE || memcmp(plain, "ACP1", 4U) != 0) return false;
    memset(state, 0, sizeof *state);
    const uint8_t *cursor = plain + 4U;
    state->generation = read_u32(cursor); cursor += 4U;
    memcpy(state->device_identifier, cursor, 16U); cursor += 16U;
    memcpy(state->credential_store_state, cursor, 16U); cursor += 16U;
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        PcKey *key = &state->keys[i];
        uint8_t used = *cursor++;
        if (used > 1U) return false;
        key->used = used != 0U;
        memcpy(key->handle.bytes, cursor, 32U); cursor += 32U;
        memcpy(key->blob, cursor, 104U); cursor += 104U;
        if (key->used) {
            BCRYPT_ECCKEY_BLOB header;
            memcpy(&header, key->blob, sizeof header);
            if (!auth_key_handle_valid(&key->handle) || header.dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC || header.cbKey != 32U) return false;
            for (size_t j = 0; j < i; ++j) {
                if (state->keys[j].used && memcmp(key->handle.bytes, state->keys[j].handle.bytes, 32U) == 0) return false;
            }
        }
    }
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        PcRecord *record = &state->records[i];
        AuthCredential *credential = &record->credential;
        uint8_t used = *cursor++, algorithm = *cursor++;
        if (used > 1U) return false;
        record->used = used != 0U;
        credential->algorithm = algorithm == 1U ? AUTH_COSE_ALG_ES256 : 0;
        memcpy(credential->credential_id, cursor, 32U); cursor += 32U;
        memcpy(credential->rp_id_hash, cursor, 32U); cursor += 32U;
        memcpy(credential->key.bytes, cursor, 32U); cursor += 32U;
        credential->user_id_length = *cursor++;
        memcpy(credential->user_id, cursor, 64U); cursor += 64U;
        credential->signature_count = read_u32(cursor); cursor += 4U;
        uint8_t discoverable = *cursor++;
        if (discoverable > 1U) return false;
        credential->discoverable = discoverable != 0U;
        if (record->used) {
            if (!auth_credential_valid(credential) || key_index(state, &credential->key) < 0) return false;
            for (size_t j = 0; j < i; ++j) {
                if (state->records[j].used && (memcmp(credential->credential_id,
                    state->records[j].credential.credential_id, 32U) == 0 ||
                    memcmp(credential->key.bytes, state->records[j].credential.key.bytes, 32U) == 0)) return false;
            }
        }
    }
    return true;
}

/* Seal the whole key/metadata snapshot, flush it, then atomically replace the
 * previous file. Live state changes only after the replacement succeeds. */
static AuthStatus commit(PcAuthenticator *pc, const PcState *next)
{
    if (pc->faulted) return AUTH_IO_ERROR;
    uint8_t plain[PC_PLAIN_SIZE];
    encode_state(next, plain);
    DATA_BLOB input = {sizeof plain, plain}, output = {0};
    if (!CryptProtectData(&input, L"CTAPHID PC development vault", NULL, NULL, NULL,
        CRYPTPROTECT_UI_FORBIDDEN, &output)) { SecureZeroMemory(plain, sizeof plain); return AUTH_CRYPTO_ERROR; }
    SecureZeroMemory(plain, sizeof plain);
    if (output.cbData > PC_SEALED_MAX) { LocalFree(output.pbData); return AUTH_CAPACITY; }
    HANDLE file = CreateFileA(pc->temporary, GENERIC_WRITE, 0U, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    AuthStatus result = AUTH_IO_ERROR;
    if (file != INVALID_HANDLE_VALUE) {
        uint8_t header[12];
        memcpy(header, "APCV", 4U); write_u32(header + 4U, 1U); write_u32(header + 8U, output.cbData);
        DWORD written = 0U;
        bool ok = WriteFile(file, header, sizeof header, &written, NULL) && written == sizeof header;
        if (ok) ok = WriteFile(file, output.pbData, output.cbData, &written, NULL) && written == output.cbData;
        if (ok) ok = FlushFileBuffers(file) != 0;
        if (!CloseHandle(file)) ok = false;
        if (ok && MoveFileExA(pc->temporary, pc->file, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            pc->state = *next;
            result = AUTH_OK;
        } else DeleteFileA(pc->temporary);
    }
    LocalFree(output.pbData);
    if (result == AUTH_IO_ERROR) pc->faulted = true;
    return result;
}

static AuthStatus load(PcAuthenticator *pc)
{
    HANDLE file = CreateFileA(pc->file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND ? AUTH_NOT_FOUND : AUTH_IO_ERROR;
    LARGE_INTEGER size;
    DWORD received;
    uint8_t header[12];
    AuthStatus result = AUTH_BAD_DATA;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 12 || size.QuadPart > 12 + PC_SEALED_MAX ||
        !ReadFile(file, header, sizeof header, &received, NULL) || received != sizeof header ||
        memcmp(header, "APCV", 4U) != 0 || read_u32(header + 4U) != 1U) { CloseHandle(file); return result; }
    uint32_t bytes = read_u32(header + 8U);
    if (bytes == 0U || bytes > PC_SEALED_MAX || (uint64_t)size.QuadPart != 12U + bytes) { CloseHandle(file); return result; }
    uint8_t *sealed = malloc(bytes);
    if (sealed == NULL) { CloseHandle(file); return AUTH_CAPACITY; }
    bool read = ReadFile(file, sealed, bytes, &received, NULL) && received == bytes;
    CloseHandle(file);
    DATA_BLOB input = {bytes, sealed}, output = {0};
    if (read && CryptUnprotectData(&input, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        if (decode_state(output.pbData, output.cbData, &pc->state)) result = AUTH_OK;
        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
    }
    free(sealed);
    return result;
}

AuthStatus pc_authenticator_open(const char *directory, PcAuthenticator **output)
{
    if (directory == NULL || directory[0] == '\0' || output == NULL) return AUTH_INVALID_ARGUMENT;
    if (!CreateDirectoryA(directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return AUTH_IO_ERROR;
    DWORD attributes = GetFileAttributesA(directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0U) return AUTH_IO_ERROR;
    PcAuthenticator *pc = calloc(1U, sizeof *pc);
    if (pc == NULL) return AUTH_CAPACITY;
    pc->lock = INVALID_HANDLE_VALUE;
    char lock[1024];
    int a = snprintf(pc->file, sizeof pc->file, "%s/credentials.vault", directory);
    int b = snprintf(pc->temporary, sizeof pc->temporary, "%s/credentials.tmp", directory);
    int c = snprintf(lock, sizeof lock, "%s/vault.lock", directory);
    AuthStatus result = AUTH_INVALID_ARGUMENT;
    if (a < 0 || (size_t)a >= sizeof pc->file || b < 0 || (size_t)b >= sizeof pc->temporary || c < 0 || (size_t)c >= sizeof lock) goto failed;
    pc->lock = CreateFileA(lock, GENERIC_READ | GENERIC_WRITE, 0U, NULL, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (pc->lock == INVALID_HANDLE_VALUE) { result = AUTH_BUSY; goto failed; }
    if (BCryptOpenAlgorithmProvider(&pc->ec, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0U) != 0 ||
        BCryptOpenAlgorithmProvider(&pc->sha, BCRYPT_SHA256_ALGORITHM, NULL, 0U) != 0) { result = AUTH_CRYPTO_ERROR; goto failed; }
    result = load(pc);
    if (result == AUTH_NOT_FOUND) {
        result = crypto_random(pc, pc->state.device_identifier, 16U);
        if (result == AUTH_OK) result = crypto_random(pc, pc->state.credential_store_state, 16U);
        if (result == AUTH_OK) result = commit(pc, &pc->state);
    }
    if (result != AUTH_OK) goto failed;
    *output = pc;
    return AUTH_OK;
failed:
    pc_authenticator_close(pc);
    return result;
}

void pc_authenticator_close(PcAuthenticator *pc)
{
    if (pc == NULL) return;
    if (pc->ec != NULL) BCryptCloseAlgorithmProvider(pc->ec, 0U);
    if (pc->sha != NULL) BCryptCloseAlgorithmProvider(pc->sha, 0U);
    if (pc->lock != INVALID_HANDLE_VALUE) CloseHandle(pc->lock);
    SecureZeroMemory(pc, sizeof *pc);
    free(pc);
}

static AuthStatus import_key(PcAuthenticator *pc, const AuthKeyHandle *handle, BCRYPT_KEY_HANDLE *key)
{
    if (pc == NULL || !auth_key_handle_valid(handle) || key == NULL) return AUTH_INVALID_ARGUMENT;
    if (pc->faulted) return AUTH_IO_ERROR;
    int index = key_index(&pc->state, handle);
    if (index < 0) return AUTH_NOT_FOUND;
    return BCryptImportKeyPair(pc->ec, NULL, BCRYPT_ECCPRIVATE_BLOB, key,
        pc->state.keys[index].blob, 104U, 0U) == 0 ? AUTH_OK : AUTH_CRYPTO_ERROR;
}

static AuthStatus export_public(BCRYPT_KEY_HANDLE key, uint8_t public_key[65])
{
    uint8_t blob[72];
    ULONG count;
    if (BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &count, 0U) != 0 || count != sizeof blob) return AUTH_CRYPTO_ERROR;
    public_key[0] = 0x04U;
    memcpy(public_key + 1U, blob + 8U, 64U);
    return AUTH_OK;
}

static AuthStatus crypto_public(void *context, const AuthKeyHandle *handle, uint8_t output[65])
{
    if (output == NULL) return AUTH_INVALID_ARGUMENT;
    BCRYPT_KEY_HANDLE key = NULL;
    AuthStatus status = import_key(context, handle, &key);
    if (status != AUTH_OK) return status;
    uint8_t result[65];
    status = export_public(key, result);
    BCryptDestroyKey(key);
    if (status == AUTH_OK) memcpy(output, result, 65U);
    return status;
}

static AuthStatus crypto_generate(void *context, AuthKeyHandle *handle, uint8_t output[65])
{
    PcAuthenticator *pc = context;
    if (pc == NULL || handle == NULL || output == NULL) return AUTH_INVALID_ARGUMENT;
    size_t slot = 0U;
    while (slot < PC_CAPACITY && pc->state.keys[slot].used) ++slot;
    if (slot == PC_CAPACITY) return AUTH_CAPACITY;
    PcState next = pc->state;
    PcKey *created = &next.keys[slot];
    bool unique = false;
    for (unsigned attempt = 0; attempt < 8U; ++attempt) {
        if (crypto_random(pc, created->handle.bytes, 32U) != AUTH_OK) { SecureZeroMemory(&next, sizeof next); return AUTH_CRYPTO_ERROR; }
        if (auth_key_handle_valid(&created->handle) && key_index(&pc->state, &created->handle) < 0) { unique = true; break; }
    }
    if (!unique) { SecureZeroMemory(&next, sizeof next); return AUTH_CRYPTO_ERROR; }
    BCRYPT_KEY_HANDLE key = NULL;
    uint8_t public_key[65];
    ULONG count = 0U;
    AuthStatus result = AUTH_CRYPTO_ERROR;
    if (BCryptGenerateKeyPair(pc->ec, &key, 256U, 0U) == 0 && BCryptFinalizeKeyPair(key, 0U) == 0 &&
        export_public(key, public_key) == AUTH_OK &&
        BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, created->blob, sizeof created->blob, &count, 0U) == 0 && count == sizeof created->blob) {
        created->used = true;
        result = commit(pc, &next);
        if (result == AUTH_OK) { *handle = created->handle; memcpy(output, public_key, 65U); }
    }
    if (key != NULL) BCryptDestroyKey(key);
    SecureZeroMemory(&next, sizeof next);
    return result;
}

static AuthStatus crypto_sign(void *context, const AuthKeyHandle *handle, const uint8_t digest[32],
    uint8_t signature[72], size_t *length)
{
    if (digest == NULL || signature == NULL || length == NULL) return AUTH_INVALID_ARGUMENT;
    BCRYPT_KEY_HANDLE key = NULL;
    AuthStatus result = import_key(context, handle, &key);
    if (result != AUTH_OK) return result;
    uint8_t raw[64];
    ULONG count;
    if (BCryptSignHash(key, NULL, (PUCHAR)digest, 32U, raw, sizeof raw, &count, 0U) != 0 || count != sizeof raw ||
        !auth_es256_signature_to_der(raw, signature, 72U, length)) result = AUTH_CRYPTO_ERROR;
    BCryptDestroyKey(key);
    return result;
}

static AuthStatus crypto_destroy(void *context, const AuthKeyHandle *handle)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || !auth_key_handle_valid(handle)) return AUTH_INVALID_ARGUMENT;
    int index = key_index(&pc->state, handle);
    if (index < 0) return AUTH_NOT_FOUND;
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        if (pc->state.records[i].used && memcmp(pc->state.records[i].credential.key.bytes, handle->bytes, 32U) == 0) return AUTH_BUSY;
    }
    PcState next = pc->state;
    SecureZeroMemory(&next.keys[index], sizeof next.keys[index]);
    AuthStatus result = commit(pc, &next);
    SecureZeroMemory(&next, sizeof next);
    return result;
}

AuthCrypto pc_authenticator_crypto(PcAuthenticator *pc)
{
    AuthCrypto crypto = {pc, crypto_random, crypto_sha256, crypto_generate, crypto_public, crypto_sign, crypto_destroy};
    return crypto;
}

static AuthStatus storage_read(void *context, const uint8_t id[32], AuthCredential *output)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || id == NULL || output == NULL) return AUTH_INVALID_ARGUMENT;
    if (pc->faulted) return AUTH_IO_ERROR;
    int index = record_index(&pc->state, id);
    if (index < 0) return AUTH_NOT_FOUND;
    *output = pc->state.records[index].credential;
    return AUTH_OK;
}

static AuthStatus storage_insert(void *context, const AuthCredential *credential)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || !auth_credential_valid(credential)) return AUTH_INVALID_ARGUMENT;
    if (record_index(&pc->state, credential->credential_id) >= 0) return AUTH_ALREADY_EXISTS;
    if (key_index(&pc->state, &credential->key) < 0) return AUTH_NOT_FOUND;
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        if (pc->state.records[i].used && memcmp(pc->state.records[i].credential.key.bytes,
            credential->key.bytes, 32U) == 0) return AUTH_ALREADY_EXISTS;
    }
    size_t slot = 0U;
    while (slot < PC_CAPACITY && pc->state.records[slot].used) ++slot;
    if (slot == PC_CAPACITY) return AUTH_CAPACITY;
    PcState next = pc->state;
    next.records[slot].used = true;
    next.records[slot].credential = *credential;
    memset(next.records[slot].credential.user_id + credential->user_id_length, 0,
        AUTH_USER_ID_MAX_SIZE - credential->user_id_length);
    AuthStatus result = commit(pc, &next);
    SecureZeroMemory(&next, sizeof next);
    return result;
}

static AuthStatus storage_erase(void *context, const uint8_t id[32])
{
    PcAuthenticator *pc = context;
    if (pc == NULL || id == NULL) return AUTH_INVALID_ARGUMENT;
    int index = record_index(&pc->state, id);
    if (index < 0) return AUTH_NOT_FOUND;
    PcState next = pc->state;
    memset(&next.records[index], 0, sizeof next.records[index]);
    AuthStatus result = commit(pc, &next);
    SecureZeroMemory(&next, sizeof next);
    return result;
}

static AuthStatus storage_find_rp(void *context, const uint8_t rp_hash[32], bool discoverable_only,
    size_t index, AuthCredential *output)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || rp_hash == NULL || output == NULL) return AUTH_INVALID_ARGUMENT;
    if (pc->faulted) return AUTH_IO_ERROR;
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        const PcRecord *record = &pc->state.records[i];
        if (record->used && memcmp(record->credential.rp_id_hash, rp_hash, 32U) == 0 &&
            (!discoverable_only || record->credential.discoverable)) {
            if (index-- == 0U) { *output = record->credential; return AUTH_OK; }
        }
    }
    return AUTH_NOT_FOUND;
}

static AuthStatus storage_count(void *context, size_t *count)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || count == NULL) return AUTH_INVALID_ARGUMENT;
    if (pc->faulted) return AUTH_IO_ERROR;
    size_t total = 0U;
    for (size_t i = 0; i < PC_CAPACITY; ++i) if (pc->state.records[i].used) ++total;
    *count = total;
    return AUTH_OK;
}

static AuthStatus storage_update_counter(void *context, const uint8_t id[32], uint32_t expected, uint32_t next_counter)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || id == NULL || expected == UINT32_MAX || next_counter != expected + 1U) return AUTH_INVALID_ARGUMENT;
    int index = record_index(&pc->state, id);
    if (index < 0) return AUTH_NOT_FOUND;
    if (pc->state.records[index].credential.signature_count != expected) return AUTH_BUSY;
    PcState next = pc->state;
    next.records[index].credential.signature_count = next_counter;
    AuthStatus result = commit(pc, &next);
    SecureZeroMemory(&next, sizeof next);
    return result;
}

AuthStorage pc_authenticator_storage(PcAuthenticator *pc)
{
    AuthStorage storage = {pc, PC_CAPACITY, storage_read, storage_insert, storage_erase,
        storage_find_rp, storage_count, storage_update_counter};
    return storage;
}

PcAuthenticatorState pc_authenticator_state(const PcAuthenticator *pc)
{
    PcAuthenticatorState result = {0};
    if (pc == NULL) return result;
    result.generation = pc->state.generation;
    memcpy(result.device_identifier, pc->state.device_identifier, 16U);
    memcpy(result.credential_store_state, pc->state.credential_store_state, 16U);
    for (size_t i = 0; i < PC_CAPACITY; ++i) {
        if (pc->state.keys[i].used) ++result.key_count;
        if (pc->state.records[i].used) ++result.credential_count;
    }
    return result;
}

bool pc_authenticator_factory_reset(void *context)
{
    PcAuthenticator *pc = context;
    if (pc == NULL || pc->state.generation == UINT32_MAX) return false;
    PcState next = {0};
    next.generation = pc->state.generation + 1U;
    if (crypto_random(pc, next.device_identifier, 16U) != AUTH_OK ||
        crypto_random(pc, next.credential_store_state, 16U) != AUTH_OK) return false;
    AuthStatus result = commit(pc, &next);
    SecureZeroMemory(&next, sizeof next);
    return result == AUTH_OK;
}

#else
/* Additional PC OS providers are separate implementations, never crypto stubs. */
AuthStatus pc_authenticator_open(const char *directory, PcAuthenticator **output)
{ (void)directory; (void)output; return AUTH_UNSUPPORTED; }
AuthStatus pc_authenticator_random(uint8_t *output, size_t length)
{ (void)output; (void)length; return AUTH_UNSUPPORTED; }
void pc_authenticator_close(PcAuthenticator *pc) { (void)pc; }
AuthCrypto pc_authenticator_crypto(PcAuthenticator *pc) { (void)pc; AuthCrypto value = {0}; return value; }
AuthStorage pc_authenticator_storage(PcAuthenticator *pc) { (void)pc; AuthStorage value = {0}; return value; }
PcAuthenticatorState pc_authenticator_state(const PcAuthenticator *pc) { (void)pc; PcAuthenticatorState value = {0}; return value; }
bool pc_authenticator_factory_reset(void *pc) { (void)pc; return false; }
#endif
