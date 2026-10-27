#include "blob_store.h"
#include "storage_bytes_internal.h"
#include "mbedtls/sha256.h"
#include <string.h>
#define BANK_BYTES 8192U
#define BANK_COUNT 4U
static const uint8_t empty_array[17] = {0x80,0x76,0xbe,0x8b,0x52,0x8d,0x00,0x75,0xf7,0xaa,0xe9,0x8d,0x6f,0xa5,0x7a,0x6d,0x3c};
static const uint8_t magic[8] = {'K','e','y','B','l','o','b',1};

static AuthStatus digest_bank(Rp2350BlobStore *store, uint32_t at, size_t length, uint8_t digest[32])
{
    mbedtls_sha256_context hash; mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0);
    AuthStatus status = AUTH_OK;
    while (status == AUTH_OK && !rc && length) {
        size_t n = length < sizeof store->page ? length : sizeof store->page;
        status = store->flash.read(store->flash.context, at, store->page, n);
        if (status == AUTH_OK) rc = mbedtls_sha256_update(&hash, store->page, n);
        at += (uint32_t)n; length -= n;
    }
    if (status == AUTH_OK && !rc) rc = mbedtls_sha256_finish(&hash, digest);
    mbedtls_sha256_free(&hash);
    return status != AUTH_OK ? status : (rc ? AUTH_CRYPTO_ERROR : AUTH_OK);
}

AuthStatus rp2350_blob_store_open(Rp2350BlobStore *store, const Rp2350Flash *flash, uint64_t epoch, const uint8_t store_id[16])
{
    if (!store || !flash || !flash->read || !flash->program_page || !flash->erase_sector || !epoch || !store_id)
        return AUTH_INVALID_ARGUMENT;
    memset(store, 0, sizeof *store); store->flash = *flash; store->epoch = epoch; memcpy(store->store_id, store_id, 16U);
    store->active_bank = BANK_COUNT; store->length = sizeof empty_array;
    AuthStatus status = AUTH_OK;
    for (uint32_t bank = 0U; bank < BANK_COUNT; ++bank) {
        status = flash->read(flash->context, bank * BANK_BYTES, store->page, 256U);
        if (status != AUTH_OK) break;
        if (memcmp(store->page, magic, sizeof magic) || store_u64(store->page + 8U) != epoch ||
            !store_equal(store->page + 64U, store_id, 16U)) continue;
        uint64_t sequence = store_u64(store->page + 16U);
        uint32_t length = store_u32(store->page + 24U);
        uint8_t expected[32], actual[32];
        memcpy(expected, store->page + 32U, sizeof expected);
        if (!sequence || length < 17U || length > CTAP_LARGE_BLOB_CAPACITY || !store_zero(store->page + 28U, 4U) ||
            !store_zero(store->page + 112U, 144U)) continue;
        if (mbedtls_sha256(store->page, 80U, actual, 0)) { status = AUTH_CRYPTO_ERROR; break; }
        if (!store_equal(actual, store->page + 80U, 32U)) continue;
        status = digest_bank(store, bank * BANK_BYTES + 256U, length, actual);
        if (status != AUTH_OK) break;
        if (!store_equal(expected, actual, sizeof expected)) continue;
        if (sequence == store->sequence) { status = AUTH_BAD_DATA; break; }
        if (sequence > store->sequence) {
            store->sequence = sequence; store->active_bank = bank; store->length = length;
        }
    }
    auth_secure_zero(store->page, sizeof store->page);
    store->initialized = status == AUTH_OK; store->faulted = status != AUTH_OK;
    return status;
}

static AuthStatus read_array(void *context, size_t offset, uint8_t *out, size_t length, size_t *total)
{
    Rp2350BlobStore *store = context;
    if (!store || !store->initialized || store->faulted) return AUTH_IO_ERROR;
    if (!total || (!out && length) || offset > store->length || length > store->length - offset)
        return AUTH_INVALID_ARGUMENT;
    AuthStatus status = AUTH_OK;
    if (length) {
        if (store->active_bank == BANK_COUNT) memcpy(out, empty_array + offset, length);
        else status = store->flash.read(store->flash.context, store->active_bank * BANK_BYTES + 256U + (uint32_t)offset, out, length);
    }
    if (status == AUTH_OK) *total = store->length;
    else { store->faulted = true; if (out) auth_secure_zero(out, length); }
    return status;
}

static AuthStatus commit_array(void *context, const uint8_t *input, size_t length)
{
    Rp2350BlobStore *store = context;
    if (!store || !store->initialized || store->faulted) return AUTH_IO_ERROR;
    if (!input || length < 17U || length > CTAP_LARGE_BLOB_CAPACITY) return AUTH_INVALID_ARGUMENT;
    if (store->sequence == UINT64_MAX) return AUTH_CAPACITY;
    uint8_t digest[32], check[32];
    if (mbedtls_sha256(input, length-16U, digest, 0) || !store_equal(digest, input+length-16U, 16U))
        return AUTH_BAD_DATA;
    if (mbedtls_sha256(input, length, digest, 0)) return AUTH_CRYPTO_ERROR;
    uint32_t bank = store->active_bank == BANK_COUNT ? 0U : (store->active_bank + 1U) % BANK_COUNT;
    uint32_t base = bank * BANK_BYTES;
    AuthStatus status = store->flash.erase_sector(store->flash.context, base);
    if (status == AUTH_OK) status = store->flash.erase_sector(store->flash.context, base+4096U);
    for (size_t offset = 0U; status == AUTH_OK && offset < length; offset += 256U) {
        size_t n = length-offset < 256U ? length-offset : 256U;
        memset(store->page, 0xff, sizeof store->page); memcpy(store->page, input+offset, n);
        status = store->flash.program_page(store->flash.context, base+256U+(uint32_t)offset, store->page);
    }
    if (status == AUTH_OK) status = digest_bank(store, base+256U, length, check);
    if (status == AUTH_OK && !store_equal(digest, check, 32U)) status = AUTH_IO_ERROR;
    if (status == AUTH_OK) {
        memset(store->page, 0, sizeof store->page); memcpy(store->page, magic, sizeof magic);
        store_put64(store->page+8U, store->epoch); store_put64(store->page+16U, store->sequence+1U);
        store_put32(store->page+24U, (uint32_t)length); memcpy(store->page+32U, digest, 32U);
        memcpy(store->page+64U, store->store_id, 16U);
        if (mbedtls_sha256(store->page, 80U, check, 0)) status = AUTH_CRYPTO_ERROR;
        else memcpy(store->page+80U, check, 32U);
        if (status == AUTH_OK) status = store->flash.program_page(store->flash.context, base, store->page);
    }
    if (status == AUTH_OK) {
        status = store->flash.read(store->flash.context, base, store->page, sizeof store->page);
        if (status == AUTH_OK && (memcmp(store->page, magic, sizeof magic) ||
            store_u64(store->page+8U) != store->epoch || store_u64(store->page+16U) != store->sequence+1U ||
            store_u32(store->page+24U) != length || !store_equal(store->page+32U, digest, 32U) ||
            !store_equal(store->page+64U, store->store_id, 16U) || !store_equal(store->page+80U, check, 32U))) status = AUTH_IO_ERROR;
    }
    if (status == AUTH_OK) { store->sequence++; store->active_bank = bank; store->length = length; }
    else store->faulted = true;
    auth_secure_zero(store->page, sizeof store->page);
    auth_secure_zero(digest, sizeof digest); auth_secure_zero(check, sizeof check);
    return status;
}

CtapLargeBlobStorage rp2350_blob_store_interface(Rp2350BlobStore *store)
{ return (CtapLargeBlobStorage){store, read_array, commit_array}; }
