#ifndef AUTH_TEST_PROVIDER_H
#define AUTH_TEST_PROVIDER_H

#include <assert.h>
#include <string.h>
#include "authenticator/auth_credentials.h"

/* These mocks test policy/ownership and rollback, not elliptic-curve math.
 * Python integration independently verifies real Windows-provider signatures. */
typedef struct {
    AuthCredential record;
    bool exists, sign_fails, generate_fails, insert_fails, hash_fails, erase_fails;
    bool read_fails, counter_fails;
    size_t generated, destroyed, signatures;
    size_t hashed_length;
    uint8_t hashed_data[196];
    uint32_t counter_at_sign;
} Store;
static AuthStatus random_bytes(void *ctx, uint8_t *out, size_t len)
{ (void)ctx; memset(out, 0xA5, len); return AUTH_OK; }
static AuthStatus hash(void *ctx, const uint8_t *in, size_t len, uint8_t out[32])
{
    Store *store = ctx;
    assert(len <= sizeof store->hashed_data);
    store->hashed_length = len;
    if (len != 0U) memcpy(store->hashed_data, in, len);
    if (store->hash_fails) return AUTH_CRYPTO_ERROR;
    memset(out, 0x42, 32U); return AUTH_OK;
}
static AuthStatus generate(void *ctx, AuthKeyHandle *key, uint8_t out[65])
{
    Store *store = ctx;
    ++store->generated;
    if (store->generate_fails) return AUTH_CRYPTO_ERROR;
    memset(key->bytes, 1, 32U); memset(out, 2, 65U); out[0] = 4U; return AUTH_OK;
}
static AuthStatus public_key(void *ctx, const AuthKeyHandle *key, uint8_t out[65])
{ (void)ctx; (void)key; memset(out, 2, 65U); out[0] = 4U; return AUTH_OK; }
static AuthStatus sign(void *ctx, const AuthKeyHandle *key, const uint8_t digest[32], uint8_t out[72], size_t *len)
{
    Store *store = ctx;
    (void)key; (void)digest; ++store->signatures;
    store->counter_at_sign = store->record.signature_count;
    if (store->sign_fails) return AUTH_CRYPTO_ERROR;
    const uint8_t der[] = {0x30, 6, 2, 1, 1, 2, 1, 1};
    memcpy(out, der, sizeof der); *len = sizeof der; return AUTH_OK;
}
static AuthStatus destroy(void *ctx, const AuthKeyHandle *key)
{ Store *store = ctx; (void)key; assert(!store->exists); ++store->destroyed; return AUTH_OK; }
static AuthStatus read_record(void *ctx, const uint8_t id[32], AuthCredential *out)
{
    Store *store = ctx;
    if (store->read_fails) return AUTH_IO_ERROR;
    if (!store->exists || memcmp(id, store->record.credential_id, 32U) != 0) return AUTH_NOT_FOUND;
    *out = store->record; return AUTH_OK;
}
static AuthStatus insert(void *ctx, const AuthCredential *record)
{
    Store *store = ctx;
    if (store->insert_fails) return AUTH_IO_ERROR;
    store->record = *record; store->exists = true; return AUTH_OK;
}
static AuthStatus erase(void *ctx, const uint8_t id[32])
{
    Store *store = ctx; (void)id;
    if (store->erase_fails) return AUTH_IO_ERROR;
    store->exists = false; return AUTH_OK;
}
static AuthStatus find(void *ctx, const uint8_t rp[32], bool discoverable, size_t index, AuthCredential *out)
{ (void)ctx; (void)rp; (void)discoverable; (void)index; (void)out; return AUTH_NOT_FOUND; }
static AuthStatus count(void *ctx, size_t *out)
{ Store *store = ctx; *out = store->exists ? 1U : 0U; return AUTH_OK; }
static AuthStatus counter(void *ctx, const uint8_t id[32], uint32_t old, uint32_t next)
{
    Store *store = ctx;
    if (store->counter_fails) return AUTH_IO_ERROR;
    if (!store->exists || memcmp(id, store->record.credential_id, 32U) != 0) return AUTH_NOT_FOUND;
    if (old != store->record.signature_count || old == UINT32_MAX || next != old + 1U) return AUTH_BAD_DATA;
    store->record.signature_count = next;
    return AUTH_OK;
}
static void service_init(AuthCredentialService *service, Store *store)
{
    AuthCrypto crypto = {store, random_bytes, hash, generate, public_key, sign, destroy};
    AuthStorage storage = {store, 1U, read_record, insert, erase, find, count, counter};
    assert(auth_credentials_init(service, &crypto, &storage));
}

#endif
