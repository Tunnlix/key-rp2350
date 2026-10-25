#ifndef AUTH_NONRESIDENT_PROVIDER_H
#define AUTH_NONRESIDENT_PROVIDER_H
#include "authenticator/auth_platform.h"

/* Optional complete group for sealed non-discoverable credentials. No private
 * bytes cross this boundary. IDs are bounded opaque protocol data; metadata's
 * compact credential_id is SHA256(wire ID), not a truncated prefix. Returned
 * records are non-discoverable and RP-bound; counter is the current durable
 * shared value. Provider owns authenticated resolution and opaque key use.
 * create durably reserves issuance before producing an ID; errors never reuse
 * its reserved handle/serial. No resident slot is consumed and failed response
 * preparation need not roll back that reservation. No automatic fallback.
 * read stages at most one encrypted credential context for crypto/extension
 * callbacks; private plaintext must be wiped at each callback exit. release
 * is idempotent RAM-only cleanup with no writes, retries or provider activation.
 * All calls are serialized, non-reentrant and buffers disjoint. */
typedef struct {
    void *context;
    AuthStatus (*create)(void *,const uint8_t rp_hash[32],uint8_t cred_protect,
        AuthCredential *,uint8_t id[AUTH_CREDENTIAL_ID_MAX_SIZE],size_t *id_length,uint8_t public_key[65]);
    AuthStatus (*read)(void *,const uint8_t *,size_t,const uint8_t rp_hash[32],AuthCredential *);
    AuthStatus (*update_counter)(void *,const uint8_t *,size_t,const uint8_t rp_hash[32],uint32_t expected,uint32_t next);
    void (*release)(void *);
} AuthNonresidentProvider;
#endif
