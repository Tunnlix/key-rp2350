#ifndef RP2350_NONRESIDENT_SEAL_INTERNAL_H
#define RP2350_NONRESIDENT_SEAL_INTERNAL_H
#include "storage_key_record_internal.h"

#define RP2350_NONRESIDENT_ID_SIZE 256U
#define RP2350_NONRESIDENT_ISSUANCE_LIMIT UINT64_C(16777216)
typedef struct {
    AuthCrypto crypto;
    AuthSecretCrypto secrets;
    uint8_t epoch[16],enc[32],mac[32];
    bool initialized,busy;
} Rp2350NonresidentSeal;
typedef struct {
    uint8_t wire[256],plain[176],tag[32],chain[16],next[16];
} Rp2350NonresidentWorkspace;
/* MUST durably reserve a fresh serial in [1, limit) before returning OK.
 * Never reuse a serial after interruption, even if no ID was published. Caller
 * owns serialized authenticated storage, root lifecycle and rollback limits.
 * This codec supplies no flash writer/reservation implementation itself. */
typedef AuthStatus (*Rp2350NonresidentReserve)(void *,uint64_t *);
/* Provider-private only: key/scalar/random bytes must never cross into core.
 * State starts zero-initialized. Objects/buffers are disjoint and caller-owned;
 * all calls serialized. HKDF
 * SHA-256 domains differ from storage encryption. Init consumes a trusted root
 * and epoch, not caller/website data. No key activation or root provisioning. */
AuthStatus rp2350_nonresident_seal_init_internal(Rp2350NonresidentSeal *,
    const AuthCrypto *,const AuthSecretCrypto *,const uint8_t root[32],const uint8_t epoch[16]);
void rp2350_nonresident_seal_close_internal(Rp2350NonresidentSeal *);
AuthStatus rp2350_nonresident_seal_create_internal(Rp2350NonresidentSeal *,
    const Rp2350Key *,const uint8_t rp_hash[32],uint8_t cred_protect,
    Rp2350NonresidentReserve,void *,uint8_t out[256],Rp2350NonresidentWorkspace *);
/* Unknown/tampered/wrong-RP/old-epoch IDs return NOT_FOUND without decryption
 * before full MAC validation. Operational primitive failures return an error
 * and clear sealing keys. On success the decoded key remains INACTIVE: owner
 * must recompute/validate its public point privately before use, and wipe this
 * record after each callback. All failed outputs and acquired scratch cleared.
 * Nested calls return BUSY without disturbing the outer operation's buffers. */
AuthStatus rp2350_nonresident_seal_open_internal(Rp2350NonresidentSeal *,
    const uint8_t *,size_t,const uint8_t rp_hash[32],Rp2350Key *,uint8_t *cred_protect,
    Rp2350NonresidentWorkspace *);
#endif
