#ifndef RP2350_STORAGE_ROOT_INTERNAL_H
#define RP2350_STORAGE_ROOT_INTERNAL_H
#include "storage_seal_internal.h"
/* Provider-private descriptors. In development profile the descriptor contains
 * the insecure test root. Never expose it through a core or transport API. */
typedef struct {
    uint8_t profile,backend,epoch[16],descriptor[128]; uint16_t descriptor_length;
    uint64_t serial,reset_generation;
} Rp2350StoreRoot;
/* Parsing permits the root backend to resolve UNTRUSTED descriptor bytes before
 * deriving an authentication key. A parsed descriptor is not authority. */
AuthStatus rp2350_store_root_inspect_internal(const uint8_t *,size_t,uint8_t,Rp2350StoreRoot *);
AuthStatus rp2350_store_root_encode_internal(Rp2350StoreSeal *,const Rp2350StoreRoot *,uint8_t[512]);
AuthStatus rp2350_store_root_open_internal(Rp2350StoreSeal *,const uint8_t *,size_t,uint8_t,Rp2350StoreRoot *);
#endif
