#ifndef RP2350_STORAGE_CODEC_H
#define RP2350_STORAGE_CODEC_H
#include "authenticator/auth_platform.h"
#include "authenticator/auth_pin.h"
#define RP2350_STORE_PLAIN_MAX 3584U
#define RP2350_STORE_PIN_MAX (24U + AUTH_PIN_MAX_RP_IDS * 32U)
#define RP2350_STORE_FRAME_MAX 4096U
#define RP2350_STORE_METADATA_MAX (128U+64U+2048U+192U+32U)
#define RP2350_STORE_PARTITION_SIZE 0x80000U
#define RP2350_STORE_ARENA_SIZE 0x3e000U
#define RP2350_STORE_ARENA_A 0x4000U
#define RP2350_STORE_ARENA_B 0x42000U
typedef struct {
    /* attempt_high is an encoded reservation field; the development writer
     * does not implement production reservation/accounting before encryption. */
    uint64_t handle_high, attempt_high, reset_generation;
    uint8_t store_state[16],handle_prefix[24],device_id[16];
    uint32_t nonresident_issued,nonresident_counter;
} Rp2350StoreGlobal;
typedef struct { uint32_t expected,next; uint8_t id[32]; } Rp2350StoreCounter;
typedef struct {
    uint16_t metadata_count,key_count;
    uint64_t last_sequence;
    uint8_t global_digest[32],ordered_digest[32];
} Rp2350StoreManifest;
typedef struct {
    uint8_t state,arena; uint64_t serial,generation,reset_generation;
    uint8_t epoch[16],manifest_digest[32];
} Rp2350StoreSelector;
typedef struct { uint16_t kind; const uint8_t *data; size_t length; } Rp2350StoreEntry;
typedef struct { uint16_t class_id,count; Rp2350StoreEntry entries[4]; } Rp2350StoreTransaction;
typedef AuthStatus (*Rp2350StoreHash)(void *,const uint8_t *,size_t,uint8_t[32]);
/* Buffers/records must not overlap. Decode failures clear output records;
 * encode failures leave length zero and never publish partial records.
 * Payloads are plaintext INTERNAL storage objects, never a transport API. */
AuthStatus rp2350_store_metadata_encode(const AuthCredential *,Rp2350StoreHash,void *,uint8_t *,size_t,size_t *);
AuthStatus rp2350_store_metadata_decode(const uint8_t *,size_t,Rp2350StoreHash,void *,AuthCredential *);
/* Legacy empty-list policies keep their exact version-1/24-byte encoding.
 * Nonempty RP lists use version 2. Old firmware must not be booted against a
 * store after that feature is configured: it rejects version 2 fail-closed.
 * Decoder accepts both versions; the upgrade never erases existing records. */
size_t rp2350_store_pin_size(const AuthPinRecord *);
AuthStatus rp2350_store_pin_encode(const AuthPinRecord *,uint8_t[RP2350_STORE_PIN_MAX]);
AuthStatus rp2350_store_pin_decode(const uint8_t *,size_t,AuthPinRecord *);
AuthStatus rp2350_store_global_encode(const Rp2350StoreGlobal *,uint8_t[96]);
AuthStatus rp2350_store_global_decode(const uint8_t *,size_t,Rp2350StoreGlobal *);
AuthStatus rp2350_store_counter_encode(const Rp2350StoreCounter *,uint8_t[48]);
AuthStatus rp2350_store_counter_decode(const uint8_t *,size_t,Rp2350StoreCounter *);
AuthStatus rp2350_store_manifest_encode(const Rp2350StoreManifest *,uint8_t[96]);
AuthStatus rp2350_store_manifest_decode(const uint8_t *,size_t,Rp2350StoreManifest *);
AuthStatus rp2350_store_selector_encode(const Rp2350StoreSelector *,uint8_t[80]);
AuthStatus rp2350_store_selector_decode(const uint8_t *,size_t,Rp2350StoreSelector *);
/* Structural framing only: caller validates every typed payload AND the complete
 * post-transaction state before applying entries. Key payloads stay opaque. */
AuthStatus rp2350_store_transaction_encode(const Rp2350StoreTransaction *,uint8_t *,size_t,size_t *);
AuthStatus rp2350_store_transaction_decode(uint16_t,const uint8_t *,size_t,Rp2350StoreTransaction *);
#endif
