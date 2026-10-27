#ifndef CTAP_LARGE_BLOBS_H
#define CTAP_LARGE_BLOBS_H
#include "ctap/ctap_client_pin.h"
#define CTAP_LARGE_BLOB_CAPACITY 4096U
#define CTAP_LARGE_BLOB_FRAGMENT (CTAP_MESSAGE_CAPACITY - 64U)
/* The array contains client-encrypted bytes. read publishes the committed size;
 * commit atomically replaces the full array. Reset returns the initial empty
 * array. All callbacks are serialized, outside HID receive callbacks. */
typedef struct {
    void *context;
    AuthStatus (*read)(void *, size_t offset, uint8_t *, size_t, size_t *total);
    AuthStatus (*commit)(void *, const uint8_t *, size_t);
} CtapLargeBlobStorage;
typedef struct {
    CtapLargeBlobStorage storage;
    size_t next_offset, expected_length;
    uint32_t channel, last_call_ms;
    uint8_t pending[CTAP_LARGE_BLOB_CAPACITY], fragment[CTAP_LARGE_BLOB_FRAGMENT];
} CtapLargeBlobs;
void ctap_large_blobs_clear(CtapLargeBlobs *);
uint8_t ctap_large_blobs_execute(CtapLargeBlobs *, CtapClientPin *, uint32_t channel,
    const uint8_t *, size_t, uint8_t *, size_t, size_t *, uint32_t now_ms);
#endif
