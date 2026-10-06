#ifndef CTAPHID_CHANNELS_H
#define CTAPHID_CHANNELS_H

#include <stdbool.h>
#include <stdint.h>

#include "protocol/ctaphid_framing.h"

#define CTAPHID_MAX_CHANNELS 16U

typedef struct {
    bool allocated;
    uint32_t channel_id;
} CtaphidChannel;

/* One manager per device, owned by the caller. Initialize with {0} or reset
 * before use. Do not modify fields directly or call concurrently without
 * external synchronization. Allocations persist until a device-level reset. */
typedef struct {
    CtaphidChannel channels[CTAPHID_MAX_CHANNELS];
    uint32_t next_channel_id;
} CtaphidChannelManager;

typedef enum {
    CTAPHID_CHANNEL_OK = 0,
    CTAPHID_CHANNEL_NULL_ARGUMENT,
    CTAPHID_CHANNEL_TABLE_FULL,
    CTAPHID_CHANNEL_IDS_EXHAUSTED
} CtaphidChannelResult;

/* Clear all allocations and restart CID generation at 1. NULL is a no-op.
 * This invalidates previous allocations and can reuse old CIDs. Call only when
 * resetting the device; same-channel INIT must preserve the allocation table. */
void ctaphid_channels_reset(CtaphidChannelManager *manager);

/* Allocate a free table slot and a unique, non-reserved CID. No heap allocation.
 * Success writes channel_id; failure leaves manager and output unchanged.
 * channel_id must not overlap manager storage. IDs increase without wrapping;
 * exhaustion is reported rather than reusing an ID within the device lifetime. */
CtaphidChannelResult ctaphid_channels_allocate(
    CtaphidChannelManager *manager,
    uint32_t *channel_id
);

/* Read-only lookup. NULL manager, zero, broadcast, and unknown CIDs return false.
 * This checks allocation only, not whether a channel owns a busy transaction. */
bool ctaphid_channels_is_allocated(
    const CtaphidChannelManager *manager,
    uint32_t channel_id
);

/* This module only stores allocations. INIT routing requests a CID; the handler
 * constructs its reply. The coordinator handles transactions, resynchronization,
 * locks, cancellation, and replies when allocation fails. No HID I/O occurs here. */

#endif
