#include "protocol/ctaphid_channels.h"

#include <stddef.h>
#include <string.h>

void ctaphid_channels_reset(CtaphidChannelManager *manager)
{
    if (manager == NULL) return;
    memset(manager, 0, sizeof *manager);
    manager->next_channel_id = 1U;
}

/* Storage selection is separate from CID generation. */
static size_t find_free_slot(const CtaphidChannelManager *manager)
{
    for (size_t i = 0; i < CTAPHID_MAX_CHANNELS; ++i) {
        if (!manager->channels[i].allocated) return i;
    }
    return CTAPHID_MAX_CHANNELS;
}

CtaphidChannelResult ctaphid_channels_allocate(
    CtaphidChannelManager *manager,
    uint32_t *channel_id
) {
    if (manager == NULL || channel_id == NULL) {
        return CTAPHID_CHANNEL_NULL_ARGUMENT;
    }

    /* Check capacity before committing any state or writing the caller's CID. */
    size_t slot = find_free_slot(manager);
    if (slot == CTAPHID_MAX_CHANNELS) {
        return CTAPHID_CHANNEL_TABLE_FULL;
    }

    /* A zero-initialized manager also starts at 1. Never wrap through broadcast
     * or zero: the broadcast value serves as the exhausted-generator marker. */
    uint32_t allocated = manager->next_channel_id;
    if (allocated == CTAPHID_INVALID_CHANNEL_ID) allocated = 1U;
    if (allocated == CTAPHID_BROADCAST_CHANNEL_ID) {
        return CTAPHID_CHANNEL_IDS_EXHAUSTED;
    }

    manager->channels[slot].channel_id = allocated;
    manager->channels[slot].allocated = true;
    manager->next_channel_id = allocated + 1U;
    *channel_id = allocated;
    return CTAPHID_CHANNEL_OK;
}

bool ctaphid_channels_is_allocated(
    const CtaphidChannelManager *manager,
    uint32_t channel_id
) {
    if (manager == NULL || channel_id == CTAPHID_INVALID_CHANNEL_ID ||
        channel_id == CTAPHID_BROADCAST_CHANNEL_ID) {
        return false;
    }
    for (size_t i = 0; i < CTAPHID_MAX_CHANNELS; ++i) {
        if (manager->channels[i].allocated &&
            manager->channels[i].channel_id == channel_id) {
            return true;
        }
    }
    return false;
}
