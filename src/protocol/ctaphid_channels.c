#include "protocol/ctaphid_channels.h"

#include <stddef.h>
#include <string.h>

void ctaphid_channels_reset(CtaphidChannelManager *manager)
{
    if (manager == NULL) return;
    memset(manager, 0, sizeof *manager);
    manager->next_channel_id = 1U;
}

CtaphidChannelResult ctaphid_channels_allocate(
    CtaphidChannelManager *manager,
    uint32_t *channel_id
) {
    if (manager == NULL || channel_id == NULL) {
        return CTAPHID_CHANNEL_NULL_ARGUMENT;
    }

    /* A zero-initialized manager also starts at 1. Never wrap through broadcast
     * or zero: the broadcast value serves as the exhausted-generator marker. */
    uint32_t allocated = manager->next_channel_id;
    if (allocated == CTAPHID_INVALID_CHANNEL_ID) allocated = 1U;
    if (allocated == CTAPHID_BROADCAST_CHANNEL_ID) {
        return CTAPHID_CHANNEL_IDS_EXHAUSTED;
    }

    if (manager->first_channel_id == 0U) manager->first_channel_id = allocated;
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
    /* Every value in this interval was issued exactly once. Keeping old CIDs
     * valid avoids evicting live clients or their channel-bound continuations. */
    return manager->first_channel_id != 0U && channel_id >= manager->first_channel_id &&
        channel_id < manager->next_channel_id;
}
