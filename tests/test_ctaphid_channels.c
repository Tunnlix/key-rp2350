#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_channels.h"

static void test_allocation_beyond_former_capacity(void)
{
    CtaphidChannelManager manager;
    ctaphid_channels_reset(&manager);
    uint32_t allocated[64];
    for (size_t i = 0; i < 64U; ++i) {
        assert(ctaphid_channels_allocate(&manager, &allocated[i]) == CTAPHID_CHANNEL_OK);
        assert(allocated[i] != 0U && allocated[i] != UINT32_MAX);
        for (size_t j = 0; j < i; ++j) assert(allocated[i] != allocated[j]);
        for (size_t j = 0; j <= i; ++j) {
            assert(ctaphid_channels_is_allocated(&manager, allocated[j]));
        }
        assert(!ctaphid_channels_is_allocated(&manager, allocated[i] + 1U));
    }
}

static void test_lookup_and_reset(void)
{
    CtaphidChannelManager manager = {0};
    assert(!ctaphid_channels_is_allocated(&manager, 0U));
    assert(!ctaphid_channels_is_allocated(&manager, UINT32_MAX));
    assert(!ctaphid_channels_is_allocated(&manager, 1U));
    assert(!ctaphid_channels_is_allocated(NULL, 1U));
    uint32_t first, second;
    assert(ctaphid_channels_allocate(&manager, &first) == CTAPHID_CHANNEL_OK);
    assert(first == 1U);
    assert(ctaphid_channels_allocate(&manager, &second) == CTAPHID_CHANNEL_OK);
    assert(second != first);
    CtaphidChannelManager saved = manager;
    assert(ctaphid_channels_is_allocated(&manager, first));
    assert(!ctaphid_channels_is_allocated(&manager, 0U));
    assert(!ctaphid_channels_is_allocated(&manager, UINT32_MAX));
    assert(memcmp(&manager, &saved, sizeof manager) == 0);
    ctaphid_channels_reset(&manager);
    assert(!ctaphid_channels_is_allocated(&manager, first));
    assert(!ctaphid_channels_is_allocated(&manager, second));
    assert(ctaphid_channels_allocate(&manager, &first) == CTAPHID_CHANNEL_OK);
    assert(first == 1U);
    ctaphid_channels_reset(NULL);
}

static void test_null_arguments(void)
{
    CtaphidChannelManager manager = {0};
    CtaphidChannelManager saved = manager;
    uint32_t output = 99U;
    assert(ctaphid_channels_allocate(NULL, &output) == CTAPHID_CHANNEL_NULL_ARGUMENT);
    assert(output == 99U);
    assert(ctaphid_channels_allocate(&manager, NULL) == CTAPHID_CHANNEL_NULL_ARGUMENT);
    assert(memcmp(&manager, &saved, sizeof manager) == 0);
}

static void test_id_exhaustion(void)
{
    CtaphidChannelManager manager = {0};
    /* Seed the generator near its limit to exercise an otherwise unreachable
     * boundary without billions of calls. Production callers must not edit it. */
    manager.next_channel_id = UINT32_MAX - 1U;
    uint32_t output = 0U;
    assert(ctaphid_channels_allocate(&manager, &output) == CTAPHID_CHANNEL_OK);
    assert(output == UINT32_MAX - 1U);
    assert(ctaphid_channels_is_allocated(&manager, output));
    assert(!ctaphid_channels_is_allocated(&manager, output - 1U));
    CtaphidChannelManager saved = manager;
    output = 99U;
    assert(ctaphid_channels_allocate(&manager, &output) == CTAPHID_CHANNEL_IDS_EXHAUSTED);
    assert(output == 99U);
    assert(memcmp(&manager, &saved, sizeof manager) == 0);
    assert(!ctaphid_channels_is_allocated(&manager, UINT32_MAX));
    assert(!ctaphid_channels_is_allocated(&manager, 0U));
}

static void test_independent_devices(void)
{
    CtaphidChannelManager first = {0}, second = {0};
    uint32_t first_id, second_id;
    assert(ctaphid_channels_allocate(&first, &first_id) == CTAPHID_CHANNEL_OK);
    assert(!ctaphid_channels_is_allocated(&second, first_id));
    assert(ctaphid_channels_allocate(&second, &second_id) == CTAPHID_CHANNEL_OK);
    assert(first_id == second_id); /* CIDs are local to each device. */
    ctaphid_channels_reset(&first);
    assert(ctaphid_channels_is_allocated(&second, second_id));
}

int main(void)
{
    test_allocation_beyond_former_capacity();
    test_lookup_and_reset();
    test_null_arguments();
    test_id_exhaustion();
    test_independent_devices();
    puts("CTAPHID channel manager tests passed.");
    return 0;
}
