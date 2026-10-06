#include "host_actions.h"

#include <inttypes.h>
#include <stdio.h>

void ctaphid_host_wink(void *context, uint32_t channel_id)
{
    (void)context;
    fprintf(stderr, "WINK: identify authenticator on CID 0x%08" PRIX32 "\n", channel_id);
}
