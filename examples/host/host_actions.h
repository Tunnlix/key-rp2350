#ifndef CTAPHID_HOST_ACTIONS_H
#define CTAPHID_HOST_ACTIONS_H

#include <stdint.h>

/* PC-only identification action; firmware supplies its own LED callback. */
void ctaphid_host_wink(void *context, uint32_t channel_id);

#endif
