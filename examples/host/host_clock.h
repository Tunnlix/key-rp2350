#ifndef CTAPHID_HOST_CLOCK_H
#define CTAPHID_HOST_CLOCK_H
#include <stdint.h>
uint32_t ctaphid_host_now_ms(void);
void ctaphid_host_sleep_ms(uint32_t duration_ms);
#endif
