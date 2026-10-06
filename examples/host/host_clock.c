#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "host_clock.h"
#ifdef _WIN32
#include <windows.h>
uint32_t ctaphid_host_now_ms(void) { return (uint32_t)GetTickCount64(); }
void ctaphid_host_sleep_ms(uint32_t duration_ms) { Sleep(duration_ms); }
#else
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
uint32_t ctaphid_host_now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { perror("clock_gettime"); exit(1); }
    return (uint32_t)((uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U);
}
void ctaphid_host_sleep_ms(uint32_t duration_ms)
{
    struct timespec wait = {(time_t)(duration_ms / 1000U), (long)(duration_ms % 1000U) * 1000000L};
    while (nanosleep(&wait, &wait) != 0 && errno == EINTR) { }
}
#endif
