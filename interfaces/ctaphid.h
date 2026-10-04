#ifndef CTAPHID_H
#define CTAPHID_H

#include <stdint.h>

void ctaphid_process_packet(uint8_t packet[64]);
const char *ctaphid_command_name(uint8_t cmd);

#endif