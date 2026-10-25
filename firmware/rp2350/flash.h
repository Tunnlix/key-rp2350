#ifndef RP2350_FLASH_H
#define RP2350_FLASH_H
#include "authenticator/auth_platform.h"
#define RP2350_FLASH_PAGE 256U
#define RP2350_FLASH_SECTOR 4096U
/* Offsets are relative to the provider-owned flash partition. */
typedef struct {
    void *context;
    AuthStatus (*read)(void *,uint32_t offset,uint8_t *,size_t);
    AuthStatus (*program_page)(void *,uint32_t offset,const uint8_t page[RP2350_FLASH_PAGE]);
    AuthStatus (*erase_sector)(void *,uint32_t offset);
} Rp2350Flash;
#endif
