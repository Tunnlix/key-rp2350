#ifndef RP2350_BOARD_LAYOUT_H
#define RP2350_BOARD_LAYOUT_H
#include "pico.h"
/* Match the XIAO linker layout; board_flash separately verifies the chip. */
#if !defined(PICO_FLASH_SIZE_BYTES) || PICO_FLASH_SIZE_BYTES != 0x200000U
#error "Review the linker/store layout before changing configured flash size"
#endif
#endif
