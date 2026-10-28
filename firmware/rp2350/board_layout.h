#ifndef RP2350_BOARD_LAYOUT_H
#define RP2350_BOARD_LAYOUT_H
#include "pico.h"
/* Match the XIAO linker layout; board_flash separately verifies the chip. */
#if !defined(PICO_FLASH_SIZE_BYTES) || PICO_FLASH_SIZE_BYTES != 0x200000U
#error "Review the linker/store layout before changing configured flash size"
#endif
#define RP2350_FIRMWARE_A_OFFSET 0x002000U
#define RP2350_FIRMWARE_B_OFFSET 0x0bd000U
#define RP2350_FIRMWARE_SLOT_BYTES 0x0bb000U
#endif
