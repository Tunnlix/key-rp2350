#ifndef RP2350_BOARD_FLASH_H
#define RP2350_BOARD_FLASH_H
#include "flash_guard.h"
#include "flash_geometry.h"
typedef struct {
    Rp2350FlashGuard guard;
    Rp2350FlashDiagnostic identity;
    uint64_t max_program_us,max_erase_us;
    uint32_t programs,erases;
    uint8_t tx[49],rx[49];
    /* Optional owner watchdog/progress hook, invoked only with XIP available.
     * Set after open; no reentry or mutation from this callback. */
    void (*progress)(void *);
    void *progress_context;
} Rp2350BoardFlash;
/* Development only, exact P25Q16H reference ID plus repeated SFDP checks.
 * Page=256 comes from the reviewed part datasheet, never from missing SFDP.
 * Single Arm core 0, no core-1 launch, DMA or concurrent XIP users. Caller owns
 * a watchdog covering ROM calls (no local timeout in SDK flash operations).
 * No production-provider binding. State is zero-initialized static SRAM. */
AuthStatus rp2350_board_flash_open(Rp2350BoardFlash *,uint32_t write_offset,uint32_t write_bytes);
#endif
