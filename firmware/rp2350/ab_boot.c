#include "ab_boot.h"
#include "board_layout.h"
#include "flash_guard.h"
#include "pico/bootrom.h"
#include "boot/picobin.h"

_Static_assert(RP2350_FIRMWARE_A_OFFSET + RP2350_FIRMWARE_SLOT_BYTES == RP2350_FIRMWARE_B_OFFSET,
    "A/B slots must be adjacent");
_Static_assert(RP2350_FIRMWARE_B_OFFSET + RP2350_FIRMWARE_SLOT_BYTES == RP2350_BLOB_FLASH_OFFSET,
    "A/B slots must end before storage");

static bool layout_valid(void) {
    const uint32_t firmware = PICOBIN_PARTITION_PERMISSION_S_R_BITS |
        PICOBIN_PARTITION_PERMISSION_S_W_BITS | PICOBIN_PARTITION_PERMISSION_NSBOOT_R_BITS |
        PICOBIN_PARTITION_PERMISSION_NSBOOT_W_BITS;
    const uint32_t metadata = PICOBIN_PARTITION_PERMISSION_S_R_BITS |
        PICOBIN_PARTITION_PERMISSION_NSBOOT_R_BITS;
    const uint32_t data = metadata | PICOBIN_PARTITION_PERMISSION_S_W_BITS;
    const uint32_t executable = PICOBIN_PARTITION_FLAGS_HAS_NAME_BITS |
        PICOBIN_PARTITION_FLAGS_IGNORED_DURING_RISCV_BOOT_BITS |
        PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_ARM_S_BITS;
    const uint32_t storage = PICOBIN_PARTITION_FLAGS_HAS_NAME_BITS |
        PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS |
        PICOBIN_PARTITION_FLAGS_IGNORED_DURING_RISCV_BOOT_BITS;
    const uint32_t starts[] = {RP2350_FIRMWARE_A_OFFSET, RP2350_FIRMWARE_B_OFFSET,
        RP2350_BLOB_FLASH_OFFSET, RP2350_STORE_FLASH_OFFSET};
    const uint32_t ends[] = {RP2350_FIRMWARE_B_OFFSET, RP2350_BLOB_FLASH_OFFSET,
        RP2350_STORE_FLASH_OFFSET, PICO_FLASH_SIZE_BYTES};
    uint32_t table[12];
    const uint32_t flags = PT_INFO_PT_INFO | PT_INFO_PARTITION_LOCATION_AND_FLAGS;
    if(rom_get_partition_table_info(table, 12, flags) != 12 || table[0] != flags ||
        table[1] != (0x100U | 4U) ||
        table[2] != (metadata | PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) ||
        table[3] != (metadata | PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_ABSOLUTE_BITS)) return false;
    for(unsigned i = 0; i < 4; ++i) {
        uint32_t permissions = i < 2 ? firmware : data;
        uint32_t partition_flags = i < 2 ? executable : storage;
        if(i == 1) partition_flags |= PICOBIN_PARTITION_FLAGS_LINK_TYPE_AS_BITS(A_PARTITION);
        uint32_t location = (starts[i] / 4096U) |
            (((ends[i] / 4096U) - 1U) << PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB);
        if(table[4 + 2*i] != (permissions | location) ||
            table[5 + 2*i] != (permissions | partition_flags)) return false;
    }
    return true;
}

bool rp2350_ab_boot_begin(Rp2350AbBoot *state) {
    *state = (Rp2350AbBoot){.pending = true};
    boot_info_t info;
    if(!rom_get_boot_info(&info)) return false;
    state->pending = (info.tbyb_and_update_info & BOOT_TBYB_AND_UPDATE_FLAG_BUY_PENDING) != 0;
    state->valid = (info.partition == 0 || info.partition == 1) && layout_valid();
    return state->valid;
}

bool rp2350_ab_boot_confirm(Rp2350AbBoot *state, void *scratch, size_t bytes) {
    if(!state || !state->valid || !state->pending || !scratch || bytes < 4096U ||
        ((uintptr_t)scratch & 3U) || !layout_valid()) return false;
    int result = rom_explicit_buy(scratch, 4096U);
    auth_secure_zero(scratch, 4096U);
    if(result != 0) return false;
    state->pending = false;
    return true;
}
