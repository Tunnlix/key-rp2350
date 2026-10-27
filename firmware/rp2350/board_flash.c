#include "board_layout.h"
#include "board_flash.h"
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include <string.h>
_Static_assert(FLASH_PAGE_SIZE==256 && FLASH_SECTOR_SIZE==4096,"Reviewed flash geometry");
extern const uint8_t __ctap_store_start[],__ctap_store_end[],__ctap_blob_start[],__ctap_blob_end[];
static void command(Rp2350BoardFlash *p,size_t n) {
    uint32_t saved=save_and_disable_interrupts();
    flash_do_cmd(p->tx,p->rx,n);
    restore_interrupts(saved);
}
static bool jedec(void *ctx,uint8_t id[3]) {
    Rp2350BoardFlash *p=ctx; memset(p->tx,0,4); p->tx[0]=0x9f;
    command(p,4); memcpy(id,p->rx+1,3); return true;
}
static bool sfdp(void *ctx,uint32_t address,uint8_t *out,size_t n) {
    Rp2350BoardFlash *p=ctx;
    if (!out || n>44 || address>0x1000000U-n) return false;
    memset(p->tx,0,sizeof(p->tx)); p->tx[0]=0x5a;
    p->tx[1]=(uint8_t)(address>>16); p->tx[2]=(uint8_t)(address>>8); p->tx[3]=(uint8_t)address;
    command(p,n+5); memcpy(out,p->rx+5,n); return true;
}
static bool physical_span(uint32_t at,size_t n) {
    return at>=RP2350_BLOB_FLASH_OFFSET && at<=0x200000U && n<=0x200000U-at;
}
static AuthStatus read_raw(void *ctx,uint32_t at,uint8_t *out,size_t n) {
    Rp2350BoardFlash *p=ctx;
    if (get_core_num()!=0 || !out || !physical_span(at,n)) return AUTH_INVALID_ARGUMENT;
    memcpy(out,(const void *)(uintptr_t)(XIP_BASE+at),n);
    if(p->progress) p->progress(p->progress_context);
    return AUTH_OK;
}
static AuthStatus program_raw(void *ctx,uint32_t at,const uint8_t page[256]) {
    Rp2350BoardFlash *p=ctx;
    if (get_core_num()!=0 || (page!=p->guard.staged && page!=p->blob_guard.staged) || (at&255U) || !physical_span(at,256)) return AUTH_INVALID_ARGUMENT;
    /* Guard has copied the entire source page into its SRAM staging buffer.
     * SDK routine executes from RAM and restores XIP before returning. */
    if(p->progress) p->progress(p->progress_context);
    uint64_t begun=time_us_64(); uint32_t saved=save_and_disable_interrupts();
    flash_range_program(at,page,256);
    restore_interrupts(saved);
    uint64_t elapsed=time_us_64()-begun;
    if (elapsed>p->max_program_us) p->max_program_us=elapsed;
    p->programs++; if(p->progress) p->progress(p->progress_context);
    return AUTH_OK; /* Guard requires complete readback. */
}
static AuthStatus erase_raw(void *ctx,uint32_t at) {
    Rp2350BoardFlash *p=ctx;
    if (get_core_num()!=0 || (at&4095U) || !physical_span(at,4096)) return AUTH_INVALID_ARGUMENT;
    if(p->progress) p->progress(p->progress_context);
    uint64_t begun=time_us_64(); uint32_t saved=save_and_disable_interrupts();
    flash_range_erase(at,4096);
    restore_interrupts(saved);
    uint64_t elapsed=time_us_64()-begun;
    if (elapsed>p->max_erase_us) p->max_erase_us=elapsed;
    p->erases++; if(p->progress) p->progress(p->progress_context);
    return AUTH_OK;
}
AuthStatus rp2350_board_flash_open(Rp2350BoardFlash *p,uint32_t at,uint32_t n) {
    if (!p || get_core_num()!=0 || (uintptr_t)p<SRAM_BASE ||
        (uintptr_t)p>SRAM_END-sizeof(*p)) return AUTH_INVALID_ARGUMENT;
    if (p->guard.busy) return AUTH_BUSY;
    auth_secure_zero(p,sizeof(*p));
    if ((uintptr_t)__ctap_blob_start!=XIP_BASE+RP2350_BLOB_FLASH_OFFSET ||
        (uintptr_t)__ctap_blob_end!=XIP_BASE+RP2350_STORE_FLASH_OFFSET ||
        (uintptr_t)__ctap_store_start!=XIP_BASE+RP2350_STORE_FLASH_OFFSET ||
        (uintptr_t)__ctap_store_end!=XIP_BASE+0x200000U) return AUTH_BAD_DATA;
    unsigned status=rp2350_flash_diagnostic(jedec,sfdp,p,&p->identity);
    if ((status!=3 && status!=4) || !rp2350_flash_identity_p25q16h(p->identity.id) ||
        (p->identity.first.page_bytes && p->identity.first.page_bytes!=256)) return AUTH_UNSUPPORTED;
    Rp2350Flash raw={p,read_raw,program_raw,erase_raw};
    AuthStatus result=rp2350_flash_guard_init(&p->guard,&raw,at,n);
    return result==AUTH_OK ? rp2350_flash_guard_init_blobs(&p->blob_guard,&raw,at==0U && n==RP2350_STORE_FLASH_BYTES) : result;
}

Rp2350Flash rp2350_board_blob_flash(Rp2350BoardFlash *p) { return rp2350_flash_guard_interface(&p->blob_guard); }
