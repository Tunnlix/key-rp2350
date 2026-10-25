#include "flash_guard.h"
#include <string.h>
static bool span(uint32_t at,size_t n) {
    return at<=RP2350_STORE_FLASH_BYTES && n<=RP2350_STORE_FLASH_BYTES-at;
}
static bool writable(const Rp2350FlashGuard *g,uint32_t at,size_t n) {
    return g->write_bytes && at>=g->write_offset && at-g->write_offset<=g->write_bytes &&
        n<=g->write_bytes-(at-g->write_offset);
}
static AuthStatus begin(Rp2350FlashGuard *g) {
    if (!g || !g->initialized || g->faulted) return AUTH_IO_ERROR;
    if (g->busy) return AUTH_BUSY;
    g->busy=true; return AUTH_OK;
}
static AuthStatus end(Rp2350FlashGuard *g,AuthStatus status) {
    if (status!=AUTH_OK) g->faulted=true;
    auth_secure_zero(g->staged,sizeof(g->staged)); auth_secure_zero(g->verify,sizeof(g->verify));
    g->busy=false; return status==AUTH_NOT_FOUND ? AUTH_IO_ERROR : status;
}
static AuthStatus read_partition(void *ctx,uint32_t at,uint8_t *out,size_t n) {
    Rp2350FlashGuard *g=ctx;
    if ((!out && n) || !span(at,n)) return AUTH_INVALID_ARGUMENT;
    AuthStatus status=begin(g);
    if (status!=AUTH_OK) { if (out) auth_secure_zero(out,n); return status; }
    status=n ? g->raw.read(g->raw.context,RP2350_STORE_FLASH_OFFSET+at,out,n) : AUTH_OK;
    if (status!=AUTH_OK && out) auth_secure_zero(out,n);
    return end(g,status);
}
static AuthStatus program(void *ctx,uint32_t at,const uint8_t page[256]) {
    Rp2350FlashGuard *g=ctx;
    if (!page || (at&255U) || !span(at,256)) return AUTH_INVALID_ARGUMENT;
    if (!g || !g->initialized || g->faulted) return AUTH_IO_ERROR;
    if (!writable(g,at,256)) return AUTH_UNSUPPORTED;
    AuthStatus status=begin(g); if (status!=AUTH_OK) return status;
    memcpy(g->staged,page,256); uint32_t physical=RP2350_STORE_FLASH_OFFSET+at;
    status=g->raw.read(g->raw.context,physical,g->verify,256);
    if (status==AUTH_OK) for (size_t i=0;i<256;i++) if (g->verify[i]!=0xff) { status=AUTH_BAD_DATA; break; }
    if (status==AUTH_OK) status=g->raw.program_page(g->raw.context,physical,g->staged);
    if (status==AUTH_OK) status=g->raw.read(g->raw.context,physical,g->verify,256);
    if (status==AUTH_OK && memcmp(g->staged,g->verify,256)) status=AUTH_IO_ERROR;
    return end(g,status);
}
static AuthStatus erase(void *ctx,uint32_t at) {
    Rp2350FlashGuard *g=ctx;
    if ((at&4095U) || !span(at,4096)) return AUTH_INVALID_ARGUMENT;
    if (!g || !g->initialized || g->faulted) return AUTH_IO_ERROR;
    if (!writable(g,at,4096)) return AUTH_UNSUPPORTED;
    AuthStatus status=begin(g); if (status!=AUTH_OK) return status;
    uint32_t physical=RP2350_STORE_FLASH_OFFSET+at;
    status=g->raw.erase_sector(g->raw.context,physical);
    for (size_t offset=0;status==AUTH_OK && offset<4096;offset+=256) {
        status=g->raw.read(g->raw.context,physical+(uint32_t)offset,g->verify,256);
        if (status==AUTH_OK) for (size_t i=0;i<256;i++) if (g->verify[i]!=0xff) { status=AUTH_IO_ERROR; break; }
    }
    return end(g,status);
}
AuthStatus rp2350_flash_guard_init(Rp2350FlashGuard *g,const Rp2350Flash *raw,uint32_t at,uint32_t n) {
    if (!g) return AUTH_INVALID_ARGUMENT;
    if (g->busy) return AUTH_BUSY;
    auth_secure_zero(g,sizeof(*g));
    if (!raw || !raw->read || (at&4095U) || (n&4095U) || !span(at,n) ||
        (n && (!raw->program_page || !raw->erase_sector))) return AUTH_INVALID_ARGUMENT;
    g->raw=*raw; g->write_offset=at; g->write_bytes=n; g->initialized=true; return AUTH_OK;
}
Rp2350Flash rp2350_flash_guard_interface(Rp2350FlashGuard *g) {
    return (Rp2350Flash){g,read_partition,program,erase};
}
