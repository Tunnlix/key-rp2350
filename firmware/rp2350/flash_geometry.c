#include "flash_geometry.h"
#include <string.h>
/* Independent bounded interpretation of JESD216 BFPT fields. Format reference:
 * Linux v6.12 drivers/mtd/spi-nor/sfdp.[ch]. No driver code is incorporated.
 * Deliberately reject ambiguous tables and sector-map extensions; this
 * diagnostic does not implement general NOR discovery or manufacturer fixups. */
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
Rp2350SfdpError rp2350_flash_geometry_trace(Rp2350SfdpRead read,void *ctx,Rp2350FlashGeometry *out,Rp2350BfptTrace *trace) {
    Rp2350BfptTrace local;
    if (!trace) trace=&local;
    memset(trace,0,sizeof(*trace));
    if (!out) return RP2350_SFDP_IO;
    memset(out,0,sizeof(*out));
    if (!read) return RP2350_SFDP_IO;
    uint8_t header[8],ph[8],bfpt[44]={0}; uint32_t pointer=0; bool found=false;
    uint8_t minor=0,length=0;
    if (!read(ctx,0,header,sizeof(header))) return RP2350_SFDP_IO;
    if (memcmp(header,"SFDP",4)) return RP2350_SFDP_SIGNATURE;
    if (header[5]!=1 || header[6]>15 || header[7]!=0xff) return RP2350_SFDP_HEADER;
    uint32_t end=8U+8U*((uint32_t)header[6]+1U);
    for (uint32_t i=0;i<=(uint32_t)header[6];i++) {
        if (!read(ctx,8U+8U*i,ph,sizeof(ph))) return RP2350_SFDP_IO;
        uint16_t id=(uint16_t)ph[0]|((uint16_t)ph[7]<<8);
        if (id==0xff81U) return RP2350_SFDP_SECTOR_MAP; /* Sector-map support not implemented. */
        if (id!=0xff00U) continue;
        trace->length_dwords=ph[3]; trace->major=ph[2]; trace->minor=ph[1];
        if (found) trace->issue=RP2350_BFPT_DUPLICATE;
        else if (ph[2]!=1) trace->issue=RP2350_BFPT_VERSION;
        else if (ph[3]<9) trace->issue=RP2350_BFPT_SHORT;
        else if (ph[3]>64) trace->issue=RP2350_BFPT_LONG;
        if (trace->issue!=RP2350_BFPT_NONE) return RP2350_SFDP_BFPT;
        pointer=(uint32_t)ph[4]|((uint32_t)ph[5]<<8)|((uint32_t)ph[6]<<16);
        if ((pointer&3U) || pointer<end || pointer>0x1000000U-4U*ph[3]) return RP2350_SFDP_POINTER;
        minor=ph[1]; length=ph[3]; found=true;
    }
    if (!found) { trace->issue=RP2350_BFPT_MISSING; return RP2350_SFDP_BFPT; }
    size_t bytes=length<11 ? (size_t)length*4U : sizeof(bfpt);
    if (!read(ctx,pointer,bfpt,bytes)) return RP2350_SFDP_IO;
    Rp2350FlashGeometry g={0};
    g.bfpt_minor=minor;
    g.bfpt_dwords=length;
    g.address_mode=(uint8_t)((le32(bfpt)>>17)&3U);
    if (g.address_mode==3) return RP2350_SFDP_DENSITY_ADDRESS;
    uint32_t density=le32(bfpt+4); uint64_t bits;
    if (density&0x80000000U) {
        uint32_t exponent=density&0x7fffffffU;
        if (exponent<3 || exponent>63) return RP2350_SFDP_DENSITY_ADDRESS;
        bits=UINT64_C(1)<<exponent;
    } else bits=(uint64_t)density+1U;
    if ((bits&7U) || !bits) return RP2350_SFDP_DENSITY_ADDRESS;
    g.bytes=bits/8U;
    if (length>=11) {
        uint32_t page_exp=(le32(bfpt+40)>>4)&15U;
        if (!page_exp) return RP2350_SFDP_PAGE;
        g.page_bytes=1U<<page_exp;
    }
    for (size_t i=0;i<4;i++) {
        uint8_t exponent=bfpt[28+2*i],opcode=bfpt[29+2*i];
        if (!exponent) continue;
        if (exponent>=32 || !opcode || opcode==0xff) return RP2350_SFDP_ERASE;
        if (exponent==12 && opcode==0x20) g.erase_4k_opcode=opcode;
    }
    *out=g; return RP2350_SFDP_OK;
}
Rp2350SfdpError rp2350_flash_geometry_detail(Rp2350SfdpRead read,void *ctx,Rp2350FlashGeometry *out) {
    return rp2350_flash_geometry_trace(read,ctx,out,NULL);
}
bool rp2350_flash_geometry_read(Rp2350SfdpRead read,void *ctx,Rp2350FlashGeometry *out) {
    return rp2350_flash_geometry_detail(read,ctx,out)==RP2350_SFDP_OK;
}
bool rp2350_flash_geometry_development(const Rp2350FlashGeometry *g) {
    return g && g->bytes==0x200000U && g->page_bytes==256 &&
        g->address_mode<=1 && g->erase_4k_opcode==0x20;
}
bool rp2350_flash_identity_p25q16h(const uint8_t id[3]) {
    /* Puya P25Q16H datasheet (2020-07-20), p48 ID table, hosted by Seeed.
     * ID equality is not physical part/package, durability or writer approval. */
    return id && id[0]==0x85 && id[1]==0x60 && id[2]==0x15;
}
unsigned rp2350_flash_diagnostic(Rp2350JedecRead id_read,Rp2350SfdpRead sfdp_read,void *ctx,Rp2350FlashDiagnostic *out) {
    if (!out) return 2;
    memset(out,0,sizeof(*out)); out->status=2;
    if (!id_read || !sfdp_read) return out->status;
    out->status=1;
    if (!id_read(ctx,out->id)) return out->status;
    for (size_t i=0;i<3;i++) if (!out->id[i] || out->id[i]==0xff) return out->status;
    out->status=2;
    out->sfdp_error=rp2350_flash_geometry_trace(sfdp_read,ctx,&out->first,&out->bfpt);
    if (out->sfdp_error!=RP2350_SFDP_OK) return out->status;
    out->status=6;
    if (!id_read(ctx,out->repeated_id) || memcmp(out->id,out->repeated_id,3)) out->disagreement=1;
    else if ((out->sfdp_error=rp2350_flash_geometry_trace(sfdp_read,ctx,&out->repeated,&out->bfpt))!=RP2350_SFDP_OK) out->disagreement=2;
    else if (out->first.bytes!=out->repeated.bytes) out->disagreement=3;
    else if (out->first.page_bytes!=out->repeated.page_bytes) out->disagreement=4;
    else if (out->first.address_mode!=out->repeated.address_mode) out->disagreement=5;
    else if (out->first.erase_4k_opcode!=out->repeated.erase_4k_opcode) out->disagreement=6;
    else if (out->first.bfpt_minor!=out->repeated.bfpt_minor || out->first.bfpt_dwords!=out->repeated.bfpt_dwords) out->disagreement=7;
    else if (rp2350_flash_geometry_development(&out->first)) out->status=3;
    else if (!out->first.page_bytes && out->first.bytes==0x200000U &&
        out->first.address_mode<=1 && out->first.erase_4k_opcode==0x20) out->status=4;
    else out->status=5;
    return out->status;
}
