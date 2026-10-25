#ifndef RP2350_FLASH_GEOMETRY_H
#define RP2350_FLASH_GEOMETRY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Read-only diagnostic parser, not authorization to program physical flash.
 * Reader addresses are SFDP offsets, never flash data-array addresses. */
typedef bool (*Rp2350SfdpRead)(void *, uint32_t, uint8_t *, size_t);
typedef struct {
    uint64_t bytes;
    uint32_t page_bytes; /* Zero means not present in a 9/10-DWORD BFPT. */
    uint8_t address_mode, erase_4k_opcode, bfpt_minor, bfpt_dwords;
} Rp2350FlashGeometry;
typedef enum {
    RP2350_SFDP_OK=0, RP2350_SFDP_IO=1, RP2350_SFDP_SIGNATURE=2,
    RP2350_SFDP_HEADER=3, RP2350_SFDP_SECTOR_MAP=4, RP2350_SFDP_BFPT=5,
    RP2350_SFDP_POINTER=6, RP2350_SFDP_DENSITY_ADDRESS=7,
    RP2350_SFDP_PAGE=8, RP2350_SFDP_ERASE=9
} Rp2350SfdpError;
typedef enum {
    RP2350_BFPT_NONE=0, RP2350_BFPT_MISSING=1, RP2350_BFPT_DUPLICATE=2,
    RP2350_BFPT_VERSION=3, RP2350_BFPT_SHORT=4, RP2350_BFPT_LONG=5
} Rp2350BfptIssue;
typedef struct {
    Rp2350BfptIssue issue;
    uint8_t length_dwords,major,minor;
} Rp2350BfptTrace;
/* Trace is untrusted diagnostic metadata, retained on rejection. Geometry
 * clears on errors; 9/10-DWORD tables return partial geometry with page=0. */
Rp2350SfdpError rp2350_flash_geometry_trace(Rp2350SfdpRead,void *,Rp2350FlashGeometry *,Rp2350BfptTrace *);
Rp2350SfdpError rp2350_flash_geometry_detail(Rp2350SfdpRead, void *, Rp2350FlashGeometry *);
bool rp2350_flash_geometry_read(Rp2350SfdpRead, void *, Rp2350FlashGeometry *);
bool rp2350_flash_geometry_development(const Rp2350FlashGeometry *);
/* Diagnostic reference ID only. Never fills unknown geometry or enables IO. */
bool rp2350_flash_identity_p25q16h(const uint8_t id[3]);
typedef bool (*Rp2350JedecRead)(void *, uint8_t[3]);
typedef struct {
    uint8_t id[3], repeated_id[3];
    Rp2350FlashGeometry first, repeated;
    unsigned status, disagreement;
    Rp2350SfdpError sfdp_error;
    Rp2350BfptTrace bfpt;
} Rp2350FlashDiagnostic;
/* Status 6 details: 1 repeated ID/read, 2 repeated SFDP parse, 3 density,
 * 4 page size, 5 addressing, 6 erase opcode, 7 BFPT revision. Not a writer gate. */
unsigned rp2350_flash_diagnostic(Rp2350JedecRead, Rp2350SfdpRead, void *, Rp2350FlashDiagnostic *);
#endif
