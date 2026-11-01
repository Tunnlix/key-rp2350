#ifndef CTAP_UVM_H
#define CTAP_UVM_H

#include "ctap/cbor_writer.h"

/* WebAuthn 2 §10.3 and FIDO Registry §3.1–3.3. Report the factors used
 * for this operation, not the device's potential capabilities. The platform
 * gathers the PIN; the authenticator matches it in software. Sealed handles
 * add REMOTE_HANDLE; neither path claims a secure element or biometric matcher. */
static inline bool ctap_uvm_write(CborWriter *writer, bool presence, bool pin, bool remote)
{
    unsigned count = (presence ? 1U : 0U) + (pin ? 1U : 0U);
    uint16_t protection = remote ? 0x11U : 0x01U;
    bool ok = cbor_write_array(writer, count ? count : 1U);
    const uint32_t methods[] = {1U, 0x800U, 0x200U};
    const bool used[] = {presence, pin, count == 0U};
    for (unsigned i = 0U; i < 3U; ++i) {
        if (used[i]) ok = ok && cbor_write_array(writer, 3U) &&
            cbor_write_uint(writer, methods[i]) && cbor_write_uint(writer, protection) && cbor_write_uint(writer, 1U);
    }
    return ok;
}
#endif
