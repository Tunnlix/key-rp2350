#include "firmware_update.h"
#include "application.h"
#include "ctap/cbor_reader.h"
#include "ctap/cbor_writer.h"

void rp2350_boot_gesture_init(Rp2350BootGesture *g, bool pressed, uint32_t now) {
    *g=(Rp2350BootGesture){.started_ms=now,.changed_ms=now,.held_ms=now,
        .pressed=pressed,.result=pressed ? RP2350_BOOT_HOLD : RP2350_BOOT_NORMAL};
}
Rp2350BootGestureResult rp2350_boot_gesture_sample(Rp2350BootGesture *g, bool pressed, uint32_t now) {
    if(g->result==RP2350_BOOT_NORMAL || g->result==RP2350_BOOT_ENTER) return g->result;
    if((uint32_t)(now-g->started_ms)>=RP2350_UPDATE_STARTUP_TIMEOUT_MS)
        return g->result=RP2350_BOOT_NORMAL;
    if(g->result==RP2350_BOOT_HOLD && g->pressed && (uint32_t)(now-g->held_ms)>=RP2350_UPDATE_HOLD_MS)
        g->result=RP2350_BOOT_RELEASE;
    if(pressed!=g->pressed) {
        g->pressed=pressed; g->changed_ms=now;
        if(pressed) g->held_ms=now;
    }
    if(!pressed && (uint32_t)(now-g->changed_ms)>=RP2350_DEBOUNCE_MS)
        g->result=g->result==RP2350_BOOT_RELEASE ? RP2350_BOOT_ENTER : RP2350_BOOT_NORMAL;
    return g->result;
}

static uint8_t parse(const uint8_t *request, size_t n, uint64_t *operation) {
    CborValue map, version, command;
    if(!cbor_read_document(request+1,n-1,&map)) return CTAP_STATUS_INVALID_CBOR;
    if(map.major!=5) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if(!cbor_map_uint(&map,1,&version) || !cbor_map_uint(&map,2,&command)) return CTAP_STATUS_MISSING_PARAMETER;
    if(version.major!=0 || command.major!=0) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if(version.value!=RP2350_UPDATE_PROTOCOL) return CTAP_STATUS_INVALID_PARAMETER;
    if(command.value>1) return CTAP_STATUS_INVALID_SUBCOMMAND;
    *operation=command.value; return CTAP_STATUS_OK;
}
void rp2350_firmware_update_abort(Rp2350Application *a, uint64_t operation) {
    if(a->update.operation!=operation) return;
    rp2350_presence_abort(&a->presence,operation);
    auth_secure_zero(&a->update,sizeof(a->update));
}
void rp2350_firmware_update_start(Rp2350Application *a, uint64_t operation, const uint8_t *request, size_t n) {
    uint8_t response[48]={CTAP_STATUS_INVALID_COMMAND}; size_t length=1; uint64_t command=0;
    if(a->io.usb_transport && rp2350_application_ready(a)) {
        response[0]=parse(request,n,&command);
        /* A vendor operation interrupts continuation/UV state just like an
         * unrelated CTAP operation; no flash mutations are involved. */
        ctap_assertion_sequence_clear(&a->backend.assertion_sequence);
        ctap_credential_management_clear(&a->backend.management);
        auth_credentials_release_nonresident(&a->service);
        if(response[0]==CTAP_STATUS_OK && command==1) {
            ctap_client_pin_invalidate(&a->pin);
            uint32_t now=a->io.now_ms(a->io.context);
            a->update=(Rp2350FirmwareUpdate){.operation=operation,.started_ms=now,.waiting=true};
            rp2350_presence_begin(&a->presence,operation,now);
            (void)ctaphid_device_set_keepalive(&a->device,operation,CTAPHID_STATUS_UPNEEDED,now);
            return;
        }
        if(response[0]==CTAP_STATUS_OK) {
            CborWriter w; cbor_writer_init(&w,response+1,sizeof(response)-1);
            bool ok=cbor_write_map(&w,4) && cbor_write_uint(&w,1) && cbor_write_text(&w,"Key") &&
                cbor_write_uint(&w,2) && cbor_write_uint(&w,RP2350_UPDATE_PROTOCOL) &&
                cbor_write_uint(&w,3) && cbor_write_uint(&w,RP2350_UPDATE_TOUCH_TIMEOUT_MS) &&
                cbor_write_uint(&w,4) && cbor_write_uint(&w,RP2350_UPDATE_HOLD_MS);
            if(ok) length+=w.length; else response[0]=CTAP_STATUS_OTHER;
        }
    }
    (void)ctaphid_device_complete_cbor(&a->device,operation,response,length);
}
CtaphidDeviceResult rp2350_firmware_update_poll(Rp2350Application *a, uint64_t event, uint32_t now) {
    if(!rp2350_application_ready(a)) {
        rp2350_firmware_update_abort(a,a->update.operation);
        return CTAPHID_DEVICE_INVALID_STATE;
    }
    if(!a->update.waiting) return CTAPHID_DEVICE_OK;
    bool expired=(uint32_t)(now-a->update.started_ms)>=RP2350_UPDATE_TOUCH_TIMEOUT_MS;
    if(!expired && event!=a->update.operation) return CTAPHID_DEVICE_OK;
    uint8_t status=expired ? CTAP_STATUS_USER_ACTION_TIMEOUT : CTAP_STATUS_OK;
    uint64_t operation=a->update.operation;
    rp2350_presence_abort(&a->presence,operation);
    a->update.waiting=false;
    CtaphidDeviceResult result=ctaphid_device_complete_cbor(&a->device,operation,&status,1);
    if(result==CTAPHID_DEVICE_OK && !expired) a->update.approved=true;
    else rp2350_firmware_update_abort(a,operation);
    return result;
}
bool rp2350_firmware_update_ready(const Rp2350Application *a) {
    return rp2350_application_ready(a) && !a->busy && a->update.approved && !a->update.waiting &&
        a->device.transaction_id==a->update.operation && a->device.phase==CTAPHID_DEVICE_IDLE &&
        !a->device.in_flight && !a->device.control_count && !a->store.busy;
}
