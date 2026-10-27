#include "tusb.h"
#include "pico/unique_id.h"
#include "ctap_device_version.h"
#include <string.h>

/* pid.codes private-test pair: https://pid.codes/1209/0001/
 * Shared, not universally unique. In-house testing only; do not redistribute,
 * sell or manufacture devices using this pair. Obtain an allocation first.
 * Product naming and open-source licensing do not establish VID/PID ownership. */
static const tusb_desc_device_t device_descriptor = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x1209,
    .idProduct = 0x0001,
    .bcdDevice = CTAP_DEVICE_USB_BCD,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1
};

/* CTAP2 uses the same FIDO HID usage page/collection as the historical U2F
 * descriptor. This declares only byte reports, not CTAP1 support. No report ID. */
static const uint8_t report_descriptor[] = {
    0x06, 0xd0, 0xf1, /* Usage Page (FIDO Alliance) */
    0x09, 0x01,       /* Usage (Authenticator) */
    0xa1, 0x01,       /* Collection (Application) */
    0x09, 0x20,       /* Usage (Data In) */
    0x15, 0x00,       /* Logical Minimum (0) */
    0x26, 0xff, 0x00, /* Logical Maximum (255) */
    0x75, 0x08,       /* Report Size (8) */
    0x95, 0x40,       /* Report Count (64) */
    0x81, 0x02,       /* Input (Data, Variable, Absolute) */
    0x09, 0x21,       /* Usage (Data Out) */
    0x95, 0x40,       /* Report Count (64) */
    0x91, 0x02,       /* Output (Data, Variable, Absolute) */
    0xc0
};

static const uint8_t configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN, 0, 100),
    TUD_HID_INOUT_DESCRIPTOR(0, 2, HID_ITF_PROTOCOL_NONE,
        sizeof(report_descriptor), 0x01, 0x81, 64, 5)
};

const uint8_t *tud_descriptor_device_cb(void) {
    return (const uint8_t *)&device_descriptor;
}
const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
    return index == 0 ? configuration_descriptor : NULL;
}
const uint8_t *tud_hid_descriptor_report_cb(uint8_t instance) {
    return instance == 0 ? report_descriptor : NULL;
}
const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t language) {
    (void)language;
    static uint16_t descriptor[33];
    static char serial[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2 + 1];
    const char *value;
    if(index == 0) {
        descriptor[0] = (TUSB_DESC_STRING << 8) | 4;
        descriptor[1] = 0x0409;
        return descriptor;
    }
    if(index == 1) value = "Tunnlix";
    else if(index == 2) value = "Key";
    else if(index == 3) {
        pico_get_unique_board_id_string(serial, sizeof(serial));
        value = serial;
    } else return NULL;
    size_t length = strlen(value);
    if(length > 32) return NULL;
    descriptor[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * length + 2));
    for(size_t i = 0; i < length; ++i) descriptor[i + 1] = (uint8_t)value[i];
    return descriptor;
}
