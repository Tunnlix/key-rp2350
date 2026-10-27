#ifndef CTAP_DEVICE_VERSION_H
#define CTAP_DEVICE_VERSION_H

/* Firmware identity, shared by INIT, GetInfo and the USB binding.
 * This is not the CTAPHID protocol revision or a CTAP conformance claim.
 * Increase the firmware version for each released firmware change. */
#define CTAP_DEVICE_VERSION_MAJOR 1
#define CTAP_DEVICE_VERSION_MINOR 2
#define CTAP_DEVICE_VERSION_BUILD 0
#define CTAP_DEVICE_VERSION_PRERELEASE ""

#define CTAP_DEVICE_VERSION_STRINGIFY_(value) #value
#define CTAP_DEVICE_VERSION_STRINGIFY(value) CTAP_DEVICE_VERSION_STRINGIFY_(value)
#define CTAP_DEVICE_VERSION_STRING CTAP_DEVICE_VERSION_STRINGIFY(CTAP_DEVICE_VERSION_MAJOR) \
    "." CTAP_DEVICE_VERSION_STRINGIFY(CTAP_DEVICE_VERSION_MINOR) \
    "." CTAP_DEVICE_VERSION_STRINGIFY(CTAP_DEVICE_VERSION_BUILD) CTAP_DEVICE_VERSION_PRERELEASE

/* Numeric transports cannot encode prerelease status: inspect the artifact's
 * version string and release manifest to distinguish a candidate from stable. */
/* Monotonic vendor firmware number: major:minor:build, one byte each. */
#define CTAP_DEVICE_FIRMWARE_VERSION ((CTAP_DEVICE_VERSION_MAJOR << 16U) | \
    (CTAP_DEVICE_VERSION_MINOR << 8U) | CTAP_DEVICE_VERSION_BUILD)

/* USB bcdDevice is decimal MM.mp: 1.0.0 is displayed as 1.00.
 * Keep minor/build single-digit until this vendor encoding is revised. */
#if CTAP_DEVICE_VERSION_MAJOR > 99 || CTAP_DEVICE_VERSION_MINOR > 9 || CTAP_DEVICE_VERSION_BUILD > 9
#error "Review the USB version encoding before increasing these version components"
#endif
#define CTAP_DEVICE_USB_BCD (((CTAP_DEVICE_VERSION_MAJOR / 10U) << 12U) | \
    ((CTAP_DEVICE_VERSION_MAJOR % 10U) << 8U) | \
    (CTAP_DEVICE_VERSION_MINOR << 4U) | CTAP_DEVICE_VERSION_BUILD)

#endif
