#ifndef CTAP_CONFIG_H
#define CTAP_CONFIG_H

/* Build settings: override with compiler -D options or the same CMake cache
 * names. Use identical values for the library, application and providers:
 * these capacities affect public struct layouts. Larger values use more RAM.
 * Wire/crypto constants and PIN security limits are not build settings. */
#ifndef CTAP_MESSAGE_CAPACITY
#define CTAP_MESSAGE_CAPACITY 1024U
#endif
#ifndef CTAP_RESIDENT_CAPACITY
#define CTAP_RESIDENT_CAPACITY 16U
#endif
#ifndef CTAP_TOUCH_TIMEOUT_MS
#define CTAP_TOUCH_TIMEOUT_MS 30000U
#endif

/* CTAP requires at least 1024 bytes; 64-byte HID framing permits at most 7609. */
#if CTAP_MESSAGE_CAPACITY < 1024 || CTAP_MESSAGE_CAPACITY > 7609
#error "CTAP_MESSAGE_CAPACITY must be between 1024 and 7609"
#endif
#if CTAP_RESIDENT_CAPACITY < 1 || CTAP_RESIDENT_CAPACITY > 255
#error "CTAP_RESIDENT_CAPACITY must be between 1 and 255"
#endif
#if CTAP_TOUCH_TIMEOUT_MS < 10000 || CTAP_TOUCH_TIMEOUT_MS > 2147483647
#error "CTAP_TOUCH_TIMEOUT_MS must be between 10000 and 2147483647"
#endif

#endif
