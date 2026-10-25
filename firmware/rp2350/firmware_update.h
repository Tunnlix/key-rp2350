#ifndef RP2350_FIRMWARE_UPDATE_H
#define RP2350_FIRMWARE_UPDATE_H

#include "protocol/ctaphid_device.h"

/* Target-only vendor CTAP command, carried by the existing FIDO HID interface.
 * No new USB interface or portable-core command is introduced. */
#define RP2350_UPDATE_COMMAND 0x50U
#define RP2350_UPDATE_PROTOCOL 1U
#define RP2350_UPDATE_TOUCH_TIMEOUT_MS 30000U
#define RP2350_UPDATE_HOLD_MS 5000U
#define RP2350_UPDATE_STARTUP_TIMEOUT_MS 30000U

typedef struct {
    uint64_t operation;
    uint32_t started_ms;
    bool waiting, approved;
} Rp2350FirmwareUpdate;

/* Evaluated before storage/entropy/USB startup. Only an initially held button
 * can arm this gesture. Hold continuously, then release; stuck input times out. */
typedef enum {
    RP2350_BOOT_NORMAL = 0,
    RP2350_BOOT_HOLD,
    RP2350_BOOT_RELEASE,
    RP2350_BOOT_ENTER
} Rp2350BootGestureResult;
typedef struct {
    uint32_t started_ms, changed_ms, held_ms;
    bool pressed;
    Rp2350BootGestureResult result;
} Rp2350BootGesture;
void rp2350_boot_gesture_init(Rp2350BootGesture *, bool pressed, uint32_t now_ms);
Rp2350BootGestureResult rp2350_boot_gesture_sample(Rp2350BootGesture *, bool pressed, uint32_t now_ms);

struct Rp2350Application;
void rp2350_firmware_update_start(struct Rp2350Application *, uint64_t,
    const uint8_t *, size_t);
void rp2350_firmware_update_abort(struct Rp2350Application *, uint64_t);
CtaphidDeviceResult rp2350_firmware_update_poll(struct Rp2350Application *, uint64_t event, uint32_t now_ms);
/* True only after physical consent AND successful final response transmission.
 * The target loop must quiesce USB and wipe runtime secrets before ROM entry. */
bool rp2350_firmware_update_ready(const struct Rp2350Application *);
#endif
