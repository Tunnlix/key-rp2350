#include "firmware_update.h"
#include "presence.h"

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

void rp2350_update_gesture_init(Rp2350UpdateGesture *g, bool pressed, uint32_t now) {
    *g = (Rp2350UpdateGesture){.started_ms=now, .changed_ms=now,
        .raw_pressed=pressed, .stable_pressed=pressed, .armed=!pressed};
}

Rp2350UpdateGestureResult rp2350_update_gesture_sample(Rp2350UpdateGesture *g, bool pressed, uint32_t now) {
    if((uint32_t)(now-g->started_ms) >= RP2350_UPDATE_TOUCH_TIMEOUT_MS)
        return RP2350_UPDATE_EXPIRED;
    if(pressed != g->raw_pressed) {
        g->raw_pressed = pressed;
        g->changed_ms = now;
    }
    if(g->raw_pressed != g->stable_pressed &&
        (uint32_t)(now-g->changed_ms) >= RP2350_DEBOUNCE_MS) {
        g->stable_pressed = g->raw_pressed;
        if(!g->stable_pressed) {
            /* Measure through the observed release, not its debounce delay. */
            if(g->holding && (g->release_ready ||
                (uint32_t)(g->changed_ms-g->held_ms) >= RP2350_UPDATE_PC_HOLD_MS))
                return RP2350_UPDATE_CONFIRMED;
            g->armed = true;
            g->holding = g->release_ready = false;
        } else if(g->armed) {
            g->held_ms = now;
            g->holding = true;
            g->armed = false;
        }
    }
    if(g->holding && g->raw_pressed &&
        (uint32_t)(now-g->held_ms) >= RP2350_UPDATE_PC_HOLD_MS)
        g->release_ready = true;
    return g->release_ready ? RP2350_UPDATE_RELEASE : RP2350_UPDATE_WAIT;
}
