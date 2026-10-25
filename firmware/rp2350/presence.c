#include "presence.h"
#include <stddef.h>
void rp2350_presence_init(Rp2350Presence *p, bool pressed, uint32_t now) {
    if (p == NULL) return;
    *p = (Rp2350Presence){.initialized=true, .raw_pressed=pressed,
        .stable_pressed=pressed, .changed_ms=now};
}
void rp2350_presence_begin(Rp2350Presence *p, uint64_t id, uint32_t now) {
    if (p == NULL || !p->initialized || id == 0) return;
    p->operation_id=id; p->started_ms=now; p->active=true;
    p->armed=!p->raw_pressed && !p->stable_pressed;
}
void rp2350_presence_abort(Rp2350Presence *p, uint64_t id) {
    if (p != NULL && p->active && p->operation_id == id) {
        p->active=false; p->armed=false;
    }
}
uint64_t rp2350_presence_sample(Rp2350Presence *p, bool pressed, uint32_t now) {
    if (p == NULL || !p->initialized) return 0;
    if (pressed != p->raw_pressed) {
        p->raw_pressed=pressed; p->changed_ms=now;
    }
    if (p->raw_pressed == p->stable_pressed ||
        (uint32_t)(now-p->changed_ms) < RP2350_DEBOUNCE_MS) return 0;
    p->stable_pressed=p->raw_pressed;
    if (!p->active) return 0;
    if (!p->stable_pressed) { p->armed=true; return 0; }
    if (!p->armed) return 0;
    p->armed=false; p->active=false;
    return p->operation_id;
}
