#ifndef RP2350_PRESENCE_H
#define RP2350_PRESENCE_H
#include <stdbool.h>
#include <stdint.h>
/* Board-independent input adapter. GPIO sampling and event delivery stay in
 * the serialized firmware loop. A waiting operation never consumes a held key. */
#define RP2350_BUTTON_GPIO 26U
#define RP2350_DEBOUNCE_MS 20U
typedef struct {
    bool initialized, raw_pressed, stable_pressed, armed, active;
    uint32_t changed_ms, started_ms;
    uint64_t operation_id;
} Rp2350Presence;
void rp2350_presence_init(Rp2350Presence *, bool pressed, uint32_t now_ms);
void rp2350_presence_begin(Rp2350Presence *, uint64_t operation_id, uint32_t now_ms);
void rp2350_presence_abort(Rp2350Presence *, uint64_t operation_id);
/* Return operation ID once for a fresh debounced press; zero means no event. */
uint64_t rp2350_presence_sample(Rp2350Presence *, bool pressed, uint32_t now_ms);
#endif
