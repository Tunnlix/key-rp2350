#ifndef RP2350_BOARD_ENTROPY_H
#define RP2350_BOARD_ENTROPY_H
#include "entropy.h"
/* Candidate hardware path. Must be exercised/characterized on the actual board
 * before accepting real credentials. No pico_rand dependency or fallback. */
bool rp2350_board_entropy_init(Rp2350Entropy *);
#endif
