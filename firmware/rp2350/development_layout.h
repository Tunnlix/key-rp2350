#ifndef RP2350_DEVELOPMENT_LAYOUT_H
#define RP2350_DEVELOPMENT_LAYOUT_H
#include "pico.h"
/* Compile-time model boundary only. This configuration value is NOT a flash
 * identification result and must never enable physical program/erase. */
#if !defined(PICO_FLASH_SIZE_BYTES) || PICO_FLASH_SIZE_BYTES != 0x200000U
#error "Review the development linker/store layout before changing configured flash size"
#endif
#endif
