#ifndef RP2350_STORAGE_BYTES_INTERNAL_H
#define RP2350_STORAGE_BYTES_INTERNAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
static inline uint16_t store_u16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0]|((uint16_t)p[1]<<8)); }
static inline uint32_t store_u32(const uint8_t *p) { return (uint32_t)store_u16(p)|((uint32_t)store_u16(p+2)<<16); }
static inline uint64_t store_u64(const uint8_t *p) { return store_u32(p)|((uint64_t)store_u32(p+4)<<32); }
static inline void store_put16(uint8_t *p,uint16_t n) { p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); }
static inline void store_put32(uint8_t *p,uint32_t n) { store_put16(p,(uint16_t)n); store_put16(p+2,(uint16_t)(n>>16)); }
static inline void store_put64(uint8_t *p,uint64_t n) { store_put32(p,(uint32_t)n); store_put32(p+4,(uint32_t)(n>>32)); }
static inline bool store_nonzero(const uint8_t *p,size_t n) { uint8_t v=0; for(size_t i=0;i<n;i++) v|=p[i]; return v!=0; }
static inline bool store_zero(const uint8_t *p,size_t n) { return !store_nonzero(p,n); }
static inline bool store_equal(const uint8_t *a,const uint8_t *b,size_t n) { uint8_t v=0; for(size_t i=0;i<n;i++) v|=a[i]^b[i]; return v==0; }
#endif
