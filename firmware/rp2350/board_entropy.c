#include "board_entropy.h"
#include "hardware/structs/trng.h"
#include "pico/time.h"
static uint32_t now_ms(void *ctx) { (void)ctx; return to_ms_since_boot(get_absolute_time()); }
static bool start(void *ctx) {
    (void)ctx;
    /* Preserve errors from an earlier collection, including SDK/ROM use.
     * Dedicated single-core owner, no interrupt user or pico_rand calls. */
    if ((trng_hw->rng_isr&0x0eU) || trng_hw->rnd_source_enable) return false;
    trng_hw->trng_debug_control=0; /* all built-in checks and decorrelator ON */
    trng_hw->rng_debug_en_input=0;
    trng_hw->trng_config=0;
    trng_hw->sample_cnt1=100;
    trng_hw->rng_imr=0x0f; /* polling only */
    trng_hw->rng_icr=1;
    trng_hw->rnd_source_enable=1;
    return true;
}
static uint32_t status(void *ctx) {
    (void)ctx;
    /* Detect another user changing the configuration while collecting. */
    if (trng_hw->trng_debug_control || trng_hw->rng_debug_en_input ||
        trng_hw->sample_cnt1!=100 || trng_hw->trng_config!=0) return 0x0e;
    return trng_hw->rng_isr;
}
static uint32_t word(void *ctx,size_t i) { (void)ctx; return trng_hw->ehr_data[i]; }
static void stop(void *ctx) { (void)ctx; trng_hw->rnd_source_enable=0; }
bool rp2350_board_entropy_init(Rp2350Entropy *p) {
    Rp2350EntropyIo io={NULL,start,status,word,stop,now_ms};
    return rp2350_entropy_init(p,&io);
}
