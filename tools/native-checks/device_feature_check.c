#include "presence.h"
#include "led_wink.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

static void check_wink_animation(void) {
    Rp2350Wink animation={0}; rp2350_wink_begin(&animation,UINT32_MAX-100U);
    assert(rp2350_wink_color(&animation,true,UINT32_MAX-100U)!=0);
    rp2350_wink_begin(&animation,99); assert(animation.started_ms==UINT32_MAX-100U);
    assert(rp2350_wink_color(&animation,true,1099)==0 && !animation.active);
    rp2350_wink_begin(&animation,2899); assert(animation.active);
    assert(!rp2350_wink_color(&animation,false,2900) && !animation.active);
    puts("PASS WINK animation: bounded timing, wrap and priority");
}
static void check_presence(void) {
    Rp2350Presence p;
    rp2350_presence_init(&p,false,0); rp2350_presence_begin_hold(&p,1,0,5000);
    assert(!rp2350_presence_sample(&p,true,10));
    assert(!rp2350_presence_sample(&p,true,30));
    assert(!rp2350_presence_sample(&p,true,5029));
    assert(rp2350_presence_sample(&p,true,5030)==1);
    assert(!rp2350_presence_sample(&p,true,6000));
    /* A pre-held button must be released before it can authorize an operation. */
    rp2350_presence_init(&p,true,0); rp2350_presence_begin_hold(&p,2,0,5000);
    assert(!rp2350_presence_sample(&p,true,9000));
    assert(!rp2350_presence_sample(&p,false,9001)); assert(!rp2350_presence_sample(&p,false,9021));
    assert(!rp2350_presence_sample(&p,true,9040)); assert(!rp2350_presence_sample(&p,true,9060));
    /* Even a raw release interrupts the hold; brief bounce cannot join holds. */
    assert(!rp2350_presence_sample(&p,false,14059)); assert(!rp2350_presence_sample(&p,true,14060));
    assert(!rp2350_presence_sample(&p,true,20000));
    assert(!rp2350_presence_sample(&p,false,20001)); assert(!rp2350_presence_sample(&p,false,20021));
    assert(!rp2350_presence_sample(&p,true,20030)); assert(!rp2350_presence_sample(&p,true,20050));
    rp2350_presence_abort(&p,2); assert(!rp2350_presence_sample(&p,true,30000));
    rp2350_presence_init(&p,false,UINT32_MAX-100);
    rp2350_presence_begin_hold(&p,3,UINT32_MAX-100,5000);
    assert(!rp2350_presence_sample(&p,true,UINT32_MAX-80));
    assert(!rp2350_presence_sample(&p,true,UINT32_MAX-60));
    assert(!rp2350_presence_sample(&p,true,4938));
    assert(rp2350_presence_sample(&p,true,4939)==3);
    rp2350_presence_init(&p,false,0); rp2350_presence_begin(&p,4,0);
    assert(!rp2350_presence_sample(&p,true,1)); assert(rp2350_presence_sample(&p,true,21)==4);
    puts("PASS long touch: 5-second boundary, short/bouncing/pre-held/cancelled presses, one-shot consent and wrapping clock");
}
int main(void) { check_wink_animation();check_presence(); }
