#include "presence.h"
#include "led_wink.h"
#include "protocol/ctaphid_device.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "ctap/ctap_get_info.h"
#include "ctap/cbor_reader.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { uint8_t report[64]; unsigned sent,winks,starts,aborts; } Recorder;
static bool sent(void *ctx,const uint8_t report[64],uint64_t transfer) {
    Recorder *r=ctx; (void)transfer; memcpy(r->report,report,64); r->sent++; return true;
}
static void wink(void *ctx,uint32_t cid) { (void)cid; ((Recorder *)ctx)->winks++; }
static void start(void *ctx,uint64_t operation,const uint8_t *data,size_t n) {
    (void)operation; (void)data; (void)n; ((Recorder *)ctx)->starts++;
}
static void abort_cbor(void *ctx,uint64_t operation) { (void)operation; ((Recorder *)ctx)->aborts++; }
static void request(CtaphidDevice *d,uint32_t cid,uint8_t command,unsigned length) {
    uint8_t report[64]={0};
    for(unsigned i=0;i<4;i++) report[i]=(uint8_t)(cid>>(24U-8U*i));
    report[4]=command|0x80; report[5]=(uint8_t)(length>>8); report[6]=(uint8_t)length;
    assert(ctaphid_device_receive_report(d,report,64,100)==CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(d,100)==CTAPHID_DEVICE_OK);
}
static uint32_t allocate(CtaphidDevice *d,Recorder *r,unsigned capabilities) {
    request(d,UINT32_MAX,CTAPHID_COMMAND_INIT,8);
    assert(r->report[4]==(0x80|CTAPHID_COMMAND_INIT) && r->report[23]==capabilities);
    return ((uint32_t)r->report[15]<<24)|((uint32_t)r->report[16]<<16)|
        ((uint32_t)r->report[17]<<8)|r->report[18];
}
static void check_wink(void) {
    Recorder r={0}; CtaphidDevice d;
    CtaphidDeviceConfig config={.submit_report=sent,.transport_context=&r,
        .wink_action=wink,.wink_context=&r,.start_cbor=start,.abort_cbor=abort_cbor,.cbor_context=&r};
    assert(ctaphid_device_init(&d,&config)==CTAPHID_DEVICE_OK);
    uint32_t a=allocate(&d,&r,0x0d),b=allocate(&d,&r,0x0d);
    request(&d,a,CTAPHID_COMMAND_WINK,0);
    assert(r.winks==1 && r.report[4]==(0x80|CTAPHID_COMMAND_WINK) && !r.report[5] && !r.report[6]);
    request(&d,a,CTAPHID_COMMAND_WINK,1); assert(r.winks==1 && r.report[7]==3);
    request(&d,0x12345678,CTAPHID_COMMAND_WINK,0); assert(r.winks==1 && r.report[7]==0x0b);
    request(&d,a,CTAPHID_COMMAND_CBOR,1); assert(r.starts==1);
    request(&d,b,CTAPHID_COMMAND_WINK,0); assert(r.winks==1 && r.report[7]==6);
    request(&d,a,CTAPHID_COMMAND_INIT,8); assert(r.aborts==1);
    request(&d,a,CTAPHID_COMMAND_WINK,0); assert(r.winks==2);
    config.wink_action=NULL;
    assert(ctaphid_device_init(&d,&config)==CTAPHID_DEVICE_OK);
    a=allocate(&d,&r,0x0c); request(&d,a,CTAPHID_COMMAND_WINK,0);
    assert(r.winks==2 && r.report[7]==1);
    Rp2350Wink animation={0}; rp2350_wink_begin(&animation,UINT32_MAX-100U);
    assert(rp2350_wink_color(&animation,true,UINT32_MAX-100U)!=0);
    rp2350_wink_begin(&animation,99); assert(animation.started_ms==UINT32_MAX-100U);
    assert(rp2350_wink_color(&animation,true,1099)==0 && !animation.active);
    rp2350_wink_begin(&animation,2899); assert(animation.active);
    assert(!rp2350_wink_color(&animation,false,2900) && !animation.active);
    puts("PASS WINK: actual HID dispatch/capabilities/invalid payload/CID/busy/abort; bounded wrapping animation and priority");
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
static void check_info(void) {
    CtapGetInfoProfile p={.make_credential=true,.hmac_secret=true,.user_presence=true,.max_message_size=1024};
    uint8_t out[CTAP_GET_INFO_MAX_CBOR_SIZE],unchanged[sizeof(out)]; size_t n=0; CborValue map,v;
    assert(ctap_get_info_encode(&p,out,sizeof(out),&n) && cbor_read_document(out,n,&map));
    assert(!cbor_map_uint(&map,0x1d,&v) && !cbor_map_uint(&map,0x18,&v));
    p.pin_uv_auth=true;p.long_touch_reset=true;
    CtaphidCtapBackend backend;
    assert(ctaphid_ctap_backend_init(&backend,&p));
    assert(!backend.profile.pin_uv_auth && !backend.profile.long_touch_reset);
    assert(ctap_get_info_encode(&p,out,sizeof(out),&n) && cbor_read_document(out,n,&map));
    assert(cbor_map_uint(&map,0x1d,&v) && v.major==0 && v.value==63);
    assert(cbor_map_uint(&map,0x18,&v) && v.major==7 && v.value==21);
    const uint8_t *cursor=map.data,*end=map.encoded+map.encoded_length;
    uint64_t previous=0;
    for(uint64_t i=0;i<map.value;i++) {
        CborValue key,value;
        assert(cbor_read_next(&cursor,end,&key) && key.major==0 && key.value>previous);
        previous=key.value; assert(cbor_read_next(&cursor,end,&value));
    }
    assert(cursor==end);
    memcpy(unchanged,out,sizeof(out)); size_t sentinel=99;
    assert(!ctap_get_info_encode(&p,out,1,&sentinel) && sentinel==99 && !memcmp(out,unchanged,sizeof(out)));
    puts("PASS GetInfo: PIN-bound maximum/reset fields, full CBOR parsing and bounded-output failure preservation");
}
int main(void) { check_wink();check_presence();check_info(); }
