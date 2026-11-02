#include "presence.h"
#include "led_wink.h"
#include "protocol/ctaphid_device.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "ctap/ctap_get_info.h"
#include "ctap/ctap_uvm.h"
#include "ctap/cbor_reader.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { uint8_t report[64]; unsigned sent,winks,starts,aborts,aborted_reports; } Recorder;
static bool sent(void *ctx,const uint8_t report[64],uint64_t transfer) {
    Recorder *r=ctx; (void)transfer; memcpy(r->report,report,64); r->sent++; return true;
}
static void wink(void *ctx,uint32_t cid) { (void)cid; ((Recorder *)ctx)->winks++; }
static void start(void *ctx,uint64_t operation,const uint8_t *data,size_t n) {
    (void)operation; (void)data; (void)n; ((Recorder *)ctx)->starts++;
}
static void abort_cbor(void *ctx,uint64_t operation) { (void)operation; ((Recorder *)ctx)->aborts++; }
static void abort_report(void *ctx,uint64_t transfer) { (void)transfer; ((Recorder *)ctx)->aborted_reports++; }
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
static void request_at(CtaphidDevice *d,uint32_t cid,uint8_t cmd,unsigned length,uint8_t value,uint32_t now) {
    uint8_t report[64]={0};
    for(unsigned i=0;i<4;i++) report[i]=(uint8_t)(cid>>(24U-8U*i));
    report[4]=cmd|0x80; report[6]=(uint8_t)length; report[7]=value;
    CtaphidDeviceResult result=ctaphid_device_receive_report(d,report,64,now);
    assert(result==CTAPHID_DEVICE_OK || (cmd==CTAPHID_COMMAND_CANCEL && result==CTAPHID_DEVICE_IGNORED));
    assert(ctaphid_device_poll(d,now)==CTAPHID_DEVICE_OK);
}
static void check_lock(void) {
    Recorder r={0}; CtaphidDevice d;
    CtaphidDeviceConfig config={.submit_report=sent,.transport_context=&r,
        .start_cbor=start,.abort_cbor=abort_cbor,.cbor_context=&r};
    assert(ctaphid_device_init(&d,&config)==CTAPHID_DEVICE_OK);
    uint32_t a=allocate(&d,&r,0x0c),b=allocate(&d,&r,0x0c);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,0,0,101); assert(r.report[7]==3 && !d.lock_channel_id);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,11,102); assert(r.report[7]==2 && !d.lock_channel_id);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,10,103);
    assert(d.lock_channel_id==a && r.report[4]==(0x80|CTAPHID_COMMAND_LOCK) && !r.report[6]);
    request_at(&d,b,CTAPHID_COMMAND_PING,0,0,104); assert(r.report[7]==6);
    request_at(&d,b,CTAPHID_COMMAND_LOCK,1,0,105); assert(r.report[7]==6 && d.lock_channel_id==a);
    request_at(&d,UINT32_MAX,CTAPHID_COMMAND_INIT,8,0,106); assert(r.report[7]==6);
    unsigned before=r.sent; request_at(&d,b,CTAPHID_COMMAND_CANCEL,0,0,107); assert(r.sent==before);
    request_at(&d,a,CTAPHID_COMMAND_INIT,8,0,108); assert(d.lock_channel_id==a);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,1,10000); assert(d.lock_channel_id==a);
    request_at(&d,b,CTAPHID_COMMAND_PING,0,0,10999); assert(r.report[7]==6);
    request_at(&d,b,CTAPHID_COMMAND_PING,0,0,11000); assert(r.report[4]==(0x80|CTAPHID_COMMAND_PING) && !d.lock_channel_id);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,10,11001);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,0,11002); assert(!d.lock_channel_id);
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,1,UINT32_MAX-499U);
    request_at(&d,b,CTAPHID_COMMAND_PING,0,0,499); assert(r.report[7]==6);
    request_at(&d,b,CTAPHID_COMMAND_PING,0,0,500); assert(r.report[4]==(0x80|CTAPHID_COMMAND_PING));
    request_at(&d,a,CTAPHID_COMMAND_LOCK,1,1,501);
    request_at(&d,a,CTAPHID_COMMAND_CBOR,1,0,502); assert(r.starts==1);
    assert(ctaphid_device_poll(&d,1501)==CTAPHID_DEVICE_OK);
    request_at(&d,b,CTAPHID_COMMAND_INIT,8,0,1501); assert(r.report[7]==6 && r.aborts==0);
    request_at(&d,a,CTAPHID_COMMAND_INIT,8,0,1502); assert(r.aborts==1);
    puts("PASS LOCK: bounded ownership, validation, renewal/release, foreign isolation, CANCEL, INIT, wrap and independent transaction lifetime");
}
static void check_initial_progress(void) {
    Recorder r={0}; CtaphidDevice d;
    CtaphidDeviceConfig config={.submit_report=sent,.transport_context=&r,
        .start_cbor=start,.abort_cbor=abort_cbor,.cbor_context=&r};
    assert(ctaphid_device_init(&d,&config)==CTAPHID_DEVICE_OK);
    uint32_t cid=allocate(&d,&r,0x0c);
    unsigned before=r.sent;
    request_at(&d,cid,CTAPHID_COMMAND_CBOR,1,0x04,101);
    assert(r.starts==1 && r.sent==before+1 && d.cbor_running);
    assert(r.report[4]==(0x80|CTAPHID_COMMAND_KEEPALIVE) && r.report[6]==1 &&
        r.report[7]==CTAPHID_STATUS_PROCESSING);
    assert(d.phase==CTAPHID_DEVICE_PROCESSING && d.last_keepalive_ms==101);
    assert(ctaphid_device_poll(&d,200)==CTAPHID_DEVICE_OK && r.sent==before+1);
    assert(ctaphid_device_poll(&d,201)==CTAPHID_DEVICE_OK && r.sent==before+2);
    /* A completion discards unsent progress and sends just its final response. */
    assert(ctaphid_device_set_keepalive(&d,d.transaction_id,CTAPHID_STATUS_UPNEEDED,202)==CTAPHID_DEVICE_OK);
    const uint8_t success=0;
    assert(ctaphid_device_complete_cbor(&d,d.transaction_id,&success,1)==CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&d,202)==CTAPHID_DEVICE_OK && r.sent==before+3);
    assert(r.report[4]==(0x80|CTAPHID_COMMAND_CBOR) && r.report[7]==0 && d.phase==CTAPHID_DEVICE_IDLE);
    assert(ctaphid_device_poll(&d,500)==CTAPHID_DEVICE_OK && r.sent==before+3);
    /* CANCEL still terminates the request after the initial progress report. */
    request_at(&d,cid,CTAPHID_COMMAND_CBOR,1,0x04,501);
    uint64_t cancelled=d.transaction_id;
    request_at(&d,cid,CTAPHID_COMMAND_CANCEL,0,0,502);
    assert(r.aborts==1 && r.report[4]==(0x80|CTAPHID_COMMAND_CBOR) && r.report[7]==0x2d);
    assert(ctaphid_device_complete_cbor(&d,cancelled,&success,1)==CTAPHID_DEVICE_INVALID_STATE);
    /* Advisory progress cannot turn competing-channel backpressure into a
     * dropped request. The already queued reports drain in the same poll. */
    uint8_t report[64]={0};
    for(unsigned i=0;i<4;i++) report[i]=(uint8_t)(cid>>(24U-8U*i));
    report[4]=0x80|CTAPHID_COMMAND_CBOR; report[6]=1; report[7]=0x04;
    assert(ctaphid_device_receive_report(&d,report,64,503)==CTAPHID_DEVICE_OK);
    d.control_count=CTAPHID_DEVICE_CONTROL_REPORTS;
    memset(d.control,0,sizeof(d.control));
    assert(ctaphid_device_poll(&d,503)==CTAPHID_DEVICE_OK && r.starts==3 && d.cbor_running);
    assert(d.control_count==0);
    assert(ctaphid_device_complete_cbor(&d,d.transaction_id,&success,1)==CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&d,504)==CTAPHID_DEVICE_OK && d.phase==CTAPHID_DEVICE_IDLE);
    /* An asynchronous initial keepalive must complete before the final reply;
     * its completion must never release the transaction's ownership. */
    config.asynchronous_transport=true; config.abort_report=abort_report;
    assert(ctaphid_device_init(&d,&config)==CTAPHID_DEVICE_OK);
    request(&d,UINT32_MAX,CTAPHID_COMMAND_INIT,8);
    cid=((uint32_t)r.report[15]<<24)|((uint32_t)r.report[16]<<16)|
        ((uint32_t)r.report[17]<<8)|r.report[18];
    assert(ctaphid_device_report_sent(&d,d.flight_id,true)==CTAPHID_DEVICE_OK);
    request_at(&d,cid,CTAPHID_COMMAND_CBOR,1,0x04,505);
    uint64_t progress_transfer=d.flight_id;
    assert(d.in_flight && r.report[4]==(0x80|CTAPHID_COMMAND_KEEPALIVE));
    assert(ctaphid_device_complete_cbor(&d,d.transaction_id,&success,1)==CTAPHID_DEVICE_OK);
    assert(ctaphid_device_report_sent(&d,progress_transfer,true)==CTAPHID_DEVICE_OK);
    assert(d.phase==CTAPHID_DEVICE_SENDING);
    assert(ctaphid_device_poll(&d,506)==CTAPHID_DEVICE_OK && d.in_flight);
    assert(r.report[4]==(0x80|CTAPHID_COMMAND_CBOR));
    assert(ctaphid_device_report_sent(&d,d.flight_id,true)==CTAPHID_DEVICE_OK && d.phase==CTAPHID_DEVICE_IDLE);
    request_at(&d,cid,CTAPHID_COMMAND_CBOR,1,0x04,507);
    assert(ctaphid_device_report_sent(&d,d.flight_id,false)==CTAPHID_DEVICE_TRANSPORT_FAILED);
    assert(!d.cbor_running && d.phase==CTAPHID_DEVICE_IDLE && r.aborts==2);
    puts("PASS initial progress: immediate PROCESSING, interval, final-response ordering, CANCEL, backpressure, asynchronous ownership and failed transfer");
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
static void check_uvm(void) {
    for(unsigned flags=0;flags<8;flags++) {
        uint8_t out[64];CborWriter w;cbor_writer_init(&w,out,sizeof(out));
        bool up=(flags&1)!=0,pin=(flags&2)!=0,remote=(flags&4)!=0;
        assert(ctap_uvm_write(&w,up,pin,remote));
        CborValue array,entry,method,key,matcher;
        assert(cbor_read_document(out,w.length,&array) && array.major==4 && array.value==(up && pin ? 2 : 1));
        const uint8_t *cursor=array.data,*end=out+w.length;
        for(uint64_t i=0;i<array.value;i++) {
            assert(cbor_read_next(&cursor,end,&entry) && entry.major==4 && entry.value==3);
            const uint8_t *item=entry.data;
            assert(cbor_read_next(&item,end,&method) && cbor_read_next(&item,end,&key) && cbor_read_next(&item,end,&matcher));
            assert(method.value==(up && i==0 ? 1 : pin ? 0x800 : 0x200));
            assert(key.value==(remote ? 0x11 : 1) && matcher.value==1);
        }
    }
    puts("PASS UVM: presence/PIN/silent factors and resident/sealed key protection");
}
static void check_info(void) {
    CtapGetInfoProfile p={.make_credential=true,.hmac_secret=true,.user_presence=true,.max_message_size=CTAP_MESSAGE_CAPACITY};
    uint8_t out[CTAP_GET_INFO_MAX_CBOR_SIZE],unchanged[sizeof(out)]; size_t n=0; CborValue map,v;
    assert(ctap_get_info_encode(&p,out,sizeof(out),&n) && cbor_read_document(out,n,&map));
    assert(!cbor_map_uint(&map,0x1d,&v) && !cbor_map_uint(&map,0x18,&v));
    assert(!cbor_map_uint(&map,0x1c,&v));
    p.pin_uv_auth=true;p.long_touch_reset=true;p.enterprise_capable=true;
    CtaphidCtapBackend backend;
    assert(ctaphid_ctap_backend_init(&backend,&p));
    assert(!backend.profile.pin_uv_auth && !backend.profile.long_touch_reset && !backend.profile.enterprise_capable);
    assert(ctap_get_info_encode(&p,out,sizeof(out),&n) && cbor_read_document(out,n,&map));
    assert(cbor_map_uint(&map,0x1d,&v) && v.major==0 && v.value==63);
    CborValue ep_options;assert(cbor_map_uint(&map,4,&ep_options) && cbor_map_text(&ep_options,"ep",&v) && v.value==20);
    assert(cbor_map_uint(&map,0x1f,&v) && v.major==4 && v.value==4);
    p.enterprise_enabled=true;
    assert(ctap_get_info_encode(&p,out,sizeof(out),&n) && cbor_read_document(out,n,&map));
    assert(cbor_map_uint(&map,4,&ep_options) && cbor_map_text(&ep_options,"ep",&v) && v.value==21);
    assert(cbor_map_uint(&map,0x18,&v) && v.major==7 && v.value==21);
    assert(!cbor_map_uint(&map,0x1b,&v) && !cbor_map_uint(&map,0x1c,&v));
    const uint8_t *cursor=map.data,*end=map.encoded+map.encoded_length;
    uint64_t previous=0;
    for(uint64_t i=0;i<map.value;i++) {
        CborValue key,value;
        assert(cbor_read_next(&cursor,end,&key) && key.major==0 && key.value>previous);
        previous=key.value; assert(cbor_read_next(&cursor,end,&value));
    }
    assert(cursor==end);
    p.resident_credentials=true;p.third_party_payment=true;p.encrypted_identifiers=true;
    p.large_blobs=true;p.usb_transport=true;p.firmware_version=66817;p.ed25519=true;
    assert(ctap_get_info_encode(&p,out,sizeof(out),&n) && cbor_read_document(out,n,&map));
    assert(cbor_map_uint(&map,0x19,&v) && v.major==2 && v.value==32);
    assert(cbor_map_uint(&map,0x1e,&v) && v.major==2 && v.value==32);
    CborValue options;assert(cbor_map_uint(&map,4,&options) && cbor_map_text(&options,"perCredMgmtRO",&v) && v.value==21);
    memcpy(unchanged,out,sizeof(out)); size_t sentinel=99;
    assert(!ctap_get_info_encode(&p,out,1,&sentinel) && sentinel==99 && !memcmp(out,unchanged,sizeof(out)));
    assert(!cbor_map_uint(&map,0x1b,&v) && !cbor_map_uint(&map,0x1c,&v));
    CborValue extensions;assert(cbor_map_uint(&map,2,&extensions));
    const uint8_t *item=extensions.data;
    for(uint64_t i=0;i<extensions.value;i++) {
        assert(cbor_read_next(&item,extensions.encoded+extensions.encoded_length,&v));
        assert(!cbor_text_equal(&v,"pinComplexityPolicy"));
    }
    puts("PASS GetInfo: PIN-bound maximum/reset fields, full CBOR parsing and bounded-output failure preservation");
}
int main(void) { check_wink();check_lock();check_initial_progress();check_presence();check_uvm();check_info(); }
