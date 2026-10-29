#include "crypto.h"
#include "entropy.h"
#include "status_led.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static unsigned state=192837,calls;
static bool fail_entropy;
typedef struct {
    unsigned blocks,clock,status,stops;
    bool fail_start, freeze_clock, repeat, zero, ones, post_read_fault;
} EntropyModel;
static bool start_entropy(void *ctx) {
    EntropyModel *m=ctx;
    m->blocks++;
    return !m->fail_start;
}
static uint32_t entropy_status(void *ctx) { return ((EntropyModel *)ctx)->status; }
static uint32_t entropy_word(void *ctx,size_t i) {
    EntropyModel *m=ctx; uint32_t word=0;
    if(m->post_read_fault && i==5) m->status=8;
    if(m->zero) return 0;
    if(m->ones) return UINT32_MAX;
    for(unsigned j=0;j<4;j++) word|=(uint32_t)(uint8_t)((m->repeat ? 0 : m->blocks-1)*24+i*4+j+1)<<(j*8);
    return word;
}
static void stop_entropy(void *ctx) { ((EntropyModel *)ctx)->stops++; }
static uint32_t entropy_clock(void *ctx) {
    EntropyModel *m=ctx;
    return m->freeze_clock ? m->clock : m->clock++;
}
typedef struct {
    EntropyModel base;
    unsigned pending, acknowledgements, words, after_status;
    bool per_block, refuse, expire;
} RecoveryModel;
static bool recovery_start(void *ctx) {
    RecoveryModel *m=ctx;
    if(m->pending || m->per_block) m->base.status=4;
    return start_entropy(&m->base);
}
static uint32_t recovery_word(void *ctx,size_t i) {
    RecoveryModel *m=ctx; m->words++;
    return entropy_word(&m->base,i);
}
static bool recovery_clear(void *ctx) {
    RecoveryModel *m=ctx;
    assert(m->base.status==4);
    m->acknowledgements++;
    if(m->refuse) return false;
    if(m->pending) m->pending--;
    m->base.status=m->pending ? 4 : m->after_status;
    if(m->expire) m->base.clock+=RP2350_ENTROPY_TIMEOUT_MS;
    return true;
}
static void check_crngt_recovery(void) {
    for(unsigned scenario=0;scenario<15;scenario++) {
        RecoveryModel m={.base={.status=1},.pending=1,.after_status=1};
        bool success=false;
        Rp2350EntropyFault expected=RP2350_ENTROPY_FAULT_STATUS;
        unsigned expected_clears=1, expected_words=0;
        size_t requested=32;
        switch(scenario) {
        case 0: success=true; expected_words=12; break;
        case 1: m.pending=3; success=true; expected_clears=3; expected_words=12; break;
        case 2: m.pending=4; expected_clears=3; break;
        case 3: m.per_block=true; requested=96; expected_clears=3; expected_words=18; break;
        case 4: m.refuse=true; break;
        case 5: m.expire=true; expected=RP2350_ENTROPY_FAULT_TIMEOUT; break;
        case 6: m.after_status=2; break;
        case 7: m.after_status=8; break;
        case 8: m.after_status=5; break; /* Never accept VALID + CRNGT. */
        case 9: m.after_status=RP2350_ENTROPY_CONFIG_ERROR|1U; expected=RP2350_ENTROPY_FAULT_CONFIG; break;
        case 10: m.base.repeat=true; expected=RP2350_ENTROPY_FAULT_REPEATED; expected_words=12; break;
        case 11: m.base.post_read_fault=true; expected_words=6; break;
        case 12: m.base.fail_start=true; expected=RP2350_ENTROPY_FAULT_START; expected_clears=0; break;
        case 13: m.base.status=5; m.pending=0; expected_clears=0; break;
        case 14: m.after_status=0; expected=RP2350_ENTROPY_FAULT_TIMEOUT; break;
        }
        Rp2350EntropyIo io={&m,recovery_start,entropy_status,recovery_word,
            stop_entropy,entropy_clock,recovery_clear};
        Rp2350Entropy source; uint8_t bytes[96];
        assert(rp2350_entropy_init(&source,&io));
        memset(bytes,0xff,sizeof(bytes));
        int result=rp2350_entropy_read(&source,bytes,requested);
        assert(m.acknowledgements==expected_clears && m.words==expected_words);
        if(success) {
            assert(result==0 && !source.faulted && source.crngt_retries==expected_clears);
            for(size_t i=0;i<requested;i++) assert(bytes[i]==i+1);
        } else {
            assert(result!=0 && source.faulted && source.failure==expected);
            assert(source.available==0 && m.base.stops>0);
            for(size_t i=0;i<requested;i++) assert(bytes[i]==0);
            for(size_t i=0;i<sizeof(source.previous);i++) assert(source.previous[i]==0);
            unsigned starts=m.base.blocks,clears=m.acknowledgements;
            assert(rp2350_entropy_read(&source,bytes,requested)!=0);
            assert(m.base.blocks==starts && m.acknowledgements==clears);
        }
    }
    /* A latched fault before cached delivery is never acknowledged. */
    RecoveryModel m={.base={.status=1},.after_status=1};
    Rp2350EntropyIo io={&m,recovery_start,entropy_status,recovery_word,
        stop_entropy,entropy_clock,recovery_clear};
    Rp2350Entropy source; uint8_t bytes[4];
    assert(rp2350_entropy_init(&source,&io));
    assert(rp2350_entropy_read(&source,bytes,1)==0 && source.available==23);
    m.base.status=4;
    assert(rp2350_entropy_read(&source,bytes,sizeof(bytes))!=0 && source.faulted);
    assert(m.acknowledgements==0 && source.failure==RP2350_ENTROPY_FAULT_STATUS);
    for(size_t i=0;i<sizeof(bytes);i++) assert(bytes[i]==0);
    puts("CRNGT: bounded fresh collection recovery, shared request budget, unchanged deadline; other failures remain terminal");
}
static void check_entropy_faults(void) {
    /* Exercise failures at start, polling, buffered delivery and after the last
     * EHR read. No output (including a partial earlier block) may escape. */
    for(unsigned scenario=0;scenario<13;scenario++) {
        EntropyModel m={.status=1};
        Rp2350EntropyIo io={&m,start_entropy,entropy_status,entropy_word,stop_entropy,entropy_clock,NULL};
        Rp2350Entropy source;
        assert(rp2350_entropy_init(&source,&io));
        Rp2350EntropyFault expected=RP2350_ENTROPY_FAULT_STATUS;
        unsigned expected_status=1;
        size_t requested=32;
        switch(scenario) {
        case 0: m.fail_start=true; m.status=4; expected_status=4; expected=RP2350_ENTROPY_FAULT_START; break;
        case 1: m.status=2; expected_status=2; break;
        case 2: m.status=4; expected_status=4; break;
        case 3: m.status=8; expected_status=8; break;
        case 4: m.status=15; expected_status=15; break;
        case 5: m.status=0; expected_status=0; expected=RP2350_ENTROPY_FAULT_TIMEOUT; break;
        case 6: m.status=0; m.freeze_clock=true; expected_status=0; expected=RP2350_ENTROPY_FAULT_POLL_LIMIT; break;
        case 7: m.repeat=true; expected=RP2350_ENTROPY_FAULT_REPEATED; break;
        case 8: m.zero=true; expected=RP2350_ENTROPY_FAULT_STUCK; break;
        case 9: m.ones=true; expected=RP2350_ENTROPY_FAULT_STUCK; break;
        case 10: m.post_read_fault=true; expected_status=8; break;
        case 11: m.status=RP2350_ENTROPY_CONFIG_ERROR|1U; expected_status=m.status; expected=RP2350_ENTROPY_FAULT_CONFIG; break;
        case 12: m.fail_start=true; m.status=RP2350_ENTROPY_CONFIG_ERROR|4U; expected_status=m.status; expected=RP2350_ENTROPY_FAULT_CONFIG; break;
        }
        uint8_t bytes[32]; memset(bytes,0xff,sizeof(bytes));
        assert(rp2350_entropy_read(&source,bytes,requested)!=0);
        assert(source.faulted && source.failure==expected && source.last_status==expected_status);
        assert(source.available==0 && m.stops>0);
        for(size_t i=0;i<requested;i++) assert(bytes[i]==0);
        for(size_t i=0;i<sizeof(source.previous);i++) assert(source.previous[i]==0);
        unsigned starts=m.blocks, stops=m.stops;
        m.status=1; m.fail_start=false;
        memset(bytes,0xff,sizeof(bytes));
        assert(rp2350_entropy_read(&source,bytes,requested)!=0);
        assert(source.failure==expected && source.last_status==expected_status);
        assert(m.blocks==starts && m.stops==stops);
        for(size_t i=0;i<requested;i++) assert(bytes[i]==0);
    }
    /* Configuration changes and hardware failures also invalidate unused bytes. */
    for(unsigned config=0;config<2;config++) {
        EntropyModel m={.status=1};
        Rp2350EntropyIo io={&m,start_entropy,entropy_status,entropy_word,stop_entropy,entropy_clock,NULL};
        Rp2350Entropy source; uint8_t bytes[8];
        assert(rp2350_entropy_init(&source,&io));
        assert(rp2350_entropy_read(&source,bytes,1)==0 && source.available==23);
        m.status=config ? RP2350_ENTROPY_CONFIG_ERROR|1U : 4U;
        assert(rp2350_entropy_read(&source,bytes,sizeof(bytes))!=0);
        assert(source.last_status==m.status && source.available==0 && m.blocks==1);
        assert(source.failure==(config ? RP2350_ENTROPY_FAULT_CONFIG : RP2350_ENTROPY_FAULT_STATUS));
        for(size_t i=0;i<sizeof(bytes);i++) assert(bytes[i]==0);
    }
    puts("Entropy: adapters without recovery retain every fault, wipe output and latch closed");
}
static void check_fault_led(void) {
    /* Count complete visible pulses and their width over every representable
     * diagnostic cycle, including status zero and simultaneous health flags. */
    assert(RP2350_ENTROPY_FAULT_CONFIG==7);
    for(unsigned detail=1;detail<=7;detail++) for(unsigned status=0;status<16;status++) {
        unsigned pulses[3]={0},on_ms[3]={0}; uint32_t previous=0;
        uint32_t cycle=(3U+detail+status+1U)*400U+4400U;
        for(uint32_t ms=0;ms<cycle;ms++) {
            uint32_t color=rp2350_fault_led_color(RP2350_FAULT_ENTROPY,(uint8_t)detail,(uint8_t)status,ms);
            if(color) {
                unsigned index=color==0x100000U ? 0 : color==0x100600U ? 1 : 2;
                assert(index!=2 || color==0x001010U);
                if(color!=previous) pulses[index]++;
                on_ms[index]++;
            }
            previous=color;
        }
        assert(pulses[0]==3 && pulses[1]==detail && pulses[2]==status+1);
        for(unsigned i=0;i<3;i++) assert(on_ms[i]==pulses[i]*150U);
        assert(previous==0 && rp2350_fault_led_color(RP2350_FAULT_ENTROPY,(uint8_t)detail,(uint8_t)status,cycle)==0x100000U);
    }
    for(unsigned fault=1;fault<=7;fault++) {
        unsigned pulses=0; uint32_t previous=0;
        for(uint32_t ms=0;ms<fault*400U+1400U;ms++) {
            uint32_t color=rp2350_fault_led_color((Rp2350Fault)fault,0,0,ms);
            if(color && color!=previous) pulses++;
            previous=color;
        }
        assert(pulses==fault);
    }
    puts("LED: entropy reason/status groups are countable; original category-only patterns preserved");
}
static void check_entropy_blocks(void) {
    EntropyModel m={.status=1};
    Rp2350EntropyIo io={&m,start_entropy,entropy_status,entropy_word,stop_entropy,entropy_clock,NULL};
    Rp2350Entropy source;
    assert(rp2350_entropy_init(&source,&io));
    uint8_t bytes[96];
    for(unsigned i=0;i<3;i++) assert(rp2350_entropy_read(&source,bytes+i*32,32)==0);
    assert(m.blocks==4 && source.blocks==4); /* Previously six blocks. */
    for(unsigned i=0;i<sizeof(bytes);i++) assert(bytes[i]==i+1);
    assert(rp2350_entropy_read(&source,bytes,1)==0 && source.available==23);
    m.status=2; memset(bytes,0xff,sizeof(bytes));
    assert(rp2350_entropy_read(&source,bytes,16)!=0 && source.faulted && source.available==0);
    for(unsigned i=0;i<16;i++) assert(bytes[i]==0);
    m.status=0; assert(rp2350_entropy_init(&source,&io));
    assert(rp2350_entropy_read(&source,bytes,16)!=0 && source.failure==RP2350_ENTROPY_FAULT_TIMEOUT);
    puts("Entropy: unique buffered bytes use 4 blocks instead of 6; cached health fault and timeout fail closed");
}
static int entropy(void *ctx,unsigned char *out,size_t n) {
    (void)ctx; calls++;
    if(fail_entropy) return -1;
    for(size_t i=0;i<n;i++) { state^=state<<13; state^=state>>17; state^=state<<5; out[i]=(uint8_t)state; }
    return 0;
}
int main(void) {
    check_entropy_blocks();
    check_entropy_faults();
    check_crngt_recovery();
    check_fault_led();
    static Rp2350Crypto crypto;
    assert(rp2350_crypto_init(&crypto,entropy,NULL)==AUTH_OK);
    AuthCrypto c=rp2350_crypto_interface(&crypto);
    AuthSecretCrypto s=rp2350_secret_interface(&crypto);
    mbedtls_ecp_keypair peer;
    mbedtls_ecp_keypair_init(&peer);
    assert(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&peer,entropy,NULL)==0);
    uint8_t pub[65],z[32],expected[32]; size_t n=0;
    assert(mbedtls_ecp_point_write_binary(&peer.MBEDTLS_PRIVATE(grp),&peer.MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED,&n,pub,sizeof(pub))==0 && n==65);
    calls=0; double start=(double)clock()/CLOCKS_PER_SEC;
    for(unsigned i=0;i<100;i++) assert(s.ecdh(s.context,pub,z)==AUTH_OK);
    printf("ECDH x100: CPU seconds=%.6f, entropy calls=%u\n",(double)clock()/CLOCKS_PER_SEC-start,calls);
    mbedtls_ecp_point own; mbedtls_mpi secret;
    mbedtls_ecp_point_init(&own); mbedtls_mpi_init(&secret);
    assert(mbedtls_ecp_point_read_binary(&peer.MBEDTLS_PRIVATE(grp),&own,crypto.agreement_public,65)==0);
    assert(mbedtls_ecdh_compute_shared(&peer.MBEDTLS_PRIVATE(grp),&secret,&own,&peer.MBEDTLS_PRIVATE(d),entropy,NULL)==0);
    assert(mbedtls_mpi_write_binary(&secret,expected,32)==0 && !memcmp(z,expected,32));
    memset(pub,0,65); memset(z,0xff,32);
    assert(s.ecdh(s.context,pub,z)==AUTH_BAD_DATA);
    for(size_t i=0;i<32;i++) assert(z[i]==0);
    AuthKeyHandle handle; uint8_t digest[32]={42},sig[72]; size_t siglen;
    calls=0; start=(double)clock()/CLOCKS_PER_SEC;
    assert(c.generate_p256(c.context,&handle,pub)==AUTH_OK);
    for(unsigned i=0;i<100;i++) assert(c.sign_p256_digest(c.context,&handle,digest,sig,&siglen)==AUTH_OK);
    printf("Keygen + ECDSA x100: CPU seconds=%.6f, entropy calls=%u\n",(double)clock()/CLOCKS_PER_SEC-start,calls);
    mbedtls_ecdsa_context verify;
    mbedtls_ecdsa_init(&verify);
    assert(mbedtls_ecp_group_load(&verify.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1)==0);
    assert(mbedtls_ecp_point_read_binary(&verify.MBEDTLS_PRIVATE(grp),&verify.MBEDTLS_PRIVATE(Q),pub,65)==0);
    assert(mbedtls_ecdsa_read_signature(&verify,digest,32,sig,siglen)==0);
    digest[0]^=1;
    assert(mbedtls_ecdsa_read_signature(&verify,digest,32,sig,siglen)!=0);
    mbedtls_ecdsa_free(&verify); mbedtls_mpi_free(&secret);
    mbedtls_ecp_point_free(&own); mbedtls_ecp_keypair_free(&peer);
    /* The bounded automatic reseed and explicit public-output reseed must
     * both fail closed, including clearing partially requested output. */
    fail_entropy=true;
    unsigned successful=0;
    for(unsigned i=0;i<257;i++) {
        memset(z,0xff,sizeof(z));
        AuthStatus status=s.ecdh(s.context,crypto.agreement_public,z);
        if(status!=AUTH_OK) {
            assert(status==AUTH_CRYPTO_ERROR && crypto.faulted);
            for(size_t j=0;j<sizeof(z);j++) assert(z[j]==0);
            break;
        }
        successful++;
    }
    assert(successful<256);
    rp2350_crypto_free(&crypto);
    fail_entropy=false;
    assert(rp2350_crypto_init(&crypto,entropy,NULL)==AUTH_OK);
    c=rp2350_crypto_interface(&crypto);
    fail_entropy=true; memset(z,0xff,sizeof(z));
    assert(c.random(c.context,z,sizeof(z))==AUTH_CRYPTO_ERROR && crypto.faulted);
    for(size_t i=0;i<sizeof(z);i++) assert(z[i]==0);
    rp2350_crypto_free(&crypto);
    puts("PASS: peer ECDH, invalid point/output clearing, signature/tamper checks, bounded and explicit reseed failures");
}
