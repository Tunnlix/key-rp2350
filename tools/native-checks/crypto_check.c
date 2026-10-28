#include "crypto.h"
#include "entropy.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static unsigned state=192837,calls;
static bool fail_entropy;
typedef struct { unsigned blocks,clock,status; } EntropyModel;
static bool start_entropy(void *ctx) { ((EntropyModel *)ctx)->blocks++; return true; }
static uint32_t entropy_status(void *ctx) { return ((EntropyModel *)ctx)->status; }
static uint32_t entropy_word(void *ctx,size_t i) {
    EntropyModel *m=ctx; uint32_t word=0;
    for(unsigned j=0;j<4;j++) word|=(uint32_t)(uint8_t)((m->blocks-1)*24+i*4+j+1)<<(j*8);
    return word;
}
static void stop_entropy(void *ctx) { (void)ctx; }
static uint32_t entropy_clock(void *ctx) { return ((EntropyModel *)ctx)->clock++; }
static void check_entropy_blocks(void) {
    EntropyModel m={.status=1};
    Rp2350EntropyIo io={&m,start_entropy,entropy_status,entropy_word,stop_entropy,entropy_clock};
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
