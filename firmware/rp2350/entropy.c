#include "entropy.h"
#include "authenticator/auth_secret_crypto.h"
#include <string.h>
bool rp2350_entropy_init(Rp2350Entropy *p,const Rp2350EntropyIo *io) {
    if (!p || !io || !io->start || !io->status || !io->read_word || !io->stop || !io->now_ms) return false;
    *p=(Rp2350Entropy){.io=*io,.initialized=true};
    return true;
}
int rp2350_entropy_read(void *ctx,unsigned char *out,size_t n) {
    Rp2350Entropy *p=ctx;
    if (!out || n==0 || n>RP2350_ENTROPY_MAX_REQUEST) return -1;
    auth_secure_zero(out,n);
    if (!p || !p->initialized || p->faulted) return -1;
    size_t done=0; uint8_t block[RP2350_ENTROPY_BLOCK_SIZE]={0};
    Rp2350EntropyFault failure=RP2350_ENTROPY_FAULT_NONE;
    while (done<n) {
        if (!p->io.start(p->io.context)) { failure=RP2350_ENTROPY_FAULT_START; goto failed; }
        uint32_t begun=p->io.now_ms(p->io.context),status,polls=0;
        do {
            if (++polls>RP2350_ENTROPY_MAX_POLLS) { failure=RP2350_ENTROPY_FAULT_POLL_LIMIT; goto failed; }
            status=p->io.status(p->io.context);
            p->last_status=status;
            if (status&0x0eU) { failure=RP2350_ENTROPY_FAULT_STATUS; goto failed; }
            if ((uint32_t)(p->io.now_ms(p->io.context)-begun)>=RP2350_ENTROPY_TIMEOUT_MS) {
                failure=RP2350_ENTROPY_FAULT_TIMEOUT; goto failed;
            }
        } while (!(status&1U));
        for (size_t i=0;i<6;i++) {
            uint32_t word=p->io.read_word(p->io.context,i);
            for (size_t j=0;j<4;j++) block[4*i+j]=(uint8_t)(word>>(8*j));
        }
        p->last_status=p->io.status(p->io.context);
        if (p->last_status&0x0eU) { failure=RP2350_ENTROPY_FAULT_STATUS; goto failed; }
        p->io.stop(p->io.context);
        if (p->have_previous && memcmp(p->previous,block,sizeof(block))==0) {
            failure=RP2350_ENTROPY_FAULT_REPEATED; goto failed;
        }
        /* Supplemental stuck-output check; not an entropy certification. */
        bool any=false,all_ff=true;
        for (size_t i=0;i<sizeof(block);i++) { any|=block[i]!=0; all_ff&=block[i]==0xff; }
        if (!any || all_ff) { failure=RP2350_ENTROPY_FAULT_STUCK; goto failed; }
        memcpy(p->previous,block,sizeof(block)); p->have_previous=true;
        size_t take=n-done;
        if (take>sizeof(block)) take=sizeof(block);
        memcpy(out+done,block,take); done+=take;
    }
    auth_secure_zero(block,sizeof(block));
    return 0;
failed:
    p->io.stop(p->io.context); p->faulted=true; p->failure=failure;
    auth_secure_zero(block,sizeof(block)); auth_secure_zero(p->previous,sizeof(p->previous));
    auth_secure_zero(out,n);
    return -1;
}
