#include "entropy.h"
#include "authenticator/auth_secret_crypto.h"
#include <string.h>
static Rp2350EntropyFault status_fault(uint32_t status) {
    return status & RP2350_ENTROPY_CONFIG_ERROR ?
        RP2350_ENTROPY_FAULT_CONFIG : RP2350_ENTROPY_FAULT_STATUS;
}
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
    uint32_t started=p->io.now_ms(p->io.context);
    p->requests++;
    size_t done=0; uint8_t block[RP2350_ENTROPY_BLOCK_SIZE]={0};
    Rp2350EntropyFault failure=RP2350_ENTROPY_FAULT_NONE;
    unsigned crngt_retries=0;
    if(p->available) {
        /* Keep every health-checked byte single-use. The full previous block
         * stays intact for the continuous comparison; only its unused suffix
         * can seed a later request. Still reject a newly latched HW/config
         * fault before releasing buffered bytes. */
        p->last_status=p->io.status(p->io.context);
        if(p->last_status&RP2350_ENTROPY_ERROR_MASK) { failure=status_fault(p->last_status); goto failed; }
        size_t take=n<p->available ? n : p->available;
        memcpy(out,p->previous+sizeof(p->previous)-p->available,take);
        p->available-=(uint8_t)take;
        done=take;
    }
    while (done<n) {
        if (!p->io.start(p->io.context)) {
            p->last_status=p->io.status(p->io.context);
            failure=p->last_status & RP2350_ENTROPY_CONFIG_ERROR ?
                RP2350_ENTROPY_FAULT_CONFIG : RP2350_ENTROPY_FAULT_START;
            goto failed;
        }
        uint32_t begun=p->io.now_ms(p->io.context),status,polls=0;
        do {
            if (++polls>RP2350_ENTROPY_MAX_POLLS) { failure=RP2350_ENTROPY_FAULT_POLL_LIMIT; goto failed; }
            status=p->io.status(p->io.context);
            p->last_status=status;
            if (status&RP2350_ENTROPY_ERROR_MASK) {
                /* Arm TZ-TRNG's polling driver acknowledges isolated CRNGT
                 * rejections and waits for fresh EHR_VALID. Use a stricter
                 * per-request bound; never read the rejected collection,
                 * accept EHR_VALID alongside a fault, or renew the deadline.
                 * Cached/post-read faults are deliberately not recoverable. */
                if(status==4U && crngt_retries<RP2350_ENTROPY_MAX_CRNGT_RETRIES &&
                    p->io.clear_crngt &&
                    (uint32_t)(p->io.now_ms(p->io.context)-begun)<RP2350_ENTROPY_TIMEOUT_MS &&
                    p->io.clear_crngt(p->io.context)) {
                    crngt_retries++;
                    p->crngt_retries++;
                    continue;
                }
                failure=status_fault(status); goto failed;
            }
            if ((uint32_t)(p->io.now_ms(p->io.context)-begun)>=RP2350_ENTROPY_TIMEOUT_MS) {
                failure=RP2350_ENTROPY_FAULT_TIMEOUT; goto failed;
            }
        } while (!(status&1U));
        for (size_t i=0;i<6;i++) {
            uint32_t word=p->io.read_word(p->io.context,i);
            for (size_t j=0;j<4;j++) block[4*i+j]=(uint8_t)(word>>(8*j));
        }
        p->last_status=p->io.status(p->io.context);
        if (p->last_status&RP2350_ENTROPY_ERROR_MASK) { failure=status_fault(p->last_status); goto failed; }
        p->io.stop(p->io.context);
        if (p->have_previous && memcmp(p->previous,block,sizeof(block))==0) {
            failure=RP2350_ENTROPY_FAULT_REPEATED; goto failed;
        }
        /* Supplemental stuck-output check; not an entropy certification. */
        bool any=false,all_ff=true;
        for (size_t i=0;i<sizeof(block);i++) { any|=block[i]!=0; all_ff&=block[i]==0xff; }
        if (!any || all_ff) { failure=RP2350_ENTROPY_FAULT_STUCK; goto failed; }
        memcpy(p->previous,block,sizeof(block)); p->have_previous=true;
        p->blocks++;
        size_t take=n-done;
        if (take>sizeof(block)) take=sizeof(block);
        memcpy(out+done,block,take); done+=take;
        p->available=(uint8_t)(sizeof(block)-take);
    }
    auth_secure_zero(block,sizeof(block));
    p->elapsed_ms+=(uint32_t)(p->io.now_ms(p->io.context)-started);
    return 0;
failed:
    p->io.stop(p->io.context); p->faulted=true; p->failure=failure;
    p->available=0;
    p->elapsed_ms+=(uint32_t)(p->io.now_ms(p->io.context)-started);
    auth_secure_zero(block,sizeof(block)); auth_secure_zero(p->previous,sizeof(p->previous));
    auth_secure_zero(out,n);
    return -1;
}
