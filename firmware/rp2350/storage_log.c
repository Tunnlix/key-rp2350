#include "storage_log_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static bool erased(const uint8_t *p,size_t n) { for(size_t i=0;i<n;i++) if(p[i]!=0xff) return false; return true; }
static bool geometry(uint32_t base,uint32_t n) {
    return (n==RP2350_STORE_ARENA_SIZE && (base==RP2350_STORE_ARENA_A || base==RP2350_STORE_ARENA_B)) || (base==0 && n==8192);
}
static AuthStatus scan(Rp2350StoreLog *j,Rp2350StoreReplay replay,Rp2350StoreFrameReplay frames,void *context,
        uint32_t *end,uint64_t *next,Rp2350StoreLogWorkspace *w) {
    uint32_t at=0; uint64_t sequence=1;
    while(at<j->size) {
        AuthStatus status=j->flash.read(j->flash.context,j->base+at,w->page,256);
        if(status!=AUTH_OK) return status;
        if(erased(w->page,256)) {
            /* Do not accept a hole concealing a programmed tail. */
            for(uint32_t tail=at+256U;tail<j->size;tail+=256U) {
                status=j->flash.read(j->flash.context,j->base+tail,w->page,256);
                if(status!=AUTH_OK) return status;
                if(!erased(w->page,256)) return AUTH_BAD_DATA;
            }
            *end=at; *next=sequence; return AUTH_OK;
        }
        Rp2350StoreIdentity id; size_t plain=0,extent=0;
        status=rp2350_store_frame_inspect(w->page,256,&id,&plain,&extent);
        bool valid_header=status==AUTH_OK && extent<=j->size-at && id.sequence==sequence && id.generation==j->generation &&
            store_equal(id.epoch,j->epoch,16) && (j->selectors ? id.class_id==4 : id.class_id!=4);
        if(!valid_header && !j->selectors) {
            /* A brownout may tear the first header page itself. This is safe
             * to abandon only if EVERY later page is erased: a committed
             * frame necessarily has a non-erased commit page after its body.
             * Recovery still requires the earlier selected checkpoint. */
            for(uint32_t tail=at+256U;tail<j->size;tail+=256U) {
                status=j->flash.read(j->flash.context,j->base+tail,w->page,256);
                if(status!=AUTH_OK) return status;
                if(!erased(w->page,256)) return AUTH_BAD_DATA;
            }
            j->interrupted=true;
            *end=at;
            *next=sequence;
            return AUTH_OK;
        }
        if(!valid_header) return AUTH_BAD_DATA;
        status=j->flash.read(j->flash.context,j->base+at,w->frame,extent);
        if(status!=AUTH_OK) return status;
        /* The commit page is programmed last. An entirely erased commit on
         * the final mutation means no operation was acknowledged from it.
         * In particular, PIN comparison cannot run before its attempt charge
         * commits. Preserve the verified prefix, but require compaction before
         * any append: this partially programmed extent must never be reused.
         * Recovery must still validate the selected checkpoint from committed
         * frames. A marked but invalid commit remains fatal corruption. */
        if(!j->selectors && erased(w->frame+extent-256U,256)) {
            /* A corrupt length must not conceal a real earlier commit inside
             * the claimed extent. V3's marker has one exact page encoding;
             * legacy CTC2 commit pages are never payload to discard either. */
            for(size_t page=256;page<extent-256U;page+=256U) {
                if((erased(w->frame+page,255) && w->frame[page+255U]==0xfe) ||
                    memcmp(w->frame+page,"CTC2",4)==0) return AUTH_BAD_DATA;
            }
            for(uint32_t tail=at+(uint32_t)extent;tail<j->size;tail+=256U) {
                status=j->flash.read(j->flash.context,j->base+tail,w->page,256);
                if(status!=AUTH_OK) return status;
                if(!erased(w->page,256)) return AUTH_BAD_DATA;
            }
            j->interrupted=true;
            *end=at;
            *next=sequence;
            return AUTH_OK;
        }
        /* Expected fields come from the independently selected region, not
         * adopted generation/sequence from unauthenticated on-flash bytes. */
        Rp2350StoreIdentity expected={.class_id=id.class_id,.sequence=sequence,.generation=j->generation,.offset=j->base+at};
        memcpy(expected.epoch,j->epoch,16); size_t length=0;
        status=rp2350_store_open_internal(j->crypto,&expected,j->base+at,w->frame,extent,w->plain,sizeof(w->plain),&length,&w->seal);
        if(status!=AUTH_OK) return status;
        Rp2350StoreTransaction transaction;
        status=rp2350_store_transaction_decode(id.class_id,w->plain,length,&transaction);
        if(status!=AUTH_OK) return status;
        if(replay) { status=replay(context,&expected,&transaction); if(status!=AUTH_OK) return status; }
        const uint8_t *digest=store_u16(w->frame+4)==3 ? w->frame+extent-320U : w->frame+extent-216U;
        if(frames) { status=frames(context,&expected,&transaction,digest); if(status!=AUTH_OK) return status; }
        auth_secure_zero(w->plain,sizeof(w->plain));
        if(sequence==UINT64_MAX) return AUTH_CAPACITY;
        sequence++; at+=(uint32_t)extent;
    }
    *end=at; *next=sequence; return AUTH_OK;
}
static AuthStatus open_log(Rp2350StoreLog *j,const Rp2350Flash *flash,Rp2350StoreSeal *crypto,
        uint32_t base,uint32_t size,uint64_t generation,const uint8_t epoch[16],
        Rp2350StoreReplay replay,Rp2350StoreFrameReplay frames,void *context,Rp2350StoreLogWorkspace *w) {
    if(!j || !w) return AUTH_INVALID_ARGUMENT;
    *j=(Rp2350StoreLog){0}; auth_secure_zero(w,sizeof(*w));
    if(!flash || !flash->read || !crypto || !epoch || !generation ||
        !geometry(base,size) || !store_nonzero(epoch,16) || !crypto->initialized || crypto->faulted || !store_equal(epoch,crypto->epoch,16)) return AUTH_INVALID_ARGUMENT;
    j->flash=*flash; j->crypto=crypto; j->base=base; j->size=size; j->generation=generation; j->selectors=base==0;
    memcpy(j->epoch,epoch,16);
    /* Replay mutates only the caller's private staging state. Authenticate each
     * frame before staging it, and publish nothing until the whole log and its
     * cross-record invariants pass. Recovery aborts and wipes staging on any
     * later error; a preliminary decrypt-and-discard pass adds no protection. */
    AuthStatus status=scan(j,replay,frames,context,&j->end,&j->next_sequence,w);
    if(status==AUTH_OK) j->initialized=true; else j->faulted=true;
    auth_secure_zero(w,sizeof(*w));
    return status==AUTH_OK && !j->end ? AUTH_NOT_FOUND : status;
}
AuthStatus rp2350_store_log_open_internal(Rp2350StoreLog *j,const Rp2350Flash *flash,Rp2350StoreSeal *crypto,
        uint32_t base,uint32_t size,uint64_t generation,const uint8_t epoch[16],
        Rp2350StoreReplay replay,void *context,Rp2350StoreLogWorkspace *w) {
    return open_log(j,flash,crypto,base,size,generation,epoch,replay,NULL,context,w);
}
AuthStatus rp2350_store_log_open_frames_internal(Rp2350StoreLog *j,const Rp2350Flash *flash,Rp2350StoreSeal *crypto,
        uint32_t base,uint32_t size,uint64_t generation,const uint8_t epoch[16],
        Rp2350StoreFrameReplay replay,void *context,Rp2350StoreLogWorkspace *w) {
    return open_log(j,flash,crypto,base,size,generation,epoch,NULL,replay,context,w);
}
static AuthStatus append_log(Rp2350StoreLog *j,uint16_t class_id,const uint8_t *plain,size_t n,
        Rp2350StoreLogWorkspace *w,bool checkpoint,bool verified_prefix) {
    if(!j || !plain || !w) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(w,sizeof(*w));
    if(!j->initialized || j->faulted || j->interrupted || !j->crypto || j->crypto->faulted) return AUTH_IO_ERROR;
    if(!j->flash.program_page) return AUTH_UNSUPPORTED;
    if(!j->flash.read || !geometry(j->base,j->size) || j->end>j->size || j->end%256U || !j->next_sequence)
        return AUTH_BAD_DATA;
    if(checkpoint && (j->selectors || j->base==0 || (class_id!=2 && class_id!=3))) return AUTH_BAD_DATA;
    if(j->next_sequence==UINT64_MAX || (j->selectors ? class_id!=4 : class_id==4)) return AUTH_BAD_DATA;
    Rp2350StoreTransaction transaction;
    AuthStatus status=rp2350_store_transaction_decode(class_id,plain,n,&transaction);
    if(status!=AUTH_OK) return status;
    size_t extent=0;
    status=rp2350_store_frame_extent(n,&extent);
    if(status!=AUTH_OK) return status;
    if(extent>j->size-j->end) return AUTH_CAPACITY;
    if(checkpoint || verified_prefix) {
        /* The checkpoint owner opened an entirely blank inactive bank and
         * retains this cursor until final replay. Check only the new extent
         * here; never overwrite a programmed page or retry an uncertain write. */
        for(size_t at=0;at<extent;at+=256U) {
            status=j->flash.read(j->flash.context,j->base+j->end+(uint32_t)at,w->page,256);
            if(status!=AUTH_OK) goto failed;
            if(!erased(w->page,256)) { status=AUTH_BAD_DATA; goto failed; }
        }
    } else {
        uint32_t checked_end=0; uint64_t checked_next=0;
        status=scan(j,NULL,NULL,NULL,&checked_end,&checked_next,w);
        if(status!=AUTH_OK || checked_end!=j->end || checked_next!=j->next_sequence) {
            if(status==AUTH_OK) status=AUTH_BAD_DATA;
            goto failed;
        }
    }
    Rp2350StoreIdentity id={.class_id=class_id,.sequence=j->next_sequence,.generation=j->generation};
    memcpy(id.epoch,j->epoch,16); size_t length=0; uint32_t offset=j->base+j->end;
    status=rp2350_store_seal_internal(j->crypto,&id,offset,plain,n,w->frame,sizeof(w->frame),&length,&w->seal);
    if(status!=AUTH_OK) goto failed;
    /* Program and verify each body page, with commit excluded until the end. */
    for(size_t at=0;at<length;at+=256U) {
        status=j->flash.program_page(j->flash.context,offset+(uint32_t)at,w->frame+at);
        if(status!=AUTH_OK) goto failed;
        status=j->flash.read(j->flash.context,offset+(uint32_t)at,w->page,256);
        if(status!=AUTH_OK) goto failed;
        if(!store_equal(w->page,w->frame+at,256)) { status=AUTH_IO_ERROR; goto failed; }
    }
    status=j->flash.read(j->flash.context,offset,w->frame,length); if(status!=AUTH_OK) goto failed;
    status=rp2350_store_open_internal(j->crypto,&id,offset,w->frame,length,w->plain,sizeof(w->plain),&length,&w->seal);
    if(status!=AUTH_OK || length!=n || !store_equal(w->plain,plain,n)) {
        if(status==AUTH_OK) status=AUTH_BAD_DATA;
        goto failed;
    }
    j->end+=(uint32_t)extent; j->next_sequence++;
    auth_secure_zero(w,sizeof(*w)); return AUTH_OK;
failed:
    j->faulted=true; auth_secure_zero(w,sizeof(*w)); return status;
}
AuthStatus rp2350_store_log_append_internal(Rp2350StoreLog *j,uint16_t class_id,const uint8_t *plain,size_t n,Rp2350StoreLogWorkspace *w) {
    return append_log(j,class_id,plain,n,w,false,false);
}
AuthStatus rp2350_store_log_append_checkpoint_internal(Rp2350StoreLog *j,uint16_t class_id,const uint8_t *plain,size_t n,Rp2350StoreLogWorkspace *w) {
    return append_log(j,class_id,plain,n,w,true,false);
}
AuthStatus rp2350_store_log_append_verified_internal(Rp2350StoreLog *j,uint16_t class_id,const uint8_t *plain,size_t n,Rp2350StoreLogWorkspace *w) {
    if(!j || j->selectors || class_id!=1) return AUTH_INVALID_ARGUMENT;
    return append_log(j,class_id,plain,n,w,false,true);
}
