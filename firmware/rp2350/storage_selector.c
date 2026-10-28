#include "storage_selector_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
static bool erased(const uint8_t *p,size_t n) {
    for(size_t i=0;i<n;i++) if(p[i]!=0xff) return false;
    return true;
}
static bool same(const Rp2350StoreSelector *a,const Rp2350StoreSelector *b) {
    return a->state==b->state && a->arena==b->arena && a->serial==b->serial && a->generation==b->generation &&
        a->reset_generation==b->reset_generation && store_equal(a->epoch,b->epoch,16) &&
        store_equal(a->manifest_digest,b->manifest_digest,32);
}
static AuthStatus remember(Rp2350StoreSelectorWorkspace *w,const Rp2350StoreSelector *s) {
    size_t at=0; while(at<w->count && w->records[at].serial<s->serial) at++;
    if(at<w->count && w->records[at].serial==s->serial) return same(&w->records[at],s) ? AUTH_OK : AUTH_BAD_DATA;
    if(w->count==16) return AUTH_CAPACITY;
    for(size_t i=w->count;i>at;i--) w->records[i]=w->records[i-1];
    w->records[at]=*s; w->count++; return AUTH_OK;
}
static AuthStatus sector(const Rp2350Flash *flash,Rp2350StoreRootAuthority *root,uint32_t base,Rp2350StoreSelectorWorkspace *w) {
    w->candidate=root->seal;
    bool hole=false,have_previous=false; uint64_t previous=0;
    for(uint32_t at=base;at<base+4096U;at+=512U) {
        for(size_t page=0;page<512;page+=256) {
            AuthStatus status=flash->read(flash->context,at+(uint32_t)page,w->frame+page,256);
            if(status!=AUTH_OK) return status;
        }
        if(erased(w->frame,512)) { hole=true; continue; }
        if(hole) return AUTH_BAD_DATA;
        /* A selector slot has a fixed body/commit boundary, so even a torn
         * first header can be safely discarded when its commit is erased. */
        if(erased(w->frame+256,256)) {
            hole=true;
            w->used[base/4096U]=8;
            continue;
        }
        Rp2350StoreIdentity id; size_t plain=0,extent=0;
        AuthStatus status=rp2350_store_frame_inspect(w->frame,512,&id,&plain,&extent);
        if(status!=AUTH_OK || id.class_id!=4 || plain!=96 || extent!=512 ||
            id.generation!=root->root.serial || !store_equal(id.epoch,root->root.epoch,16) ||
            (have_previous && (previous==UINT64_MAX || id.sequence!=previous+1U))) return AUTH_BAD_DATA;
        /* A body without its last-written commit never selected a new arena.
         * Keep prior authenticated selectors, require the remaining slots to
         * be blank, and retire this sector's append space. The writer will
         * recycle it only while preserving a current selector elsewhere. */
        /* Only the first anchor serial is a candidate from the header; MAC
         * verification and payload equality must succeed before trusting it. */
        Rp2350StoreIdentity expected={.class_id=4,.sequence=have_previous ? previous+1U : id.sequence,
            .generation=root->root.serial};
        for(size_t i=0;i<16;i++) expected.epoch[i]=root->root.epoch[i];
        size_t length=0;
        status=rp2350_store_open_internal(&w->candidate,&expected,at,w->frame,512,w->plain,96,&length,&w->seal);
        if(status!=AUTH_OK) return status;
        Rp2350StoreTransaction tx; Rp2350StoreSelector s;
        status=rp2350_store_transaction_decode(4,w->plain,length,&tx);
        if(status!=AUTH_OK || tx.count!=1 || tx.entries[0].kind!=9) return AUTH_BAD_DATA;
        status=rp2350_store_selector_decode(tx.entries[0].data,tx.entries[0].length,&s);
        auth_secure_zero(w->plain,sizeof(w->plain));
        if(status!=AUTH_OK) return status;
        if(s.serial!=expected.sequence || s.reset_generation!=root->root.reset_generation ||
            !store_equal(s.epoch,root->root.epoch,16)) return AUTH_BAD_DATA;
        status=remember(w,&s); if(status!=AUTH_OK) return status;
        previous=s.serial; have_previous=true;
        w->used[base/4096U]++; w->last[base/4096U]=s.serial;
    }
    return AUTH_OK;
}
static void clear_records(Rp2350StoreSelectorWorkspace *w) {
    auth_secure_zero(w->records,sizeof(w->records));
    memset(w->used,0,sizeof(w->used));
    memset(w->last,0,sizeof(w->last));
    w->count=0;
}
AuthStatus rp2350_store_select_internal(Rp2350StoreSelection *out,const Rp2350Flash *flash,
        Rp2350StoreRootAuthority *root,Rp2350StoreSelectorWorkspace *w) {
    if(out) auth_secure_zero(out,sizeof(*out));
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !root || !w) return AUTH_INVALID_ARGUMENT;
    if(!root->validated || !root->seal.initialized || root->seal.faulted || !root->root.serial ||
        !root->root.reset_generation || !store_nonzero(root->root.epoch,16) ||
        !store_equal(root->seal.epoch,root->root.epoch,16) || !root->seal.crypto.sha256 ||
        !root->seal.secrets.hmac_sha256 || !root->seal.secrets.aes256_cbc) return AUTH_CRYPTO_ERROR;
    uint8_t damaged=0;
    AuthStatus first=sector(flash,root,0,w);
    AuthStatus status=first;
    if(first==AUTH_BAD_DATA) { damaged=1; clear_records(w); }
    else if(first!=AUTH_OK) goto done;
    status=sector(flash,root,4096,w);
    if(status==AUTH_BAD_DATA && first==AUTH_OK) {
        damaged=2;
        clear_records(w);
        status=sector(flash,root,0,w);
    }
    if(status!=AUTH_OK) goto done;
    if(!w->count) { status=AUTH_BAD_DATA; goto done; }
    for(size_t i=1;i<w->count;i++) {
        const Rp2350StoreSelector *a=&w->records[i-1],*b=&w->records[i];
        if(a->serial==UINT64_MAX || b->serial!=a->serial+1U || a->state==2 ||
            (b->state==1 && (a->generation==UINT64_MAX || b->generation!=a->generation+1U || b->arena==a->arena))) {
            status=AUTH_BAD_DATA; goto done;
        }
    }
    /* A sector being recycled can be partially erased. Retain only complete
     * authenticated authority from the other sector. This is NOT permission
     * to serve: boot must validate its entire selected checkpoint/log. The
     * exclusive provider erases the old arena before any post-switch request,
     * so an older selector cannot mount pre-operation PIN/credential state.
     * Live providers also reject any authority/version change. */
    out->selector=w->records[w->count-1]; out->validated=true; out->damaged_mask=damaged;
    for(size_t i=0;i<2;i++) { out->used[i]=w->used[i]; if(w->last[i]==out->selector.serial) out->current_mask|=(uint8_t)(1U<<i); }
    if(out->selector.state==1) out->arena_base=out->selector.arena ? RP2350_STORE_ARENA_B : RP2350_STORE_ARENA_A;
done:
    if(status==AUTH_NOT_FOUND) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) auth_secure_zero(out,sizeof(*out));
    auth_secure_zero(w,sizeof(*w)); return status;
}
