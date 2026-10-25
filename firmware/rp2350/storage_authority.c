#include "storage_authority_internal.h"
#include "storage_bytes_internal.h"

static bool erased(const uint8_t *p,size_t n) {
    for(size_t i=0;i<n;i++) if(p[i]!=0xff) return false;
    return true;
}
static bool policy_valid(const Rp2350StoreRootPolicy *p) {
    return (p->profile==1 && p->backend==0) || (p->profile==2 && p->backend!=0);
}
void rp2350_store_root_authority_clear_internal(Rp2350StoreRootAuthority *out) {
    if(out) auth_secure_zero(out,sizeof(*out));
}
AuthStatus rp2350_store_root_pair_open_internal(Rp2350StoreRootAuthority *out,const Rp2350Flash *flash,
        const Rp2350StoreRootPolicy *policy,Rp2350StoreRootResolve resolve,void *context,Rp2350StoreRootWorkspace *w) {
    if(out) rp2350_store_root_authority_clear_internal(out);
    if(w) auth_secure_zero(w,sizeof(*w));
    if(!out || !flash || !flash->read || !policy || !policy_valid(policy) || !resolve || !w) return AUTH_INVALID_ARGUMENT;
    AuthStatus status=AUTH_BAD_DATA; bool blank_pair=false;
    for(size_t slot=0;slot<2;slot++) {
        /* Bounded page-sized reads, even if the backend cannot read a sector
         * in one operation. No writer callback is required or called. */
        for(size_t page=0;page<4096;page+=256) {
            status=flash->read(flash->context,0x2000U+(uint32_t)slot*4096U+(uint32_t)page,w->slots[slot]+page,256);
            if(status!=AUTH_OK) goto done;
        }
    }
    bool blank_a=erased(w->slots[0],4096),blank_b=erased(w->slots[1],4096);
    if(blank_a || blank_b) {
        blank_pair=blank_a && blank_b; status=blank_pair ? AUTH_NOT_FOUND : AUTH_BAD_DATA; goto done;
    }
    for(size_t slot=0;slot<2;slot++) {
        status=rp2350_store_root_inspect_internal(w->slots[slot],4096,policy->profile,&w->roots[slot]);
        if(status!=AUTH_OK) goto done;
        if(w->roots[slot].backend!=policy->backend) { status=AUTH_BAD_DATA; goto done; }
    }
    if(!store_equal(w->slots[0],w->slots[1],4096)) { status=AUTH_BAD_DATA; goto done; }
    /* Matching syntax/copies are still untrusted. The backend resolves once
     * because descriptors are identical; both root MAC/commit checks follow. */
    status=resolve(context,&w->roots[0],&w->seal);
    if(status!=AUTH_OK) goto done;
    if(!w->seal.initialized || w->seal.faulted || !w->seal.crypto.sha256 || !w->seal.crypto.random ||
        !w->seal.secrets.hmac_sha256 || !w->seal.secrets.aes256_cbc) { status=AUTH_CRYPTO_ERROR; goto done; }
    for(size_t slot=0;slot<2;slot++) {
        status=rp2350_store_root_open_internal(&w->seal,w->slots[slot],4096,policy->profile,&w->roots[slot]);
        if(status!=AUTH_OK) goto done;
    }
    out->root=w->roots[0]; out->seal=w->seal; out->validated=true;
done:
    /* Missing backend material/read errors must never look like erased media. */
    if(status==AUTH_NOT_FOUND && !blank_pair) status=AUTH_IO_ERROR;
    if(status!=AUTH_OK) rp2350_store_root_authority_clear_internal(out);
    auth_secure_zero(w,sizeof(*w)); return status;
}
