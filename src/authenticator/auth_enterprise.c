#include "authenticator/auth_credentials.h"
#include <string.h>
static bool certificates_valid(const uint8_t *const *certs,const size_t *lengths,size_t count) {
    if(!count || count>AUTH_ENTERPRISE_MAX_CERTIFICATES) return false;
    size_t total=0;
    for(size_t i=0;i<count;i++) {
        if(!certs[i] || !lengths[i] || lengths[i]>AUTH_ENTERPRISE_MAX_CHAIN_BYTES-total) return false;
        total+=lengths[i];
    }
    return total!=0;
}
static bool same_leaf(const uint8_t *a,size_t an,const uint8_t *b,size_t bn) {
    return a && b && an==bn && memcmp(a,b,an)==0;
}
bool auth_batch_valid(const AuthBatchAttestation *p) {
    return p && p->sign_digest && certificates_valid(p->certificates,p->certificate_lengths,p->certificate_count);
}
bool auth_enterprise_valid(const AuthEnterpriseAttestation *p) {
    if(!p || !p->sign_digest || !certificates_valid(p->certificates,p->certificate_lengths,p->certificate_count) ||
        p->rp_count>AUTH_ENTERPRISE_MAX_RPS || (p->rp_count && !p->rp_hashes) || (!p->platform_managed && !p->rp_count)) return false;
    uint8_t nonzero=0;
    for(size_t i=0;i<32;i++) nonzero|=p->fingerprint[i];
    return nonzero!=0;
}
bool auth_credentials_configure_enterprise(AuthCredentialService *s,const AuthEnterpriseAttestation *p) {
    if(CTAP_MESSAGE_CAPACITY<2048U) return false;
    if(!s || s->creation_busy || s->lookup_busy || s->enterprise.sign_digest || !auth_enterprise_valid(p)) return false;
    if(same_leaf(p->certificates[0],p->certificate_lengths[0],s->batch.certificates[0],s->batch.certificate_lengths[0])) return false;
    s->enterprise=*p;return true;
}
bool auth_credentials_configure_batch(AuthCredentialService *s,const AuthBatchAttestation *p) {
    if(CTAP_MESSAGE_CAPACITY<2048U) return false;
    if(!s || s->creation_busy || s->lookup_busy || s->batch.sign_digest || !auth_batch_valid(p)) return false;
    if(same_leaf(p->certificates[0],p->certificate_lengths[0],s->enterprise.certificates[0],s->enterprise.certificate_lengths[0])) return false;
    s->batch=*p;return true;
}
