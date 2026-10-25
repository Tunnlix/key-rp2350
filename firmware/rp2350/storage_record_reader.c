#include "storage_record_reader_internal.h"
#include "storage_bytes_internal.h"
#include <string.h>
typedef struct {
    Rp2350StoreRecordWorkspace *w; const Rp2350StoreBootConfig *config;
    const Rp2350StoreMetadataIndex *metadata; const Rp2350StoreReplayKey *key; bool found;
} RecordRead;
static AuthStatus read_record(void *ctx,const Rp2350StoreIdentity *id,const Rp2350StoreTransaction *tx) {
    RecordRead *r=ctx;
    uint64_t sequence=r->metadata ? r->metadata->sequence : r->key->sequence;
    if(id->sequence!=sequence) return AUTH_OK;
    for(size_t i=0;i<tx->count;i++) {
        const Rp2350StoreEntry *entry=&tx->entries[i];
        if(entry->kind!=(r->metadata ? 2U : 4U)) continue;
        if(r->found || (id->class_id!=1 && id->class_id!=2)) return AUTH_BAD_DATA;
        r->found=true; AuthStatus status;
        if(r->metadata) {
            status=rp2350_store_metadata_decode(entry->data,entry->length,r->config->hash,
                r->config->records_context,&r->w->credential);
            if(status!=AUTH_OK) return status;
            /* The record predates any later counter-only mutations. */
            r->w->credential.signature_count=r->metadata->signature_count;
            status=rp2350_store_metadata_index_internal(&r->w->index,&r->w->credential,id->sequence,
                r->config->hash,r->config->records_context,r->w->canonical,sizeof(r->w->canonical));
            if(status!=AUTH_OK) return status;
            if(!rp2350_store_metadata_index_equal_internal(r->metadata,&r->w->index)) return AUTH_BAD_DATA;
        } else {
            AuthKeyHandle handle={0}; uint8_t digest[32]={0};
            status=r->config->key_inspect(r->config->records_context,entry->data,entry->length,&handle);
            if(status==AUTH_OK) status=r->config->hash(r->config->records_context,entry->data,entry->length,digest);
            bool valid=entry->length==136 && store_equal(handle.bytes,r->key->handle.bytes,32) &&
                store_equal(digest,r->key->digest,32);
            auth_secure_zero(&handle,sizeof(handle)); auth_secure_zero(digest,sizeof(digest));
            if(status!=AUTH_OK) return status;
            if(!valid) return AUTH_BAD_DATA;
            memcpy(r->w->key,entry->data,136);
        }
    }
    return AUTH_OK;
}
AuthStatus rp2350_store_record_read_internal(Rp2350StoreRecordWorkspace *w,const Rp2350Flash *flash,
        const Rp2350StoreBootConfig *config,Rp2350StoreSeal *seal,const Rp2350StoreSelection *selection,
        const Rp2350StoreMetadataIndex *metadata,const Rp2350StoreReplayKey *key,Rp2350StoreLogWorkspace *io) {
    if(!w) return AUTH_INVALID_ARGUMENT;
    auth_secure_zero(w,sizeof(*w));
    if(io) auth_secure_zero(io,sizeof(*io));
    if(!flash || !flash->read || !config || !config->hash || !config->key_inspect || !seal || !selection || !selection->validated || !io ||
        (!!metadata==!!key) || !(metadata ? metadata->sequence : key->sequence) || (key && key->retired))
        return AUTH_INVALID_ARGUMENT;
    RecordRead read={w,config,metadata,key,false};
    uint32_t offset=metadata ? metadata->offset : key->offset;
    uint16_t class_id=metadata ? metadata->class_id : key->class_id;
    if(offset<selection->arena_base || offset-selection->arena_base>=RP2350_STORE_ARENA_SIZE || offset%256U ||
        (class_id!=1 && class_id!=2)) return AUTH_BAD_DATA;
    Rp2350StoreIdentity expected={.class_id=class_id,.sequence=metadata ? metadata->sequence : key->sequence,
        .generation=selection->selector.generation,.offset=offset};
    memcpy(expected.epoch,selection->selector.epoch,16);
    AuthStatus status=flash->read(flash->context,offset,io->page,256);
    Rp2350StoreIdentity inspected; size_t plain=0,extent=0;
    if(status==AUTH_OK) status=rp2350_store_frame_inspect(io->page,256,&inspected,&plain,&extent);
    if(status==AUTH_OK && extent>RP2350_STORE_ARENA_SIZE-(offset-selection->arena_base)) status=AUTH_BAD_DATA;
    if(status==AUTH_OK) status=flash->read(flash->context,offset,io->frame,extent);
    size_t length=0;
    if(status==AUTH_OK) status=rp2350_store_open_internal(seal,&expected,offset,io->frame,extent,
        io->plain,sizeof(io->plain),&length,&io->seal);
    Rp2350StoreTransaction tx;
    if(status==AUTH_OK) status=rp2350_store_transaction_decode(class_id,io->plain,length,&tx);
    if(status==AUTH_OK) status=read_record(&read,&expected,&tx);
    if(status==AUTH_OK && !read.found) status=AUTH_BAD_DATA;
    auth_secure_zero(io,sizeof(*io));
    if(status!=AUTH_OK) auth_secure_zero(w,sizeof(*w));
    return status;
}
