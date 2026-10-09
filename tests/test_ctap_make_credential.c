#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/cbor_reader.h"
#include "ctap/cbor_writer.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"

#include "auth_test_provider.h"

static size_t request(uint8_t *out, bool exclude, bool none)
{
    uint8_t digest[32] = {0}, id[32]; memset(id, 0xA5, sizeof id);
    CborWriter writer; cbor_writer_init(&writer, out, 512U);
    assert(cbor_write_map(&writer, 4U + (exclude ? 1U : 0U) + (none ? 1U : 0U)));
    assert(cbor_write_uint(&writer, 1) && cbor_write_bytes(&writer, digest, 32U));
    assert(cbor_write_uint(&writer, 2) && cbor_write_map(&writer, 1) &&
        cbor_write_text(&writer, "id") && cbor_write_text(&writer, "example.com"));
    assert(cbor_write_uint(&writer, 3) && cbor_write_map(&writer, 1) &&
        cbor_write_text(&writer, "id") && cbor_write_bytes(&writer, NULL, 0U));
    assert(cbor_write_uint(&writer, 4) && cbor_write_array(&writer, 1) && cbor_write_map(&writer, 2) &&
        cbor_write_text(&writer, "alg") && cbor_write_int(&writer, -7) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key"));
    if (exclude) assert(cbor_write_uint(&writer, 5) && cbor_write_array(&writer, 1) && cbor_write_map(&writer, 2) &&
        cbor_write_text(&writer, "id") && cbor_write_bytes(&writer, id, 32U) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key"));
    if (none) assert(cbor_write_uint(&writer, 11) && cbor_write_array(&writer, 1) && cbor_write_text(&writer, "none"));
    return writer.length;
}

static void assert_workspace_cleared(const CtapMakeCredentialWorkspace *workspace)
{
    const unsigned char *bytes = (const unsigned char *)&workspace->scratch;
    for (size_t i = 0U; i < sizeof workspace->scratch; ++i) assert(bytes[i] == 0U);
    assert(!workspace->busy);
}
static void test_failure_rollback_and_none(void)
{
    Store store = {0}; AuthCredentialService service; service_init(&service, &store);
    uint8_t input[512], output[512], aaguid[16]; memset(aaguid, 1, sizeof aaguid);
    size_t input_length = request(input, false, false), length = 999U;
    CtapMakeCredentialWorkspace workspace = {0};
    CtapMakeCredential prepared;
    assert(ctap_make_credential_prepare(&service, &workspace, input, input_length, &prepared) == 0U);
    assert(!store.exists && store.generated == 0U); /* Validation is side-effect free. */
    assert_workspace_cleared(&workspace);
    CtapMakeCredential saved = prepared;
    memset(&workspace.scratch, 0xA5, sizeof workspace.scratch);
    assert(ctap_make_credential_prepare(&service, &workspace, input, 0U, &prepared) == CTAP_STATUS_INVALID_CBOR);
    assert(memcmp(&prepared, &saved, sizeof saved) == 0);
    assert_workspace_cleared(&workspace);
    workspace.busy = true;
    memset(&workspace.scratch, 0xA5, sizeof workspace.scratch);
    assert(ctap_make_credential_prepare(&service, &workspace, input, input_length, &prepared) == CTAP_STATUS_OTHER);
    const unsigned char *scratch = (const unsigned char *)&workspace.scratch;
    for (size_t i = 0U; i < sizeof workspace.scratch; ++i) assert(scratch[i] == 0xA5U);
    assert(memcmp(&prepared, &saved, sizeof saved) == 0 && workspace.busy);
    workspace.busy = false;
    assert(ctap_make_credential_prepare(NULL, &workspace, input, input_length, &prepared) == CTAP_STATUS_OTHER);
    assert_workspace_cleared(&workspace);

    memset(output, 0xEE, sizeof output);
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, 383U, &length) == 0x7FU);
    assert_workspace_cleared(&workspace);
    assert(store.generated == 0U && output[0] == 0xEEU && length == 999U);
    /* Reject reuse of active scratch without clearing the outer operation. */
    memset(&workspace.scratch, 0xA5, sizeof workspace.scratch); workspace.busy = true;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid,
        output, sizeof output, &length) == CTAP_STATUS_OTHER);
    assert(workspace.busy && store.generated == 0U && length == 999U && output[0] == 0xEEU);
    const unsigned char *bytes = (const unsigned char *)&workspace.scratch;
    for (size_t i = 0U; i < sizeof workspace.scratch; ++i) assert(bytes[i] == 0xA5U);
    workspace.busy = false;
    assert(ctap_make_credential_finish_at(NULL, &workspace, &prepared, aaguid,
        output, sizeof output, &length, 0U) == CTAP_STATUS_OTHER);
    assert_workspace_cleared(&workspace);
    store.generate_fails = true;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&workspace);
    assert(!store.exists && store.destroyed == 0U);
    store.generate_fails = false; store.insert_fails = true;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&workspace);
    assert(!store.exists && store.destroyed == 1U);
    store.insert_fails = false; store.sign_fails = true;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&workspace);
    assert(!store.exists && store.destroyed == 2U && output[0] == 0xEEU && length == 999U);
    store.sign_fails = false; store.hash_fails = true;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&workspace);
    assert(!store.exists && store.destroyed == 3U);
    store.hash_fails = false;
    input_length = request(input, false, true);
    assert(ctap_make_credential_prepare(&service, &workspace, input, input_length, &prepared) == 0U);
    size_t signed_before = store.signatures;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0U);
    assert_workspace_cleared(&workspace);
    assert(store.exists && store.signatures == signed_before && store.record.user_id_length == 0U && !store.record.discoverable);
    CborValue response, data, statement;
    assert(cbor_read_document(output, length, &response));
    assert(cbor_map_uint(&response, 2, &data) && data.value == 164U && data.data[32] == 0x41U);
    assert(memcmp(data.data + 37U, (uint8_t[16]){0}, 16U) == 0);
    assert(cbor_map_uint(&response, 3, &statement) && statement.major == 5U && statement.value == 0U);
    input_length = request(input, true, false);
    saved = prepared;
    store.read_fails = true;
    assert(ctap_make_credential_prepare(&service, &workspace, input, input_length, &prepared) == CTAP_STATUS_OTHER);
    assert(memcmp(&prepared, &saved, sizeof saved) == 0);
    assert_workspace_cleared(&workspace);
    store.read_fails = false;
    assert(ctap_make_credential_prepare(&service, &workspace, input, input_length, &prepared) == 0U && prepared.credential_excluded);
    assert_workspace_cleared(&workspace);
    size_t generated = store.generated;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x19U);
    assert_workspace_cleared(&workspace);
    assert(store.generated == generated);
    prepared.credential_excluded = false;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x28U);
    assert_workspace_cleared(&workspace);
    /* Failed rollback must not claim success or destroy a still-referenced key. */
    assert(auth_credentials_delete(&service, store.record.credential_id, store.record.rp_id_hash) == AUTH_OK);
    prepared.omit_attestation = false;
    store.sign_fails = true; store.erase_fails = true;
    size_t destroyed = store.destroyed;
    assert(ctap_make_credential_finish(&service, &workspace, &prepared, aaguid, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&workspace);
    assert(store.exists && store.destroyed == destroyed);
}

typedef struct {
    Store store; AuthCredentialService service;
    CtaphidDevice device; CtaphidCtapBackend backend;
    uint8_t report[64]; uint32_t now;
} Fixture;
static bool submit(void *ctx, const uint8_t report[64], uint64_t transfer)
{ Fixture *f = ctx; (void)transfer; memcpy(f->report, report, 64U); return true; }
static bool receive(void *ctx, const uint8_t report[64])
{
    Fixture *f = ctx;
    return ctaphid_device_receive_report(&f->device, report, 64U, f->now) == CTAPHID_DEVICE_OK;
}
static void setup(Fixture *f)
{
    memset(f, 0, sizeof *f); service_init(&f->service, &f->store);
    CtapGetInfoProfile profile = {0}; profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE; profile.user_presence = true;
    assert(ctaphid_ctap_backend_init(&f->backend, &profile));
    f->backend.presence_timeout_ms = 30000U; /* Fixed timeline for these scenarios. */
    assert(ctaphid_ctap_backend_configure_credentials(&f->backend, &f->service));
    assert(!ctaphid_ctap_backend_configure_credentials(&f->backend, &f->service));
    CtaphidDeviceConfig config = {0}; config.submit_report = submit; config.transport_context = f;
    config.start_cbor = ctaphid_ctap_backend_start; config.abort_cbor = ctaphid_ctap_backend_abort; config.cbor_context = &f->backend;
    assert(ctaphid_device_init(&f->device, &config) == CTAPHID_DEVICE_OK);
    uint32_t cid; assert(ctaphid_channels_allocate(&f->device.channels, &cid) == CTAPHID_CHANNEL_OK && cid == 1U);
}
static void begin(Fixture *f, bool excluded)
{
    uint8_t input[513]; input[0] = 1U;
    size_t length = 1U + request(input + 1U, excluded, false);
    assert(ctaphid_send_response(1U, 0x10U, input, length, receive, f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f->device, f->now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&f->backend, &f->device, f->now) == CTAPHID_DEVICE_OK);
    assert(f->backend.awaiting_presence && f->backend.presence_started);
    assert(ctaphid_device_poll(&f->device, f->now) == CTAPHID_DEVICE_OK);
    assert(f->report[4] == 0xBBU && f->report[7] == 2U);
}
static void finish(Fixture *f, uint32_t now, uint8_t status)
{
    assert(ctaphid_ctap_backend_poll(&f->backend, &f->device, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&f->device, now) == CTAPHID_DEVICE_OK);
    assert(f->report[4] == 0x90U && f->report[6] == 1U && f->report[7] == status);
    assert(!f->backend.pending && !f->backend.awaiting_make_credential && f->device.phase == CTAPHID_DEVICE_IDLE);
}
static void test_timeout_denial_cancel_resync(void)
{
    Fixture f; setup(&f); begin(&f, false);
    assert(f.store.generated == 0U);
    finish(&f, 30000U, 0x27U); assert(!f.store.exists && f.store.generated == 0U);
    setup(&f); begin(&f, false);
    assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, false, 1U));
    finish(&f, 1U, 0x27U); assert(f.store.generated == 0U);
    setup(&f); begin(&f, false);
    uint64_t stale = f.backend.operation_id;
    assert(ctaphid_send_response(1U, 0x11U, NULL, 0U, receive, &f) == CTAPHID_RESPONSE_OK);
    finish(&f, 1U, 0x2DU); assert(f.store.generated == 0U);
    f.now = 2U; begin(&f, false);
    assert(!ctaphid_ctap_backend_signal_presence(&f.backend, stale, true, 3U));
    uint8_t nonce[8] = {0};
    assert(ctaphid_send_response(1U, 0x06U, nonce, sizeof nonce, receive, &f) == CTAPHID_RESPONSE_OK);
    assert(!f.backend.pending && !f.store.exists && f.store.generated == 0U);
    assert(ctaphid_device_poll(&f.device, 3U) == CTAPHID_DEVICE_OK && f.report[4] == 0x86U);
    /* Exclusion timeout has a different required result than normal UP timeout. */
    setup(&f);
    uint8_t pub[65], rp[32]; memset(rp, 0x42, sizeof rp);
    AuthCredential existing;
    assert(auth_credentials_create(&f.service, rp, NULL, 0U, false, &existing, pub) == AUTH_OK);
    begin(&f, true); finish(&f, 30000U, 0x19U);
    assert(f.store.exists && f.store.generated == 1U);
}

static void test_reader_boundaries(void)
{
    CborValue value;
    const uint8_t four[] = {0x81, 0x81, 0x81, 0xA1, 0, 0xF9, 0x3E, 0};
    assert(cbor_read_document(four, sizeof four, &value));
    const uint8_t five[] = {0x81, 0x81, 0x81, 0x81, 0x81, 0};
    assert(!cbor_read_document(five, sizeof five, &value));
    const uint8_t overflow[] = {0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    assert(!cbor_read_document(overflow, sizeof overflow, &value));
    uint8_t encoded[16]; CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
    assert(cbor_write_int(&writer, INT64_MIN));
    assert(cbor_read_document(encoded, writer.length, &value) && value.major == 1U && value.value == INT64_MAX);
    assert(!cbor_read_document(NULL, 0, &value));
}

int main(void)
{
    test_failure_rollback_and_none();
    test_timeout_denial_cancel_resync();
    test_reader_boundaries();
    puts("MakeCredential tests passed (policy, virtual deadlines, cancellation, rollback, CBOR bounds).");
    return 0;
}
