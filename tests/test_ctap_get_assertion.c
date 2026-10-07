#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/cbor_writer.h"
#include "ctap/cbor_reader.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"
#include "auth_test_provider.h"

static size_t request(uint8_t *out, bool up)
{
    uint8_t client[32], id[32]; memset(client, 0xAA, sizeof client); memset(id, 0xA5, sizeof id);
    CborWriter writer; cbor_writer_init(&writer, out, 512U);
    assert(cbor_write_map(&writer, 4U) &&
        cbor_write_uint(&writer, 1U) && cbor_write_text(&writer, "example.com") &&
        cbor_write_uint(&writer, 2U) && cbor_write_bytes(&writer, client, 32U) &&
        cbor_write_uint(&writer, 3U) && cbor_write_array(&writer, 1U) && cbor_write_map(&writer, 2U) &&
        cbor_write_text(&writer, "id") && cbor_write_bytes(&writer, id, 32U) &&
        cbor_write_text(&writer, "type") && cbor_write_text(&writer, "public-key") &&
        cbor_write_uint(&writer, 5U) && cbor_write_map(&writer, 1U) &&
        cbor_write_text(&writer, "up") && cbor_write_bool(&writer, up));
    return writer.length;
}
static void seed(Store *store, AuthCredentialService *service)
{
    service_init(service, store);
    uint8_t rp[32], pub[65]; memset(rp, 0x42, sizeof rp);
    AuthCredential record;
    assert(auth_credentials_create(service, rp, NULL, 0U, false, &record, pub) == AUTH_OK);
}
static void assert_workspace_cleared(const CtapGetAssertionWorkspace *workspace)
{
    const unsigned char *bytes = (const unsigned char *)&workspace->scratch;
    for (size_t i = 0U; i < sizeof workspace->scratch; ++i) assert(bytes[i] == 0U);
    assert(!workspace->busy);
}
static void test_signature_layout_and_durable_counter(void)
{
    Store store = {0}; AuthCredentialService service; seed(&store, &service);
    uint8_t input[512], output[192]; size_t length = 999U;
    size_t input_length = request(input, true);
    CtapGetAssertionWorkspace ga_workspace = {0}; CtapGetAssertion prepared;
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, input, input_length, &prepared) == 0U);
    assert(prepared.user_presence_required && store.signatures == 0U && store.record.signature_count == 0U);
    assert_workspace_cleared(&ga_workspace);
    CtapGetAssertion saved = prepared;
    memset(&ga_workspace.scratch, 0xA5, sizeof ga_workspace.scratch);
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, input, 0U, &prepared) == CTAP_STATUS_INVALID_CBOR);
    assert(memcmp(&prepared, &saved, sizeof saved) == 0);
    assert_workspace_cleared(&ga_workspace);
    ga_workspace.busy = true;
    memset(&ga_workspace.scratch, 0xA5, sizeof ga_workspace.scratch);
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, input, input_length, &prepared) == CTAP_STATUS_OTHER);
    const unsigned char *scratch = (const unsigned char *)&ga_workspace.scratch;
    for (size_t i = 0U; i < sizeof ga_workspace.scratch; ++i) assert(scratch[i] == 0xA5U);
    assert(ga_workspace.busy && memcmp(&prepared, &saved, sizeof saved) == 0);
    uint8_t untouched[192]; memset(untouched, 0xEE, sizeof untouched);
    size_t untouched_length = 999U;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, untouched, sizeof untouched,
        &untouched_length) == CTAP_STATUS_OTHER);
    assert(ga_workspace.busy && untouched_length == 999U && untouched[0] == 0xEEU);
    assert(store.record.signature_count == 0U && store.signatures == 0U);
    for (size_t i = 0U; i < sizeof ga_workspace.scratch; ++i) assert(scratch[i] == 0xA5U);
    ga_workspace.busy = false;
    assert(ctap_get_assertion_prepare(NULL, &ga_workspace, input, input_length, &prepared) == CTAP_STATUS_OTHER);
    assert_workspace_cleared(&ga_workspace);
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0U);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == 1U && store.counter_at_sign == 1U && store.signatures == 1U);
    assert(store.hashed_length == 69U && store.hashed_data[32] == 1U && store.hashed_data[36] == 1U);
    assert(memcmp(store.hashed_data + 37U, prepared.client_data_hash, 32U) == 0);
    CborValue response, data, descriptor, id, signature;
    assert(cbor_read_document(output, length, &response) && response.major == 5U && response.value == 3U);
    assert(cbor_map_uint(&response, 1U, &descriptor) && cbor_map_text(&descriptor, "id", &id));
    assert(id.value == 32U && memcmp(id.data, prepared.credential_id, 32U) == 0);
    assert(cbor_map_uint(&response, 2U, &data) && data.value == 37U && data.data[32] == 1U && data.data[36] == 1U);
    assert(cbor_map_uint(&response, 3U, &signature) && signature.major == 2U && signature.value == 8U);
    /* A silent check uses the same signing/counter path with UP=0. */
    input_length = request(input, false);
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, input, input_length, &prepared) == 0U && !prepared.user_presence_required);
    store.record.signature_count = 0x00FFFFFFU;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0U);
    assert_workspace_cleared(&ga_workspace);
    assert(store.counter_at_sign == 0x01000000U);
    assert(memcmp(store.hashed_data + 32U, (uint8_t[]){0, 1, 0, 0, 0}, 5U) == 0); /* Big endian, no AT/ED/UV. */
}
static void test_fail_closed_and_counter_never_rolls_back(void)
{
    Store store = {0}; AuthCredentialService service; seed(&store, &service);
    uint8_t input[512], output[192]; memset(output, 0xEE, sizeof output);
    size_t length = 999U; CtapGetAssertionWorkspace ga_workspace = {0}; CtapGetAssertion prepared;
    size_t input_length = request(input, true);
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, input, input_length, &prepared) == 0U);
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, 191U, &length) == 0x7FU);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == 0U && store.signatures == 0U);
    store.counter_fails = true;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == 0U && store.signatures == 0U);
    store.counter_fails = false; store.sign_fails = true;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == 1U && store.counter_at_sign == 1U);
    assert(output[0] == 0xEEU && length == 999U);
    store.sign_fails = false; store.hash_fails = true;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == 2U && store.signatures == 1U);
    store.hash_fails = false;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0U);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == 3U && store.counter_at_sign == 3U);
    store.record.signature_count = UINT32_MAX;
    size_t signed_before = store.signatures;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0x7FU);
    assert_workspace_cleared(&ga_workspace);
    assert(store.record.signature_count == UINT32_MAX && store.signatures == signed_before);
    store.read_fails = true;
    CtapGetAssertion saved = prepared;
    assert(ctap_get_assertion_prepare(&service, &ga_workspace, input, input_length, &prepared) == 0x7FU);
    assert(memcmp(&prepared, &saved, sizeof saved) == 0);
    assert_workspace_cleared(&ga_workspace);
    store.read_fails = false; prepared.rp_id_hash[0] ^= 1U;
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0x2EU);
    assert_workspace_cleared(&ga_workspace);
    assert(store.signatures == signed_before);
    prepared.rp_id_hash[0] ^= 1U; store.exists = false; /* Reset/deletion after prepare. */
    assert(ctap_get_assertion_finish(&service, &ga_workspace, &prepared, output, sizeof output, &length) == 0x2EU);
    assert_workspace_cleared(&ga_workspace);
}

typedef struct {
    Store store; AuthCredentialService service;
    CtaphidDevice device; CtaphidCtapBackend backend;
    uint8_t first_report[64]; uint32_t now;
} Fixture;
static bool submit(void *context, const uint8_t report[64], uint64_t token)
{
    Fixture *fixture = context; (void)token;
    if ((report[4] & 0x80U) != 0U) memcpy(fixture->first_report, report, 64U);
    return true;
}
static bool receive(void *context, const uint8_t report[64])
{
    Fixture *fixture = context;
    return ctaphid_device_receive_report(&fixture->device, report, 64U, fixture->now) == CTAPHID_DEVICE_OK;
}
static void setup(Fixture *f)
{
    memset(f, 0, sizeof *f); seed(&f->store, &f->service);
    CtapGetInfoProfile profile = {0}; profile.max_message_size = 1024U; profile.user_presence = true;
    assert(ctaphid_ctap_backend_init(&f->backend, &profile));
    assert(ctaphid_ctap_backend_configure_credentials(&f->backend, &f->service));
    CtaphidDeviceConfig config = {0}; config.submit_report = submit; config.transport_context = f;
    config.start_cbor = ctaphid_ctap_backend_start; config.abort_cbor = ctaphid_ctap_backend_abort; config.cbor_context = &f->backend;
    assert(ctaphid_device_init(&f->device, &config) == CTAPHID_DEVICE_OK);
    uint32_t cid; assert(ctaphid_channels_allocate(&f->device.channels, &cid) == CTAPHID_CHANNEL_OK && cid == 1U);
}
static void begin(Fixture *f, bool up)
{
    uint8_t input[513]; input[0] = 2U;
    size_t length = 1U + request(input + 1U, up);
    assert(ctaphid_send_response(1U, 0x10U, input, length, receive, f) == CTAPHID_RESPONSE_OK);
    assert(ctaphid_device_poll(&f->device, f->now) == CTAPHID_DEVICE_OK);
    assert(f->backend.pending && f->backend.awaiting_get_assertion && f->store.record.signature_count == 0U);
    if (up) {
        assert(ctaphid_ctap_backend_poll(&f->backend, &f->device, f->now) == CTAPHID_DEVICE_OK);
        assert(ctaphid_device_poll(&f->device, f->now) == CTAPHID_DEVICE_OK);
        assert(f->first_report[4] == 0xBBU && f->first_report[7] == 2U);
    }
}
static void finish(Fixture *f, uint32_t now, uint8_t status)
{
    assert(ctaphid_ctap_backend_poll(&f->backend, &f->device, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&f->device, now) == CTAPHID_DEVICE_OK);
    assert(f->first_report[4] == 0x90U && f->first_report[7] == status);
    assert(!f->backend.pending && !f->backend.awaiting_get_assertion && f->device.phase == CTAPHID_DEVICE_IDLE);
}
static void test_backend_touch_deadlines_cancel_resync_and_silent(void)
{
    Fixture f; setup(&f); begin(&f, true);
    assert(!ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id + 1U, true, 1U));
    assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, 29999U) == CTAPHID_DEVICE_OK);
    finish(&f, 30000U, 0x27U); assert(f.store.signatures == 0U && f.store.record.signature_count == 0U);
    setup(&f); begin(&f, true);
    assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, false, 1U));
    finish(&f, 1U, 0x27U); assert(f.store.signatures == 0U && f.store.record.signature_count == 0U);
    for (unsigned up = 0U; up <= 1U; ++up) {
        setup(&f); begin(&f, up != 0U);
        uint64_t stale = f.backend.operation_id;
        assert(ctaphid_send_response(1U, 0x11U, NULL, 0U, receive, &f) == CTAPHID_RESPONSE_OK);
        finish(&f, 1U, 0x2DU); assert(f.store.signatures == 0U && f.store.record.signature_count == 0U);
        begin(&f, up != 0U);
        assert(!ctaphid_ctap_backend_signal_presence(&f.backend, stale, true, 2U));
        uint8_t nonce[8] = {0};
        assert(ctaphid_send_response(1U, 0x06U, nonce, 8U, receive, &f) == CTAPHID_RESPONSE_OK);
        assert(!f.backend.pending && !f.backend.awaiting_get_assertion && f.store.record.signature_count == 0U);
        assert(ctaphid_device_poll(&f.device, 2U) == CTAPHID_DEVICE_OK && f.first_report[4] == 0x86U);
    }
    setup(&f); begin(&f, false); finish(&f, 1U, 0U);
    assert(f.store.record.signature_count == 1U && f.store.hashed_data[32] == 0U);
    setup(&f); begin(&f, true);
    assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, true, 1U));
    finish(&f, 1U, 0U); assert(f.store.record.signature_count == 1U && f.store.hashed_data[32] == 1U);
}
int main(void)
{
    test_signature_layout_and_durable_counter();
    test_fail_closed_and_counter_never_rolls_back();
    test_backend_touch_deadlines_cancel_resync_and_silent();
    puts("GetAssertion tests passed (signed layout, durable counters, failures, UP, deadlines, aborts).");
    return 0;
}
