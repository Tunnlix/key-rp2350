#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap_reset.h"
#include "protocol/ctaphid_ctap_backend.h"

typedef struct {
    size_t calls;
    bool fail, pin_set;
    uint8_t records[64], device_identifier[16], store_state[16];
    uint32_t generation;
} MockStorage;

static bool clear_storage(void *context)
{
    MockStorage *storage = context;
    ++storage->calls;
    if (storage->fail) return false;
    memset(storage->records, 0, sizeof storage->records);
    storage->pin_set = false;
    ++storage->generation;
    /* Deterministic test identifiers; production callback requires CSPRNG. */
    memset(storage->device_identifier, (int)storage->generation, 16U);
    memset(storage->store_state, (int)(storage->generation + 1U), 16U);
    return true;
}

static void test_reset_policy(void)
{
    MockStorage storage = {0};
    CtapReset reset;
    ctap_reset_init(&reset, 100U, clear_storage, &storage);
    assert(ctap_reset_authorize(&reset, 1U, 10099U) == 0U);
    CtapUserPresence presence = {0};
    assert(ctap_user_presence_begin(&presence, 1U, 10099U, 30000U));
    assert(ctap_reset_commit(&reset, 1U, &presence) == 0x27U && storage.calls == 0U);
    assert(ctap_user_presence_signal(&presence, 1U, true, 20000U));
    ctap_reset_poll(&reset, 20000U); /* Timely receipt allows later confirmation. */
    assert(ctap_reset_commit(&reset, 1U, &presence) == 0U && storage.calls == 1U);
    assert(ctap_reset_commit(&reset, 1U, &presence) == 0x27U && storage.calls == 1U);
    assert(ctap_reset_authorize(&reset, 2U, 20001U) == 0x30U);
    assert(ctap_reset_authorize(&reset, 3U, 101U) == 0x30U); /* Closed after counter wrap too. */
    ctap_reset_init(&reset, 0U, clear_storage, &storage);
    assert(ctap_reset_authorize(&reset, 4U, 10000U) == 0U);
    ctap_reset_abort(&reset, 3U);
    assert(reset.authorized_operation == 4U);
    ctap_reset_abort(&reset, 4U);
    assert(ctap_reset_authorize(&reset, 5U, 10001U) == 0x30U);
    ctap_reset_init(&reset, UINT32_MAX - 100U, clear_storage, &storage);
    assert(ctap_reset_authorize(&reset, 6U, 9899U) == 0U); /* Exactly ten seconds across wrap. */
    ctap_reset_abort(&reset, 6U);
    assert(ctap_reset_authorize(&reset, 7U, 9900U) == 0x30U);
    ctap_reset_init(&reset, 0U, NULL, NULL);
    assert(ctap_reset_authorize(&reset, 8U, 1U) == 0x27U);
}

typedef struct {
    CtaphidDevice device;
    CtaphidCtapBackend backend;
    MockStorage storage;
    uint8_t report[64];
    bool reject_transport;
} Fixture;

static bool submit(void *context, const uint8_t report[64], uint64_t transfer_id)
{
    Fixture *fixture = context;
    (void)transfer_id;
    memcpy(fixture->report, report, 64U);
    return !fixture->reject_transport;
}

static void setup(Fixture *fixture, bool reset_enabled)
{
    memset(fixture, 0, sizeof *fixture);
    memset(fixture->storage.records, 0xA5, sizeof fixture->storage.records);
    fixture->storage.pin_set = true;
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = 1024U;
    profile.user_presence = true;
    assert(ctaphid_ctap_backend_init(&fixture->backend, &profile));
    assert(ctaphid_ctap_backend_configure_reset(&fixture->backend, 0U,
        reset_enabled ? clear_storage : NULL, &fixture->storage));
    assert(!ctaphid_ctap_backend_configure_reset(&fixture->backend, 1U, clear_storage, &fixture->storage));
    CtaphidDeviceConfig config = {0};
    config.submit_report = submit;
    config.transport_context = fixture;
    config.start_cbor = ctaphid_ctap_backend_start;
    config.abort_cbor = ctaphid_ctap_backend_abort;
    config.cbor_context = &fixture->backend;
    assert(ctaphid_device_init(&fixture->device, &config) == CTAPHID_DEVICE_OK);
    uint8_t init[64] = {0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0, 8};
    assert(ctaphid_device_receive_report(&fixture->device, init, sizeof init, 0U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, 0U) == CTAPHID_DEVICE_OK);
}

static void request_reset(Fixture *fixture, uint32_t received, uint32_t processed)
{
    uint8_t request[64] = {0, 0, 0, 1, 0x90, 0, 1, 0x07};
    assert(ctaphid_device_receive_report(&fixture->device, request, sizeof request, received) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, processed) == CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&fixture->backend, &fixture->device, processed) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, processed) == CTAPHID_DEVICE_OK);
}

static void finish(Fixture *fixture, uint32_t now, uint8_t status)
{
    assert(ctaphid_ctap_backend_poll(&fixture->backend, &fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(fixture->report[4] == 0x90U && fixture->report[6] == 1U && fixture->report[7] == status);
    assert(fixture->device.phase == CTAPHID_DEVICE_IDLE && !fixture->backend.pending);
}

static void test_confirmed_reset_and_original_clock(void)
{
    Fixture fixture;
    setup(&fixture, true);
    CtaphidChannelManager original_channels = fixture.device.channels;
    request_reset(&fixture, 9999U, 12000U); /* Authorize receipt, not processing time. */
    assert(fixture.backend.pending && fixture.backend.reset_authorized);
    assert(fixture.report[4] == 0xBBU && fixture.report[7] == 2U);
    assert(fixture.storage.calls == 0U && fixture.storage.pin_set);
    uint64_t operation = fixture.backend.operation_id;
    assert(ctaphid_ctap_backend_signal_presence(&fixture.backend, operation, true, 12001U));
    finish(&fixture, 12001U, 0U);
    assert(fixture.storage.calls == 1U && !fixture.storage.pin_set);
    for (size_t i = 0; i < sizeof fixture.storage.records; ++i) assert(fixture.storage.records[i] == 0U);
    assert(fixture.storage.generation == 1U && fixture.storage.device_identifier[0] == 1U && fixture.storage.store_state[0] == 2U);
    assert(memcmp(&fixture.device.channels, &original_channels, sizeof original_channels) == 0);
    assert(!ctaphid_ctap_backend_signal_presence(&fixture.backend, operation, true, 12002U));
    request_reset(&fixture, 12002U, 12002U);
    assert(fixture.report[7] == 0x30U && fixture.storage.calls == 1U);
    assert(fixture.backend.reset.powered_at_ms == 0U);
}

static void test_denied_timeout_and_disabled(void)
{
    Fixture fixture;
    setup(&fixture, true);
    request_reset(&fixture, 1U, 1U);
    assert(ctaphid_ctap_backend_signal_presence(&fixture.backend, fixture.backend.operation_id, false, 2U));
    finish(&fixture, 2U, 0x27U);
    assert(fixture.storage.calls == 0U && fixture.storage.pin_set);
    request_reset(&fixture, 3U, 3U);
    finish(&fixture, 30003U, 0x2FU);
    assert(fixture.storage.calls == 0U && fixture.storage.pin_set);
    setup(&fixture, false);
    request_reset(&fixture, 1U, 1U);
    assert(fixture.report[7] == 0x27U && fixture.storage.calls == 0U && !fixture.backend.pending);
    setup(&fixture, true);
    request_reset(&fixture, 10001U, 10001U);
    assert(fixture.report[7] == 0x30U && fixture.storage.calls == 0U);
}

static void test_cancellation_resync_and_stale_touch(void)
{
    Fixture fixture;
    setup(&fixture, true);
    request_reset(&fixture, 1U, 1U);
    uint64_t old_operation = fixture.backend.operation_id;
    uint8_t cancel[64] = {0, 0, 0, 1, 0x91};
    assert(ctaphid_device_receive_report(&fixture.device, cancel, sizeof cancel, 2U) == CTAPHID_DEVICE_OK);
    finish(&fixture, 2U, 0x2DU);
    assert(fixture.storage.calls == 0U && fixture.backend.reset.authorized_operation == 0U);
    request_reset(&fixture, 3U, 3U);
    assert(!ctaphid_ctap_backend_signal_presence(&fixture.backend, old_operation, true, 4U));
    uint8_t init[64] = {0, 0, 0, 1, 0x86, 0, 8};
    assert(ctaphid_device_receive_report(&fixture.device, init, sizeof init, 4U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture.device, 4U) == CTAPHID_DEVICE_OK);
    assert(!fixture.backend.pending && fixture.backend.reset.authorized_operation == 0U && fixture.storage.calls == 0U);
}

static void test_storage_failure_and_lost_response(void)
{
    Fixture fixture;
    setup(&fixture, true);
    fixture.storage.fail = true;
    request_reset(&fixture, 1U, 1U);
    assert(ctaphid_ctap_backend_signal_presence(&fixture.backend, fixture.backend.operation_id, true, 2U));
    finish(&fixture, 2U, 0x7FU);
    assert(fixture.storage.calls == 1U && fixture.storage.generation == 0U && fixture.storage.pin_set);
    setup(&fixture, true);
    request_reset(&fixture, 1U, 1U);
    assert(ctaphid_ctap_backend_signal_presence(&fixture.backend, fixture.backend.operation_id, true, 2U));
    assert(ctaphid_ctap_backend_poll(&fixture.backend, &fixture.device, 2U) == CTAPHID_DEVICE_OK);
    fixture.reject_transport = true;
    assert(ctaphid_device_poll(&fixture.device, 2U) == CTAPHID_DEVICE_TRANSPORT_FAILED);
    assert(fixture.storage.calls == 1U && fixture.storage.generation == 1U);
    assert(ctaphid_ctap_backend_poll(&fixture.backend, &fixture.device, 3U) == CTAPHID_DEVICE_OK);
    assert(fixture.storage.calls == 1U); /* No rollback or double commit after lost reply. */
}

static void test_reset_request_validation(void)
{
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = 1024U;
    uint8_t response[CTAP_MAX_RESPONSE_SIZE];
    const uint8_t request[] = {0x07, 0xA0};
    size_t length;
    assert(ctap_execute(&profile, request, 1U, response, sizeof response, &length) == CTAP_EXECUTION_RESPONSE_READY);
    assert(response[0] == 0x27U);
    profile.user_presence = true;
    assert(ctap_execute(&profile, request, sizeof request, response, sizeof response, &length) == CTAP_EXECUTION_RESPONSE_READY);
    assert(response[0] == 0x03U);
    assert(ctap_execute(&profile, request, 1U, response, sizeof response, &length) == CTAP_EXECUTION_WAIT_FACTORY_RESET);
}

int main(void)
{
    test_reset_policy();
    test_confirmed_reset_and_original_clock();
    test_denied_timeout_and_disabled();
    test_cancellation_resync_and_stale_touch();
    test_storage_failure_and_lost_response();
    test_reset_request_validation();
    puts("CTAP reset tests passed (window, confirmation, storage, aborts, failure, no timer restart).");
    return 0;
}
