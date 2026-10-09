#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap_user_presence.h"
#include "protocol/ctaphid_ctap_backend.h"

static void test_fresh_events_and_deadlines(void)
{
    CtapUserPresence presence = {0}, saved = presence;
    assert(!ctap_user_presence_signal(&presence, 1U, true, 0U));
    assert(!ctap_user_presence_begin(&presence, 0U, 0U, 30000U));
    assert(!ctap_user_presence_begin(&presence, 1U, 0U, 9999U));
    assert(!ctap_user_presence_begin(&presence, 1U, 0U, UINT32_MAX));
    assert(memcmp(&presence, &saved, sizeof presence) == 0);
    assert(ctap_user_presence_begin(&presence, 1U, 0U, 10000U));
    saved = presence;
    assert(!ctap_user_presence_begin(&presence, 2U, 0U, 30000U));
    assert(memcmp(&presence, &saved, sizeof presence) == 0);
    assert(ctap_user_presence_poll(&presence, 9999U) == CTAP_PRESENCE_WAITING);
    assert(!ctap_user_presence_signal(&presence, 2U, true, 9999U));
    assert(!ctap_user_presence_signal(&presence, 1U, true, 10000U));
    assert(presence.result == CTAP_PRESENCE_TIMED_OUT);
    ctap_user_presence_abort(&presence, 2U);
    assert(presence.result == CTAP_PRESENCE_TIMED_OUT);
    ctap_user_presence_abort(&presence, 1U);
    assert(presence.result == CTAP_PRESENCE_IDLE);
    assert(ctap_user_presence_begin(&presence, 2U, 10001U, 30000U));
    assert(!ctap_user_presence_signal(&presence, 2U, true, 10000U)); /* Queued pre-request edge. */
    assert(presence.result == CTAP_PRESENCE_WAITING);
    assert(!ctap_user_presence_signal(&presence, 1U, true, 10002U));
    assert(ctap_user_presence_signal(&presence, 2U, true, 10002U));
    assert(!ctap_user_presence_signal(&presence, 2U, true, 10003U));
    assert(presence.result == CTAP_PRESENCE_CONFIRMED);
    assert(ctap_user_presence_begin(&presence, 3U, 10004U, 30000U));
    assert(presence.result == CTAP_PRESENCE_WAITING); /* No cached confirmation. */
    assert(ctap_user_presence_signal(&presence, 3U, false, 10005U));
    assert(presence.result == CTAP_PRESENCE_DENIED);
    assert(ctap_user_presence_poll(NULL, 0U) == CTAP_PRESENCE_IDLE);
}

static void test_clock_wraparound(void)
{
    CtapUserPresence presence = {0};
    assert(ctap_user_presence_begin(&presence, 1U, UINT32_MAX - 100U, 30000U));
    assert(ctap_user_presence_poll(&presence, 29898U) == CTAP_PRESENCE_WAITING);
    assert(ctap_user_presence_poll(&presence, 29899U) == CTAP_PRESENCE_TIMED_OUT);
}

typedef struct {
    CtaphidDevice device;
    CtaphidCtapBackend backend;
    uint8_t last_report[64];
    size_t reports;
} Fixture;

static bool submit(void *context, const uint8_t report[64], uint64_t transfer_id)
{
    Fixture *fixture = context;
    (void)transfer_id;
    memcpy(fixture->last_report, report, 64U);
    ++fixture->reports;
    return true;
}

static void setup(Fixture *fixture)
{
    memset(fixture, 0, sizeof *fixture);
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE;
    profile.user_presence = true;
    assert(ctaphid_ctap_backend_init(&fixture->backend, &profile));
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
    assert(fixture->last_report[18] == 1U && fixture->last_report[23] == 0x0CU);
}

static void begin_selection(Fixture *fixture, uint32_t now)
{
    uint8_t selection[64] = {0, 0, 0, 1, 0x90, 0, 1, 0x0B};
    assert(ctaphid_device_receive_report(&fixture->device, selection, sizeof selection, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_ctap_backend_poll(&fixture->backend, &fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(fixture->device.phase == CTAPHID_DEVICE_PROCESSING);
    assert(fixture->last_report[4] == 0xBBU && fixture->last_report[7] == 2U);
}

static void finish(Fixture *fixture, uint32_t now, uint8_t status)
{
    assert(ctaphid_ctap_backend_poll(&fixture->backend, &fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture->device, now) == CTAPHID_DEVICE_OK);
    assert(fixture->last_report[4] == 0x90U && fixture->last_report[6] == 1U && fixture->last_report[7] == status);
    assert(fixture->device.phase == CTAPHID_DEVICE_IDLE && !fixture->backend.pending);
}

static void test_selection_outcomes(void)
{
    Fixture fixture;
    setup(&fixture);
    begin_selection(&fixture, 100U);
    uint64_t operation = fixture.backend.operation_id;
    assert(ctaphid_device_poll(&fixture.device, 200U) == CTAPHID_DEVICE_OK);
    assert(fixture.last_report[4] == 0xBBU && fixture.last_report[7] == 2U);
    assert(ctaphid_ctap_backend_signal_presence(&fixture.backend, operation, true, 201U));
    finish(&fixture, 201U, 0U);
    assert(!ctaphid_ctap_backend_signal_presence(&fixture.backend, operation, true, 202U));

    begin_selection(&fixture, 300U);
    assert(!ctaphid_ctap_backend_signal_presence(&fixture.backend, operation, true, 301U));
    assert(ctaphid_ctap_backend_signal_presence(&fixture.backend, fixture.backend.operation_id, false, 301U));
    finish(&fixture, 301U, 0x27U);

    begin_selection(&fixture, 400U);
    assert(ctaphid_ctap_backend_poll(&fixture.backend, &fixture.device, 400U + CTAP_USER_PRESENCE_DEFAULT_TIMEOUT_MS - 1U) == CTAPHID_DEVICE_OK);
    assert(fixture.device.phase == CTAPHID_DEVICE_PROCESSING);
    finish(&fixture, 400U + CTAP_USER_PRESENCE_DEFAULT_TIMEOUT_MS, 0x2FU); /* Configured deadline, using virtual time. */
}

static void test_cancel_and_resync_clear_presence(void)
{
    Fixture fixture;
    setup(&fixture);
    begin_selection(&fixture, 10U);
    uint64_t old_operation = fixture.backend.operation_id;
    uint8_t cancel[64] = {0, 0, 0, 1, 0x91};
    assert(ctaphid_device_receive_report(&fixture.device, cancel, sizeof cancel, 11U) == CTAPHID_DEVICE_OK);
    assert(fixture.backend.presence.result == CTAP_PRESENCE_IDLE);
    finish(&fixture, 11U, 0x2DU);
    begin_selection(&fixture, 20U);
    assert(!ctaphid_ctap_backend_signal_presence(&fixture.backend, old_operation, true, 21U));
    old_operation = fixture.backend.operation_id;
    uint8_t init[64] = {0, 0, 0, 1, 0x86, 0, 8};
    assert(ctaphid_device_receive_report(&fixture.device, init, sizeof init, 21U) == CTAPHID_DEVICE_OK);
    assert(!fixture.backend.pending && fixture.backend.presence.result == CTAP_PRESENCE_IDLE);
    assert(ctaphid_device_poll(&fixture.device, 21U) == CTAPHID_DEVICE_OK);
    assert(fixture.last_report[4] == 0x86U);
    begin_selection(&fixture, 30U);
    assert(!ctaphid_ctap_backend_signal_presence(&fixture.backend, old_operation, true, 31U));
    assert(fixture.backend.presence.result == CTAP_PRESENCE_WAITING);
}

static void test_selection_request_validation(void)
{
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE;
    uint8_t response[CTAP_MAX_RESPONSE_SIZE];
    const uint8_t request[] = {0x0B, 0xA0};
    size_t length = 999U;
    assert(ctap_execute(&profile, request, 1U, response, sizeof response, &length) == CTAP_EXECUTION_RESPONSE_READY);
    assert(length == 1U && response[0] == 0x01U);
    profile.user_presence = true;
    assert(ctap_execute(&profile, request, sizeof request, response, sizeof response, &length) == CTAP_EXECUTION_RESPONSE_READY);
    assert(length == 1U && response[0] == 0x03U);
    length = 999U;
    memset(response, 0xEE, sizeof response);
    assert(ctap_execute(&profile, request, 1U, response, sizeof response, &length) == CTAP_EXECUTION_WAIT_USER_PRESENCE);
    assert(length == 999U && response[0] == 0xEEU);
}

int main(void)
{
    test_fresh_events_and_deadlines();
    test_clock_wraparound();
    test_selection_outcomes();
    test_cancel_and_resync_clear_presence();
    test_selection_request_validation();
    puts("User presence tests passed (fresh events, deadlines, selection, cancel, resync).");
    return 0;
}
