#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_device.h"

/* Deterministic fake USB driver and deferred CBOR worker. No wall-clock sleeps. */
typedef struct {
    uint8_t reports[128][64];
    uint64_t transfers[128];
    size_t count, transport_aborts, cbor_starts, cbor_aborts, winks;
    uint64_t aborted_transfer, operation;
    bool reject;
} Mock;

typedef struct { CtaphidDevice device; Mock mock; } Fixture;

static bool submit(void *context, const uint8_t report[64], uint64_t id)
{
    Mock *mock = context;
    assert(mock->count < 128U);
    memcpy(mock->reports[mock->count], report, 64U);
    mock->transfers[mock->count++] = id;
    return !mock->reject;
}

static void abort_report(void *context, uint64_t id)
{
    Mock *mock = context;
    ++mock->transport_aborts;
    mock->aborted_transfer = id;
}

static void start_cbor(void *context, uint64_t id, const uint8_t *request, size_t length)
{
    Mock *mock = context;
    assert(length == 1U && request[0] == 0x04U);
    mock->operation = id;
    ++mock->cbor_starts;
}

static void abort_cbor(void *context, uint64_t id)
{
    Mock *mock = context;
    assert(id == mock->operation);
    ++mock->cbor_aborts;
}

static void wink_action(void *context, uint32_t channel_id)
{
    Mock *mock = context;
    assert(channel_id != 0U && channel_id != UINT32_MAX);
    ++mock->winks;
}

static void setup(Fixture *fixture, bool asynchronous, bool cbor)
{
    memset(fixture, 0, sizeof *fixture);
    CtaphidDeviceConfig config = {0};
    config.submit_report = submit;
    config.abort_report = abort_report;
    config.transport_context = &fixture->mock;
    config.asynchronous_transport = asynchronous;
    config.wink_action = wink_action;
    config.wink_context = &fixture->mock;
    if (cbor) {
        config.start_cbor = start_cbor;
        config.abort_cbor = abort_cbor;
        config.cbor_context = &fixture->mock;
    }
    assert(ctaphid_device_init(&fixture->device, &config) == CTAPHID_DEVICE_OK);
}

static uint32_t decode_cid(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) | bytes[3];
}

static CtaphidDeviceResult initial(Fixture *fixture, uint32_t cid,
    uint8_t command, uint16_t length, uint32_t now)
{
    uint8_t report[64] = {0};
    report[0] = (uint8_t)(cid >> 24); report[1] = (uint8_t)(cid >> 16);
    report[2] = (uint8_t)(cid >> 8); report[3] = (uint8_t)cid;
    report[4] = (uint8_t)(command | 0x80U);
    report[5] = (uint8_t)(length >> 8); report[6] = (uint8_t)length;
    for (size_t i = 7U; i < sizeof report; ++i) report[i] = (uint8_t)(i - 7U);
    if (command == 0x10U) report[7] = 0x04U;
    return ctaphid_device_receive_report(&fixture->device, report, sizeof report, now);
}

static CtaphidDeviceResult continuation(Fixture *fixture, uint32_t cid,
    uint8_t sequence, size_t offset, uint32_t now)
{
    uint8_t report[64] = {0};
    report[0] = (uint8_t)(cid >> 24); report[1] = (uint8_t)(cid >> 16);
    report[2] = (uint8_t)(cid >> 8); report[3] = (uint8_t)cid;
    report[4] = sequence;
    for (size_t i = 5U; i < sizeof report; ++i) report[i] = (uint8_t)(offset + i - 5U);
    return ctaphid_device_receive_report(&fixture->device, report, sizeof report, now);
}

static void poll_at(Fixture *fixture, uint32_t now)
{
    assert(ctaphid_device_poll(&fixture->device, now) == CTAPHID_DEVICE_OK);
}

static void complete_transfer(Fixture *fixture)
{
    assert(fixture->device.in_flight);
    assert(ctaphid_device_report_sent(&fixture->device,
        fixture->device.flight_id, true) == CTAPHID_DEVICE_OK);
}

static uint32_t allocate(Fixture *fixture, uint32_t now)
{
    assert(initial(fixture, UINT32_MAX, 0x06U, 8U, now) == CTAPHID_DEVICE_OK);
    poll_at(fixture, now);
    const uint8_t *reply = fixture->mock.reports[fixture->mock.count - 1U];
    assert(decode_cid(reply) == UINT32_MAX && reply[4] == 0x86U && reply[6] == 17U);
    assert(reply[19] == 2U); /* CTAP 2.3 uses HID protocol version 2. */
    uint8_t capabilities = 0x08U;
    if (fixture->device.config.start_cbor != NULL) capabilities |= 0x04U;
    if (fixture->device.config.wink_action != NULL) capabilities |= 0x01U;
    assert(reply[23] == capabilities);
    uint32_t cid = decode_cid(reply + 15U);
    if (fixture->device.config.asynchronous_transport) complete_transfer(fixture);
    assert(fixture->device.phase == CTAPHID_DEVICE_IDLE);
    return cid;
}

static void expect_error(Fixture *fixture, uint32_t cid, uint8_t error)
{
    const uint8_t *reply = fixture->mock.reports[fixture->mock.count - 1U];
    assert(decode_cid(reply) == cid && reply[4] == 0xBFU);
    assert(reply[5] == 0U && reply[6] == 1U && reply[7] == error);
    for (size_t i = 8U; i < 64U; ++i) assert(reply[i] == 0U);
}

static void test_basic_commands(void)
{
    Fixture fixture;
    setup(&fixture, false, false);
    uint32_t cid = allocate(&fixture, 0U);
    const uint16_t lengths[] = {0U, 1U, 57U, 58U, 60U, 116U, 117U, 1024U};
    for (size_t n = 0; n < sizeof lengths / sizeof lengths[0]; ++n) {
        size_t before = fixture.mock.count;
        assert(initial(&fixture, cid, 0x01U, lengths[n], 10U) == CTAPHID_DEVICE_OK);
        size_t offset = 57U;
        uint8_t sequence = 0U;
        while (offset < lengths[n]) {
            assert(continuation(&fixture, cid, sequence++, offset, 11U) == CTAPHID_DEVICE_OK);
            offset += 59U;
        }
        assert(fixture.device.phase == CTAPHID_DEVICE_PROCESSING);
        poll_at(&fixture, 12U);
        assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
        size_t received = 0U;
        for (size_t i = before; i < fixture.mock.count; ++i) {
            const uint8_t *report = fixture.mock.reports[i];
            assert(decode_cid(report) == cid);
            size_t header = i == before ? 7U : 5U;
            assert(report[4] == (i == before ? 0x81U : (uint8_t)(i - before - 1U)));
            if (i == before) assert(((size_t)report[5] << 8 | report[6]) == lengths[n]);
            size_t count = lengths[n] - received;
            if (count > 64U - header) count = 64U - header;
            for (size_t j = 0; j < count; ++j) assert(report[header + j] == (uint8_t)(received + j));
            for (size_t j = header + count; j < 64U; ++j) assert(report[j] == 0U);
            received += count;
        }
        assert(received == lengths[n]);
    }
    assert(initial(&fixture, cid, 0x08U, 0U, 20U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 20U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][4] == 0x88U);
    assert(fixture.mock.winks == 1U);
    const uint8_t unsupported[] = {0x03U, 0x04U, 0x10U, 0x3BU, 0x3FU, 0x7FU};
    for (size_t i = 0; i < sizeof unsupported; ++i) {
        assert(initial(&fixture, cid, unsupported[i], 1U, 30U) == CTAPHID_DEVICE_OK);
        poll_at(&fixture, 30U);
        expect_error(&fixture, cid, 0x01U);
    }
}

static void test_async_ownership(void)
{
    Fixture fixture;
    setup(&fixture, true, false);
    uint32_t first = allocate(&fixture, 0U), second = allocate(&fixture, 1U);
    assert(initial(&fixture, first, 0x01U, 60U, 10U) == CTAPHID_DEVICE_OK);
    assert(initial(&fixture, second, 0x01U, 0U, 11U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 11U);
    expect_error(&fixture, second, 0x06U);
    complete_transfer(&fixture);
    assert(fixture.device.phase == CTAPHID_DEVICE_RECEIVING);
    assert(continuation(&fixture, first, 0U, 57U, 12U) == CTAPHID_DEVICE_OK);
    assert(initial(&fixture, second, 0x06U, 8U, 12U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 12U);
    expect_error(&fixture, second, 0x06U);
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING);
    complete_transfer(&fixture); /* The BUSY reply must not release first. */
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING);
    poll_at(&fixture, 13U);
    uint64_t first_token = fixture.device.flight_id;
    complete_transfer(&fixture); /* Initial PING response is not the final report. */
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING);
    poll_at(&fixture, 14U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][4] == 0U);
    assert(ctaphid_device_report_sent(&fixture.device, first_token, true) == CTAPHID_DEVICE_IGNORED);
    complete_transfer(&fixture);
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
    /* A rejected known-channel request also retains ownership through ERROR. */
    assert(initial(&fixture, first, 0x01U, 7610U, 20U) == CTAPHID_DEVICE_OK);
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING);
    poll_at(&fixture, 20U);
    expect_error(&fixture, first, 0x03U);
    assert(initial(&fixture, second, 0x01U, 0U, 21U) == CTAPHID_DEVICE_OK);
    assert(fixture.device.control_count == 1U && fixture.device.active_channel_id == first);
    complete_transfer(&fixture);
    poll_at(&fixture, 21U);
    expect_error(&fixture, second, 0x06U);
    complete_transfer(&fixture);
}

static void test_validation_and_sequence_errors(void)
{
    Fixture fixture;
    setup(&fixture, false, false);
    uint32_t cid = allocate(&fixture, 0U);
    uint8_t short_report[63] = {0};
    size_t before = fixture.mock.count;
    assert(ctaphid_device_receive_report(&fixture.device, short_report, sizeof short_report, 0U) == CTAPHID_DEVICE_INVALID_REPORT_LENGTH);
    assert(continuation(&fixture, 777U, 0U, 0U, 1U) == CTAPHID_DEVICE_IGNORED);
    assert(fixture.mock.count == before);
    const uint32_t invalid_cids[] = {0U, 777U, UINT32_MAX};
    for (size_t i = 0; i < sizeof invalid_cids / sizeof invalid_cids[0]; ++i) {
        assert(initial(&fixture, invalid_cids[i], 0x01U, 0U, 2U) == CTAPHID_DEVICE_OK);
        assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
        poll_at(&fixture, 2U);
        expect_error(&fixture, invalid_cids[i], 0x0BU);
    }
    const uint16_t oversized[] = {1025U, 7610U};
    for (size_t i = 0; i < sizeof oversized / sizeof oversized[0]; ++i) {
        assert(initial(&fixture, cid, 0x01U, oversized[i], 3U) == CTAPHID_DEVICE_OK);
        poll_at(&fixture, 3U);
        expect_error(&fixture, cid, 0x03U);
        assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
    }
    assert(initial(&fixture, cid, 0x01U, 200U, 10U) == CTAPHID_DEVICE_OK);
    CtaphidReassembler saved = fixture.device.reassembler;
    assert(continuation(&fixture, 777U, 0U, 57U, 11U) == CTAPHID_DEVICE_IGNORED);
    assert(memcmp(&saved, &fixture.device.reassembler, sizeof saved) == 0);
    assert(continuation(&fixture, cid, 1U, 57U, 12U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 12U);
    expect_error(&fixture, cid, 0x04U);
    assert(initial(&fixture, cid, 0x01U, 200U, 20U) == CTAPHID_DEVICE_OK);
    assert(initial(&fixture, cid, 0x01U, 0U, 21U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 21U);
    expect_error(&fixture, cid, 0x04U);
}

static void test_reception_timeout(void)
{
    Fixture fixture;
    setup(&fixture, false, false);
    uint32_t first = allocate(&fixture, 0U), second = allocate(&fixture, 1U);
    assert(initial(&fixture, first, 0x01U, 200U, UINT32_MAX - 100U) == CTAPHID_DEVICE_OK);
    size_t before = fixture.mock.count;
    poll_at(&fixture, 2898U);
    assert(fixture.mock.count == before && fixture.device.phase == CTAPHID_DEVICE_RECEIVING);
    poll_at(&fixture, 2899U);
    expect_error(&fixture, first, 0x05U);
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
    assert(initial(&fixture, first, 0x01U, 200U, 4000U) == CTAPHID_DEVICE_OK);
    assert(continuation(&fixture, first, 0U, 57U, 6999U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 9998U);
    assert(fixture.device.phase == CTAPHID_DEVICE_RECEIVING);
    /* Expiry notification does not prevent starting the new request. */
    before = fixture.mock.count;
    assert(initial(&fixture, second, 0x01U, 0U, 9999U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 9999U);
    assert(fixture.mock.count == before + 2U);
    assert(decode_cid(fixture.mock.reports[before]) == first && fixture.mock.reports[before][7] == 0x05U);
    assert(decode_cid(fixture.mock.reports[before + 1U]) == second && fixture.mock.reports[before + 1U][4] == 0x81U);
}

static void test_resynchronization(void)
{
    Fixture fixture;
    setup(&fixture, true, false);
    uint32_t cid = allocate(&fixture, 0U);
    assert(initial(&fixture, cid, 0x01U, 60U, 10U) == CTAPHID_DEVICE_OK);
    assert(initial(&fixture, cid, 0x06U, 8U, 11U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 11U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][4] == 0x86U);
    complete_transfer(&fixture);
    assert(initial(&fixture, cid, 0x01U, 60U, 20U) == CTAPHID_DEVICE_OK);
    assert(continuation(&fixture, cid, 0U, 57U, 21U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 21U);
    uint64_t old_token = fixture.device.flight_id;
    assert(initial(&fixture, cid, 0x06U, 7U, 22U) == CTAPHID_DEVICE_OK);
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING && fixture.mock.transport_aborts == 0U);
    assert(initial(&fixture, cid, 0x06U, 8U, 23U) == CTAPHID_DEVICE_OK);
    assert(fixture.mock.transport_aborts == 1U && fixture.mock.aborted_transfer == old_token);
    assert(ctaphid_device_report_sent(&fixture.device, old_token, true) == CTAPHID_DEVICE_IGNORED);
    poll_at(&fixture, 23U); /* Resync flushes old fragments and same-CID errors. */
    assert(fixture.mock.reports[fixture.mock.count - 1U][4] == 0x86U);
    assert(ctaphid_device_report_sent(&fixture.device, old_token, true) == CTAPHID_DEVICE_IGNORED);
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING);
    complete_transfer(&fixture);
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE && ctaphid_channels_is_allocated(&fixture.device.channels, cid));
}

static void test_cbor_cancellation_and_keepalive(void)
{
    Fixture fixture;
    setup(&fixture, false, true);
    uint32_t first = allocate(&fixture, 0U), second = allocate(&fixture, 1U);
    assert(initial(&fixture, first, 0x10U, 1U, 10U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 10U);
    assert(fixture.device.cbor_running && fixture.mock.cbor_starts == 1U);
    uint64_t operation = fixture.mock.operation;
    size_t before = fixture.mock.count;
    poll_at(&fixture, 109U);
    assert(fixture.mock.count == before);
    poll_at(&fixture, 110U);
    const uint8_t *reply = fixture.mock.reports[fixture.mock.count - 1U];
    assert(reply[4] == 0xBBU && reply[7] == 1U && fixture.device.phase == CTAPHID_DEVICE_PROCESSING);
    assert(ctaphid_device_set_keepalive(&fixture.device, operation, 2U, 111U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 111U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][7] == 2U);
    assert(ctaphid_device_set_keepalive(&fixture.device, operation, 3U, 112U) == CTAPHID_DEVICE_INVALID_ARGUMENT);
    before = fixture.mock.count;
    assert(initial(&fixture, second, 0x11U, 0U, 112U) == CTAPHID_DEVICE_IGNORED);
    assert(initial(&fixture, 0U, 0x11U, 0U, 112U) == CTAPHID_DEVICE_IGNORED);
    assert(initial(&fixture, first, 0x11U, 7610U, 112U) == CTAPHID_DEVICE_IGNORED);
    assert(initial(&fixture, first, 0x11U, 1U, 112U) == CTAPHID_DEVICE_IGNORED);
    assert(fixture.mock.count == before && fixture.mock.cbor_aborts == 0U);
    assert(initial(&fixture, first, 0x11U, 0U, 113U) == CTAPHID_DEVICE_OK);
    assert(fixture.mock.cbor_aborts == 1U && fixture.device.phase == CTAPHID_DEVICE_SENDING);
    const uint8_t late[] = {0, 0xA0};
    assert(ctaphid_device_complete_cbor(&fixture.device, operation, late, sizeof late) == CTAPHID_DEVICE_INVALID_STATE);
    poll_at(&fixture, 113U);
    reply = fixture.mock.reports[fixture.mock.count - 1U];
    assert(fixture.mock.count == before + 1U && reply[4] == 0x90U && reply[6] == 1U && reply[7] == 0x2DU);
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
    before = fixture.mock.count;
    assert(initial(&fixture, first, 0x11U, 0U, 114U) == CTAPHID_DEVICE_IGNORED);
    poll_at(&fixture, 114U);
    assert(fixture.mock.count == before);

    assert(initial(&fixture, first, 0x10U, 1U, 200U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 200U);
    uint64_t new_operation = fixture.mock.operation;
    assert(new_operation != operation);
    assert(ctaphid_device_complete_cbor(&fixture.device, operation, late, sizeof late) == CTAPHID_DEVICE_INVALID_STATE);
    poll_at(&fixture, 4000U); /* User-presence work does not expire after three seconds. */
    assert(fixture.device.cbor_running);
    assert(ctaphid_device_complete_cbor(&fixture.device, new_operation, NULL, 0U) == CTAPHID_DEVICE_INVALID_RESPONSE);
    assert(ctaphid_device_complete_cbor(&fixture.device, new_operation, late, sizeof late) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 4001U);
    reply = fixture.mock.reports[fixture.mock.count - 1U];
    assert(reply[4] == 0x90U && reply[6] == 2U && reply[7] == 0U && reply[8] == 0xA0U);
}

static void test_init_aborts_cbor(void)
{
    Fixture fixture;
    setup(&fixture, true, true);
    uint32_t cid = allocate(&fixture, 0U);
    assert(initial(&fixture, cid, 0x10U, 1U, 10U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 10U);
    uint64_t old_operation = fixture.mock.operation;
    poll_at(&fixture, 110U); /* In-flight keepalive must also be aborted. */
    uint64_t old_transfer = fixture.device.flight_id;
    assert(initial(&fixture, cid, 0x06U, 8U, 111U) == CTAPHID_DEVICE_OK);
    assert(fixture.mock.cbor_aborts == 1U && fixture.mock.transport_aborts == 1U);
    const uint8_t response[] = {0U};
    assert(ctaphid_device_complete_cbor(&fixture.device, old_operation, response, sizeof response) == CTAPHID_DEVICE_INVALID_STATE);
    assert(ctaphid_device_report_sent(&fixture.device, old_transfer, true) == CTAPHID_DEVICE_IGNORED);
    poll_at(&fixture, 111U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][4] == 0x86U);
    complete_transfer(&fixture);
}

static void test_transport_failures(void)
{
    Fixture fixture;
    setup(&fixture, true, false);
    uint32_t first = allocate(&fixture, 0U), second = allocate(&fixture, 1U);
    assert(initial(&fixture, first, 0x01U, 0U, 100U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 100U);
    uint64_t stale = fixture.device.flight_id;
    poll_at(&fixture, 3099U);
    assert(ctaphid_device_poll(&fixture.device, 3100U) == CTAPHID_DEVICE_TRANSPORT_FAILED);
    assert(fixture.mock.transport_aborts == 1U && fixture.device.phase == CTAPHID_DEVICE_IDLE);
    assert(ctaphid_device_report_sent(&fixture.device, stale, true) == CTAPHID_DEVICE_IGNORED);
    assert(initial(&fixture, first, 0x01U, 200U, 4000U) == CTAPHID_DEVICE_OK);
    assert(initial(&fixture, second, 0x01U, 0U, 4001U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 4001U);
    assert(ctaphid_device_report_sent(&fixture.device, fixture.device.flight_id, false) == CTAPHID_DEVICE_TRANSPORT_FAILED);
    assert(fixture.device.phase == CTAPHID_DEVICE_RECEIVING && fixture.device.active_channel_id == first);

    setup(&fixture, false, false);
    first = allocate(&fixture, 0U);
    fixture.mock.reject = true;
    assert(initial(&fixture, first, 0x01U, 0U, 10U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&fixture.device, 10U) == CTAPHID_DEVICE_TRANSPORT_FAILED);
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
}

static void test_cancel_outside_processing_and_async_keepalive(void)
{
    Fixture fixture;
    setup(&fixture, true, true);
    uint32_t cid = allocate(&fixture, 0U);
    assert(initial(&fixture, cid, 0x01U, 60U, 10U) == CTAPHID_DEVICE_OK);
    CtaphidReassembler saved = fixture.device.reassembler;
    assert(initial(&fixture, cid, 0x11U, 0U, 11U) == CTAPHID_DEVICE_IGNORED);
    assert(memcmp(&saved, &fixture.device.reassembler, sizeof saved) == 0);
    assert(continuation(&fixture, cid, 0U, 57U, 12U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 12U);
    size_t before = fixture.mock.count;
    assert(initial(&fixture, cid, 0x11U, 0U, 13U) == CTAPHID_DEVICE_IGNORED);
    assert(fixture.mock.count == before && fixture.device.phase == CTAPHID_DEVICE_SENDING);
    complete_transfer(&fixture);
    poll_at(&fixture, 13U);
    complete_transfer(&fixture);

    assert(initial(&fixture, cid, 0x10U, 1U, 20U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 20U);
    uint64_t operation = fixture.mock.operation;
    assert(ctaphid_device_set_keepalive(&fixture.device, operation, 1U, 21U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_set_keepalive(&fixture.device, operation, 2U, 22U) == CTAPHID_DEVICE_OK);
    assert(fixture.device.control_count == 1U);
    poll_at(&fixture, 22U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][7] == 2U);
    assert(ctaphid_device_set_keepalive(&fixture.device, operation, 1U, 23U) == CTAPHID_DEVICE_OK);
    assert(fixture.device.control_count == 1U);
    const uint8_t response[] = {0U};
    assert(ctaphid_device_complete_cbor(&fixture.device, operation, response, sizeof response) == CTAPHID_DEVICE_OK);
    assert(fixture.device.control_count == 0U); /* Drop the unsent keepalive. */
    complete_transfer(&fixture); /* In-flight keepalive does not finish the reply. */
    assert(fixture.device.phase == CTAPHID_DEVICE_SENDING);
    poll_at(&fixture, 24U);
    assert(fixture.mock.reports[fixture.mock.count - 1U][4] == 0x90U);
    complete_transfer(&fixture);
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
}

static void test_queue_backpressure(void)
{
    Fixture fixture;
    setup(&fixture, true, false);
    uint32_t first = allocate(&fixture, 0U), second = allocate(&fixture, 1U);
    assert(initial(&fixture, first, 0x01U, 200U, 10U) == CTAPHID_DEVICE_OK);
    for (size_t i = 0; i < CTAPHID_DEVICE_CONTROL_REPORTS; ++i) {
        assert(initial(&fixture, second, 0x01U, 0U, 11U) == CTAPHID_DEVICE_OK);
    }
    assert(initial(&fixture, second, 0x01U, 0U, 11U) == CTAPHID_DEVICE_QUEUE_FULL);
    poll_at(&fixture, 3010U); /* Must drain a slot even while expiry needs a slot. */
    assert(fixture.device.phase == CTAPHID_DEVICE_IDLE);
    while (fixture.device.in_flight || fixture.device.control_count != 0U) {
        if (fixture.device.in_flight) complete_transfer(&fixture);
        poll_at(&fixture, 3011U);
    }
    expect_error(&fixture, first, 0x05U);
}

static void test_config_validation(void)
{
    CtaphidDevice device = {0}, saved = device;
    CtaphidDeviceConfig config = {0};
    assert(ctaphid_device_init(&device, &config) == CTAPHID_DEVICE_INVALID_ARGUMENT);
    config.submit_report = submit;
    config.asynchronous_transport = true;
    assert(ctaphid_device_init(&device, &config) == CTAPHID_DEVICE_INVALID_ARGUMENT);
    config.abort_report = abort_report;
    config.start_cbor = start_cbor;
    assert(ctaphid_device_init(&device, &config) == CTAPHID_DEVICE_INVALID_ARGUMENT);
    assert(memcmp(&device, &saved, sizeof device) == 0);
    assert(ctaphid_device_poll(NULL, 0U) == CTAPHID_DEVICE_INVALID_ARGUMENT);
}

static void test_wink_platform_binding(void)
{
    Fixture fixture;
    setup(&fixture, false, false);
    uint32_t cid = allocate(&fixture, 0U);
    assert(initial(&fixture, cid, 0x08U, 1U, 10U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 10U);
    expect_error(&fixture, cid, 0x03U);
    assert(fixture.mock.winks == 0U);
    assert(initial(&fixture, cid, 0x08U, 0U, 11U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 11U);
    assert(fixture.mock.winks == 1U);

    /* An embedded build without an LED action must not promise WINK support. */
    setup(&fixture, false, false);
    CtaphidDeviceConfig config = fixture.device.config;
    config.wink_action = NULL;
    config.wink_context = NULL;
    assert(ctaphid_device_init(&fixture.device, &config) == CTAPHID_DEVICE_OK);
    cid = allocate(&fixture, 0U);
    assert(fixture.mock.reports[0][23] == 0x08U);
    assert(initial(&fixture, cid, 0x08U, 0U, 10U) == CTAPHID_DEVICE_OK);
    poll_at(&fixture, 10U);
    expect_error(&fixture, cid, 0x01U);
    assert(fixture.mock.winks == 0U);
}

int main(void)
{
    test_basic_commands();
    test_async_ownership();
    test_validation_and_sequence_errors();
    test_reception_timeout();
    test_resynchronization();
    test_cbor_cancellation_and_keepalive();
    test_init_aborts_cbor();
    test_transport_failures();
    test_cancel_outside_processing_and_async_keepalive();
    test_queue_backpressure();
    test_config_validation();
    test_wink_platform_binding();
    puts("CTAPHID device coordinator tests passed (CTAP 2.3 HID transaction behavior).");
    return 0;
}
