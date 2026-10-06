#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/ctaphid_response.h"

/* Fake transport copies reports, just as a real asynchronous queue must do. */
typedef struct {
    uint8_t reports[129][CTAPHID_REPORT_SIZE];
    size_t accepted;
    size_t attempted;
    size_t fail_at;
} CapturedReports;

static bool capture_report(void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    CapturedReports *capture = context;
    ++capture->attempted;
    if (capture->attempted == capture->fail_at) return false;
    assert(capture->accepted < 129U);
    memcpy(capture->reports[capture->accepted++], report, CTAPHID_REPORT_SIZE);
    return true;
}

static size_t expected_report_count(size_t length)
{
    if (length <= 57U) return 1U;
    return 1U + (length - 57U + 58U) / 59U;
}

/* Inspect raw bytes independently of the parser: shared encoder/decoder bugs
 * must not be able to make a round-trip test pass. */
static void verify_reports(const CapturedReports *capture, uint8_t command,
    const uint8_t *payload, size_t length)
{
    assert(capture->accepted == expected_report_count(length));
    assert(capture->attempted == capture->accepted);
    size_t offset = 0U;
    for (size_t index = 0; index < capture->accepted; ++index) {
        const uint8_t *report = capture->reports[index];
        assert(report[0] == 0x12U && report[1] == 0x34U);
        assert(report[2] == 0x56U && report[3] == 0x78U);
        size_t header = index == 0U ? 7U : 5U;
        if (index == 0U) {
            assert(report[4] == (uint8_t)(command | 0x80U));
            assert(report[5] == (uint8_t)(length >> 8));
            assert(report[6] == (uint8_t)length);
        } else {
            assert(report[4] == (uint8_t)(index - 1U));
        }
        size_t count = length - offset;
        if (count > 64U - header) count = 64U - header;
        for (size_t i = 0; i < count; ++i) {
            assert(report[header + i] == payload[offset + i]);
        }
        for (size_t i = header + count; i < 64U; ++i) {
            assert(report[i] == 0U);
        }
        offset += count;
    }
    assert(offset == length);
}

static void test_all_wire_lengths(void)
{
    uint8_t payload[CTAPHID_MAX_WIRE_MESSAGE_SIZE];
    uint8_t original[CTAPHID_MAX_WIRE_MESSAGE_SIZE];
    for (size_t i = 0; i < sizeof payload; ++i) {
        payload[i] = (uint8_t)(i * 37U + 11U);
    }
    memcpy(original, payload, sizeof original);
    for (size_t length = 0; length <= sizeof payload; ++length) {
        CapturedReports capture = {0};
        assert(ctaphid_send_response(0x12345678U, 0x01U, payload, length,
            capture_report, &capture) == CTAPHID_RESPONSE_OK);
        verify_reports(&capture, 0x01U, payload, length);
    }
    assert(memcmp(payload, original, sizeof payload) == 0);
}

static void test_empty_and_error_responses(void)
{
    CapturedReports capture = {0};
    assert(ctaphid_send_response(0x12345678U, 0x08U, NULL, 0U,
        capture_report, &capture) == CTAPHID_RESPONSE_OK);
    verify_reports(&capture, 0x08U, NULL, 0U);

    memset(&capture, 0, sizeof capture);
    const uint8_t invalid_sequence = 0x04U;
    assert(ctaphid_send_response(0x12345678U, 0x3FU, &invalid_sequence, 1U,
        capture_report, &capture) == CTAPHID_RESPONSE_OK);
    const uint8_t expected[64] = {0x12, 0x34, 0x56, 0x78, 0xBF, 0x00, 0x01, 0x04};
    assert(capture.accepted == 1U);
    assert(memcmp(capture.reports[0], expected, sizeof expected) == 0);

    /* Broadcast INIT replies retain the broadcast CID in their header. */
    memset(&capture, 0, sizeof capture);
    uint8_t init_payload[17] = {0};
    assert(ctaphid_send_response(UINT32_MAX, 0x06U, init_payload, sizeof init_payload,
        capture_report, &capture) == CTAPHID_RESPONSE_OK);
    for (size_t i = 0; i < 4U; ++i) assert(capture.reports[0][i] == 0xFFU);
    assert(capture.reports[0][4] == 0x86U && capture.reports[0][6] == 17U);
}

static void test_validation_before_sending(void)
{
    CapturedReports capture = {0};
    const uint8_t payload = 0U;
    assert(ctaphid_send_response(1U, 1U, NULL, 1U, capture_report, &capture) ==
        CTAPHID_RESPONSE_INVALID_ARGUMENT);
    assert(ctaphid_send_response(1U, 1U, &payload, 1U, NULL, &capture) ==
        CTAPHID_RESPONSE_INVALID_ARGUMENT);
    for (unsigned command = 128U; command <= 255U; ++command) {
        assert(ctaphid_send_response(1U, (uint8_t)command, &payload, 1U,
            capture_report, &capture) == CTAPHID_RESPONSE_INVALID_COMMAND);
    }
    assert(ctaphid_send_response(1U, 1U, &payload, 7610U, capture_report, &capture) ==
        CTAPHID_RESPONSE_INVALID_LENGTH);
    assert(ctaphid_send_response(1U, 1U, &payload, SIZE_MAX, capture_report, &capture) ==
        CTAPHID_RESPONSE_INVALID_LENGTH);
    assert(capture.attempted == 0U);
}

static void test_all_seven_bit_commands(void)
{
    /* Framing accepts vendor commands too; command support belongs to dispatch. */
    for (unsigned command = 0U; command <= 127U; ++command) {
        CapturedReports capture = {0};
        assert(ctaphid_send_response(0x12345678U, (uint8_t)command, NULL, 0U,
            capture_report, &capture) == CTAPHID_RESPONSE_OK);
        verify_reports(&capture, (uint8_t)command, NULL, 0U);
    }
}

static void test_transport_failure(void)
{
    const uint8_t payload[200] = {0};
    for (size_t failure = 1U; failure <= expected_report_count(sizeof payload); ++failure) {
        CapturedReports capture = {0};
        capture.fail_at = failure;
        assert(ctaphid_send_response(1U, 1U, payload, sizeof payload,
            capture_report, &capture) == CTAPHID_RESPONSE_SEND_FAILED);
        assert(capture.attempted == failure);
        assert(capture.accepted == failure - 1U);
    }
}

int main(void)
{
    test_all_wire_lengths();
    test_empty_and_error_responses();
    test_validation_before_sending();
    test_all_seven_bit_commands();
    test_transport_failure();
    puts("CTAPHID response tests passed (all payload lengths 0..7609).");
    return 0;
}
