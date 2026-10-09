#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap.h"
#include "ctap/cbor_writer.h"
#include "ctap/cbor_reader.h"
#include "protocol/ctaphid_ctap_backend.h"

/* Independent wire vector for the minimal configured CTAP 2.3 profile. */
static const uint8_t expected_info[] = {
    0xA8, 0x01, 0x81, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x33, 0x02, 0x82, 0x6B, 0x68,
    0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x6E, 0x68, 0x6D, 0x61, 0x63, 0x2D,
    0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2D, 0x6D, 0x63, 0x03, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xA4, 0x62, 0x72, 0x6B,
    0xF4, 0x62, 0x75, 0x70, 0xF5, 0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4, 0x70, 0x6D, 0x61, 0x6B, 0x65,
    0x43, 0x72, 0x65, 0x64, 0x55, 0x76, 0x4E, 0x6F, 0x74, 0x52, 0x71, 0x64, 0xF5, 0x05, 0x19, 0x04,
    0x00, 0x06, 0x81, 0x02, 0x0A, 0x81, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70,
    0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x16, 0x81, 0x66, 0x70,
    0x61, 0x63, 0x6B, 0x65, 0x64,
};

static void test_cbor_primitive_vectors(void)
{
    const struct { uint64_t value; uint8_t bytes[9]; size_t length; } cases[] = {
        {0U, {0x00}, 1U}, {23U, {0x17}, 1U}, {24U, {0x18, 0x18}, 2U},
        {255U, {0x18, 0xFF}, 2U}, {256U, {0x19, 0x01, 0x00}, 3U},
        {65535U, {0x19, 0xFF, 0xFF}, 3U},
        {65536U, {0x1A, 0x00, 0x01, 0x00, 0x00}, 5U},
        {UINT32_MAX, {0x1A, 0xFF, 0xFF, 0xFF, 0xFF}, 5U},
        {UINT64_MAX, {0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 9U}
    };
    uint8_t output[16];
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        CborWriter writer;
        cbor_writer_init(&writer, output, sizeof output);
        assert(cbor_write_uint(&writer, cases[i].value));
        assert(writer.length == cases[i].length);
        assert(memcmp(output, cases[i].bytes, writer.length) == 0);
        for (size_t capacity = 0; capacity < cases[i].length; ++capacity) {
            cbor_writer_init(&writer, output, capacity);
            assert(!cbor_write_uint(&writer, cases[i].value));
            assert(writer.failed && writer.length == 0U);
            assert(!cbor_write_bool(&writer, true));
        }
    }
    CborWriter writer;
    cbor_writer_init(&writer, output, 2U);
    assert(!cbor_write_text(&writer, "long"));
    assert(writer.failed && writer.length == 0U);
    cbor_writer_init(&writer, output, sizeof output);
    assert(cbor_write_bool(&writer, false) && cbor_write_bool(&writer, true));
    assert(output[0] == 0xF4U && output[1] == 0xF5U);
    cbor_writer_init(&writer, NULL, 0U);
    assert(!cbor_write_map(&writer, 1U));
    cbor_writer_init(&writer, output, sizeof output);
    assert(!cbor_write_bytes(&writer, NULL, 1U) && writer.length == 0U);
}

static void test_get_info_encoding_and_bounds(void)
{
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = 1024U;
    profile.make_credential = profile.hmac_secret = profile.user_presence = true;
    uint8_t output[CTAP_MAX_RESPONSE_SIZE], saved[CTAP_MAX_RESPONSE_SIZE];
    size_t length = 0U;
    assert(ctap_get_info_encode(&profile, output, sizeof output, &length));
    assert(length == sizeof expected_info);
    assert(memcmp(output, expected_info, length) == 0);
    for (size_t capacity = 0; capacity < sizeof expected_info; ++capacity) {
        memset(output, 0xEE, sizeof output);
        memcpy(saved, output, sizeof saved);
        length = 999U;
        assert(!ctap_get_info_encode(&profile, output, capacity, &length));
        assert(length == 999U && memcmp(output, saved, sizeof output) == 0);
    }
    /* A production application supplies its stable AAGUID; no hardcoded identity. */
    for (size_t i = 0; i < 16U; ++i) profile.aaguid[i] = (uint8_t)(i + 1U);
    assert(ctap_get_info_encode(&profile, output, sizeof output, &length));
    CborValue map, value;
    assert(cbor_read_document(output, length, &map) && cbor_map_uint(&map, 3U, &value));
    assert(value.value == 16U && memcmp(value.data, profile.aaguid, 16U) == 0);
    profile.pin_uv_auth = true;
    assert(ctap_get_info_encode(&profile, output, sizeof output, &length));
    assert(cbor_read_document(output, length, &map) && cbor_map_uint(&map, 13U, &value) && value.value == 4U);
    profile.hmac_secret = false;
    assert(!ctap_get_info_encode(&profile, output, sizeof output, &length));
    profile.hmac_secret = true;
    profile.make_credential = false;
    assert(!ctap_get_info_encode(&profile, output, sizeof output, &length));
    profile.make_credential = true;
    assert(!ctap_get_info_encode(NULL, output, sizeof output, &length));
    profile.max_message_size = 0U;
    assert(!ctap_get_info_encode(&profile, output, sizeof output, &length));
}

static void test_ctap_command_statuses(void)
{
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = 1024U;
    profile.make_credential = profile.hmac_secret = profile.user_presence = true;
    uint8_t output[CTAP_MAX_RESPONSE_SIZE];
    const uint8_t request[] = {0x04};
    size_t length;
    assert(ctap_execute(&profile, request, sizeof request, output, sizeof output, &length));
    assert(length == 1U + sizeof expected_info && output[0] == 0U);
    assert(memcmp(output + 1U, expected_info, sizeof expected_info) == 0);
    const uint8_t invalid_length[] = {0x04, 0xA0};
    assert(ctap_execute(&profile, invalid_length, sizeof invalid_length, output, sizeof output, &length));
    assert(length == 1U && output[0] == 0x03U);
    const uint8_t unsupported[] = {0x01, 0xA0};
    assert(ctap_execute(&profile, unsupported, sizeof unsupported, output, sizeof output, &length));
    assert(length == 1U && output[0] == 0x01U);
    assert(ctap_execute(&profile, request, 0U, output, sizeof output, &length));
    assert(length == 1U && output[0] == 0x03U);
    memset(output, 0xEE, sizeof output);
    uint8_t saved[sizeof output];
    memcpy(saved, output, sizeof saved);
    length = 999U;
    assert(!ctap_execute(&profile, request, sizeof request, output, 1U, &length));
    assert(length == 999U && memcmp(output, saved, sizeof saved) == 0);
}

typedef struct { uint8_t report[64]; size_t count; } Transport;

static bool submit(void *context, const uint8_t report[64], uint64_t transfer_id)
{
    Transport *transport = context;
    (void)transfer_id;
    memcpy(transport->report, report, sizeof transport->report);
    ++transport->count;
    return true;
}

static void receive(CtaphidDevice *device, uint8_t command, uint8_t data, uint32_t now)
{
    uint8_t report[64] = {0, 0, 0, 1};
    report[4] = (uint8_t)(command | 0x80U);
    report[6] = command == 0x06U ? 8U : (command == 0x11U ? 0U : 1U);
    report[7] = data;
    assert(ctaphid_device_receive_report(device, report, sizeof report, now) == CTAPHID_DEVICE_OK);
}

static void test_backend_coordinator_bridge(void)
{
    CtapGetInfoProfile profile = {0};
    profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE;
    CtaphidCtapBackend backend;
    assert(ctaphid_ctap_backend_init(&backend, &profile));
    Transport transport = {0};
    CtaphidDeviceConfig config = {0};
    config.submit_report = submit;
    config.transport_context = &transport;
    config.start_cbor = ctaphid_ctap_backend_start;
    config.abort_cbor = ctaphid_ctap_backend_abort;
    config.cbor_context = &backend;
    CtaphidDevice device;
    assert(ctaphid_device_init(&device, &config) == CTAPHID_DEVICE_OK);
    uint32_t cid;
    assert(ctaphid_channels_allocate(&device.channels, &cid) == CTAPHID_CHANNEL_OK && cid == 1U);
    receive(&device, 0x10U, 0x04U, 1U);
    assert(ctaphid_device_poll(&device, 1U) == CTAPHID_DEVICE_OK);
    assert(backend.pending && transport.count == 0U && device.cbor_running);
    assert(ctaphid_ctap_backend_poll(&backend, &device, 5U) == CTAPHID_DEVICE_OK);
    assert(!backend.pending && device.phase == CTAPHID_DEVICE_SENDING);
    assert(ctaphid_device_poll(&device, 1U) == CTAPHID_DEVICE_OK);
    assert(transport.count == 1U && device.phase == CTAPHID_DEVICE_IDLE);
    /* An unbound backend cannot advertise an authenticator version. */
    assert(transport.report[4] == 0x90U && transport.report[6] == 1U);
    assert(transport.report[7] == CTAP_STATUS_OTHER);

    /* Prepared work can be cancelled without reentering coordinator callbacks. */
    receive(&device, 0x10U, 0x04U, 2U);
    assert(ctaphid_device_poll(&device, 2U) == CTAPHID_DEVICE_OK && backend.pending);
    receive(&device, 0x11U, 0U, 3U);
    assert(!backend.pending);
    assert(ctaphid_ctap_backend_poll(&backend, &device, 5U) == CTAPHID_DEVICE_OK);
    assert(ctaphid_device_poll(&device, 3U) == CTAPHID_DEVICE_OK);
    assert(transport.report[4] == 0x90U && transport.report[7] == 0x2DU);

    receive(&device, 0x10U, 0x04U, 4U);
    assert(ctaphid_device_poll(&device, 4U) == CTAPHID_DEVICE_OK && backend.pending);
    receive(&device, 0x06U, 0xAAU, 5U);
    assert(!backend.pending);
    assert(ctaphid_device_poll(&device, 5U) == CTAPHID_DEVICE_OK);
    assert(transport.report[4] == 0x86U && transport.report[23] == 0x0CU);

    /* Stale prepared results cannot complete a newer/idle transaction. */
    const uint8_t request[] = {0x04};
    ctaphid_ctap_backend_start(&backend, 999U, request, sizeof request);
    assert(ctaphid_ctap_backend_poll(&backend, &device, 5U) == CTAPHID_DEVICE_IGNORED);
    assert(!backend.pending && device.phase == CTAPHID_DEVICE_IDLE);
    profile.max_message_size = CTAPHID_MAX_MESSAGE_SIZE + 1U;
    assert(!ctaphid_ctap_backend_init(&backend, &profile));
}

int main(void)
{
    test_cbor_primitive_vectors();
    test_get_info_encoding_and_bounds();
    test_ctap_command_statuses();
    test_backend_coordinator_bridge();
    puts("CTAP GetInfo tests passed (canonical CBOR, bounds, statuses, backend lifecycle).");
    return 0;
}
