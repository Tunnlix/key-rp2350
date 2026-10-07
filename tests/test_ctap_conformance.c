#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctap/ctap_entities.h"
#include "ctap/ctap_request.h"
#include "ctap/ctap_pin_protocol.h"
#include "protocol/ctaphid_ctap_backend.h"
#include "protocol/ctaphid_response.h"
#include "auth_test_provider.h"

/* Regression checks for normative decoding and error precedence. Primitive
 * callbacks here are deterministic mocks, not cryptographic implementations. */
static void test_unknown_key_namespaces(void)
{
    uint8_t encoded[128]; CborWriter w; cbor_writer_init(&w, encoded, sizeof encoded);
    assert(cbor_write_map(&w, 4U) && cbor_write_uint(&w, 1U) && cbor_write_uint(&w, 7U) &&
        cbor_write_int(&w, -1) && cbor_write_uint(&w, 8U) &&
        cbor_write_text(&w, "future") && cbor_write_bool(&w, true) &&
        cbor_write_bool(&w, true) && cbor_write_bool(&w, false));
    CborValue fields[3] = {{0}}; bool present[3] = {false};
    assert(ctap_request_map(encoded, w.length, 3U, fields, present) == CTAP_STATUS_OK);
    assert(!present[0] && present[1] && !present[2] && fields[1].value == 7U);
    cbor_writer_init(&w, encoded, sizeof encoded);
    assert(cbor_write_map(&w, 2U) && cbor_write_uint(&w, 1U) && cbor_write_bool(&w, true) &&
        cbor_write_text(&w, "id") && cbor_write_bytes(&w, NULL, 0U));
    CborValue map; AuthCredential user = {0};
    assert(cbor_read_document(encoded, w.length, &map));
    assert(ctap_user_entity_parse(&map, &user) == CTAP_STATUS_OK && user.user_id_length == 0U);
}

static void test_client_pin_known_optional_types(void)
{
    const uint8_t cases[][8] = {
        {0xA2, 2, 1, 3, 0xF4}, /* getRetries + non-map keyAgreement */
        {0xA2, 2, 1, 4, 0xF4}, /* non-bytes auth */
        {0xA2, 2, 1, 5, 0xF4}, /* non-bytes newPinEnc */
        {0xA2, 2, 1, 6, 0xF4}, /* non-bytes pinHashEnc */
        {0xA2, 2, 1, 9, 0xF4}, /* non-uint permissions */
        {0xA2, 2, 1, 10, 0xF4} /* non-text RP ID */
    };
    CtapClientPinRequest parsed, saved; memset(&parsed, 0xEE, sizeof parsed); saved = parsed;
    for (size_t i = 0U; i < sizeof cases / sizeof cases[0]; ++i) {
        assert(ctap_client_pin_prepare(cases[i], 5U, &parsed) == CTAP_STATUS_CBOR_UNEXPECTED_TYPE);
        assert(memcmp(&parsed, &saved, sizeof parsed) == 0);
    }
    const uint8_t future[] = {0xA2, 2, 1, 0x66, 'f','u','t','u','r','e', 0xF4};
    assert(ctap_client_pin_prepare(future, sizeof future, &parsed) == CTAP_STATUS_OK && parsed.subcommand == 1U);
}

static void test_public_key_unknown_and_forbidden_parameters(void)
{
    for (unsigned known_optional = 0U; known_optional <= 1U; ++known_optional) {
        uint8_t encoded[128], point[32] = {1}, decoded[65];
        CborWriter w; cbor_writer_init(&w, encoded, sizeof encoded);
        assert(cbor_write_map(&w, 6U) && cbor_write_uint(&w, 1U) && cbor_write_uint(&w, 2U));
        if (known_optional) assert(cbor_write_uint(&w, 2U) && cbor_write_bytes(&w, NULL, 0U));
        assert(cbor_write_uint(&w, 3U) && cbor_write_int(&w, -25));
        if (!known_optional) assert(cbor_write_uint(&w, 99U) && cbor_write_bool(&w, false));
        assert(cbor_write_int(&w, -1) && cbor_write_uint(&w, 1U) &&
            cbor_write_int(&w, -2) && cbor_write_bytes(&w, point, 32U) &&
            cbor_write_int(&w, -3) && cbor_write_bytes(&w, point, 32U));
        CborValue map; assert(cbor_read_document(encoded, w.length, &map));
        assert(ctap_pin_public_key_parse(&map, decoded) ==
            (known_optional ? CTAP_STATUS_INVALID_PARAMETER : CTAP_STATUS_OK));
    }
}

typedef struct {
    Store store; AuthCredentialService service; CtapClientPin pin;
    CtaphidCtapBackend backend; CtaphidDevice device; uint32_t now;
} ExclusionFixture;
static AuthStatus mock_mac(void *ctx, const uint8_t *key, size_t key_length,
    const uint8_t *message, size_t message_length, uint8_t out[32])
{ (void)ctx; (void)key; (void)key_length; (void)message; (void)message_length; memset(out, 0x3C, 32U); return AUTH_OK; }
static bool send(void *ctx, const uint8_t report[64], uint64_t transfer)
{ (void)ctx; (void)report; (void)transfer; return true; }
static bool reset(void *ctx)
{ (void)ctx; return true; }
static bool receive(void *ctx, const uint8_t report[64])
{ ExclusionFixture *f = ctx; return ctaphid_device_receive_report(&f->device, report, 64U, f->now) == CTAPHID_DEVICE_OK; }
static void test_excluded_result_survives_token_expiry(void)
{
    for (unsigned confirmed = 0U; confirmed <= 1U; ++confirmed) {
        ExclusionFixture f = {0}; service_init(&f.service, &f.store);
        f.service.secrets.hmac_sha256 = mock_mac;
        uint8_t rp[32], public_key[65], client_hash[32] = {0}, mac_bytes[32];
        memset(rp, 0x42, 32U); memset(mac_bytes, 0x3C, 32U); AuthCredential credential;
        assert(auth_credentials_create(&f.service, rp, NULL, 0U, false, &credential, public_key) == AUTH_OK);
        f.pin.service = &f.service; f.pin.pin_set = true; f.pin.token_active = f.pin.token_used = true;
        f.pin.permissions = CTAP_PIN_PERMISSION_MC; f.pin.token_generation = 1U; f.pin.token_rp_bound = true;
        memcpy(f.pin.token_rp_hash, rp, 32U);
        CtapGetInfoProfile profile = {0}; profile.max_message_size = 1024U; profile.user_presence = true;
        assert(ctaphid_ctap_backend_init(&f.backend, &profile));
        assert(ctaphid_ctap_backend_configure_credentials(&f.backend, &f.service));
        assert(ctaphid_ctap_backend_configure_reset(&f.backend, 0U, reset, &f));
        assert(ctaphid_ctap_backend_configure_pin(&f.backend, &f.pin));
        CtaphidDeviceConfig config = {0}; config.submit_report = send; config.transport_context = &f;
        config.start_cbor = ctaphid_ctap_backend_start; config.abort_cbor = ctaphid_ctap_backend_abort; config.cbor_context = &f.backend;
        assert(ctaphid_device_init(&f.device, &config) == CTAPHID_DEVICE_OK);
        uint32_t cid; assert(ctaphid_channels_allocate(&f.device.channels, &cid) == CTAPHID_CHANNEL_OK);
        uint8_t request[512]; request[0] = CTAP_COMMAND_MAKE_CREDENTIAL;
        CborWriter w; cbor_writer_init(&w, request + 1U, sizeof request - 1U);
        assert(cbor_write_map(&w, 7U) && cbor_write_uint(&w, 1U) && cbor_write_bytes(&w, client_hash, 32U) &&
            cbor_write_uint(&w, 2U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "id") && cbor_write_text(&w, "example.com") &&
            cbor_write_uint(&w, 3U) && cbor_write_map(&w, 1U) && cbor_write_text(&w, "id") && cbor_write_bytes(&w, NULL, 0U) &&
            cbor_write_uint(&w, 4U) && cbor_write_array(&w, 1U) && cbor_write_map(&w, 2U) &&
            cbor_write_text(&w, "alg") && cbor_write_int(&w, -7) && cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key") &&
            cbor_write_uint(&w, 5U) && cbor_write_array(&w, 1U) && cbor_write_map(&w, 2U) &&
            cbor_write_text(&w, "id") && cbor_write_bytes(&w, credential.credential_id, 32U) &&
            cbor_write_text(&w, "type") && cbor_write_text(&w, "public-key") &&
            cbor_write_uint(&w, 8U) && cbor_write_bytes(&w, mac_bytes, 32U) && cbor_write_uint(&w, 9U) && cbor_write_uint(&w, 2U));
        f.now = 599990U;
        assert(ctaphid_send_response(cid, 0x10U, request, 1U + w.length, receive, &f) == CTAPHID_RESPONSE_OK);
        assert(ctaphid_device_poll(&f.device, f.now) == CTAPHID_DEVICE_OK);
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, f.now) == CTAPHID_DEVICE_OK);
        assert(f.backend.make_credential.credential_excluded && f.backend.awaiting_presence);
        uint32_t end = confirmed ? 600001U : 629990U;
        if (confirmed) assert(ctaphid_ctap_backend_signal_presence(&f.backend, f.backend.operation_id, true, end));
        assert(ctaphid_ctap_backend_poll(&f.backend, &f.device, end) == CTAPHID_DEVICE_OK);
        assert(f.backend.response[0] == CTAP_STATUS_CREDENTIAL_EXCLUDED && !f.pin.token_active);
        assert(f.store.generated == 1U && f.store.signatures == 0U);
    }
}

int main(void)
{
    test_unknown_key_namespaces();
    test_client_pin_known_optional_types();
    test_public_key_unknown_and_forbidden_parameters();
    test_excluded_result_survives_token_expiry();
    puts("CTAP conformance regressions passed (unknown keys, typed PIN members, COSE keys, exclusion precedence).");
    return 0;
}
