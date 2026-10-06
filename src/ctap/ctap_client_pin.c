#include "ctap/ctap_client_pin.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/ctap_request.h"
#include "ctap/cbor_writer.h"

#include <string.h>

bool ctap_client_pin_init(CtapClientPin *pin, AuthCredentialService *service, const AuthPinStorage *storage)
{
    if (pin == NULL || service == NULL || storage == NULL || storage->read == NULL || storage->write == NULL ||
        !auth_secret_crypto_valid(&service->secrets) || service->secrets.regenerate == NULL) return false;
    AuthPinRecord record = {0};
    bool valid = storage->read(storage->context, &record) == AUTH_OK && auth_pin_record_valid(&record);
    auth_secure_zero(&record, sizeof record);
    if (!valid) return false;
    *pin = (CtapClientPin){service, *storage, 0U, false};
    return true;
}

void ctap_client_pin_reset_state(CtapClientPin *pin)
{
    if (pin != NULL) { pin->consecutive_failures = 0U; pin->faulted = false; }
}

uint8_t ctap_client_pin_prepare(const uint8_t *input, size_t length, CtapClientPinRequest *request)
{
    if (request == NULL) return CTAP_STATUS_OTHER;
    CborValue fields[11] = {{0}}; bool present[11] = {false};
    uint8_t status = ctap_request_map(input, length, 11U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[2]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[2].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    uint64_t command = fields[2].value;
    if (command < 1U || command > 4U) return CTAP_STATUS_INVALID_SUBCOMMAND;
    if (present[1] && fields[1].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (command != 1U && !present[1]) return CTAP_STATUS_MISSING_PARAMETER;
    if (present[1] && fields[1].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    CtapClientPinRequest prepared = {0}; prepared.subcommand = (uint8_t)command;
    if (command >= 3U) {
        if (!present[3] || !present[4] || !present[5] || (command == 4U && !present[6]))
            return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[4].major != 2U || fields[5].major != 2U || (command == 4U && fields[6].major != 2U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (fields[5].value != 80U || (command == 4U && fields[6].value != 32U)) return CTAP_STATUS_INVALID_PARAMETER;
        if (fields[4].value != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
        /* ClientPIN COSE keys cannot include optional parameters other than alg. */
        if (fields[3].major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (fields[3].value != 5U) return CTAP_STATUS_INVALID_PARAMETER;
        status = ctap_pin_public_key_parse(&fields[3], prepared.peer);
        if (status != CTAP_STATUS_OK) return status;
        memcpy(prepared.new_pin_enc, fields[5].data, 80U);
        memcpy(prepared.auth, fields[4].data, 32U); prepared.auth_length = 32U;
        if (command == 4U) memcpy(prepared.pin_hash_enc, fields[6].data, 32U);
    }
    *request = prepared;
    return CTAP_STATUS_OK;
}

static bool persist(CtapClientPin *pin, const AuthPinRecord *record)
{
    if (pin->storage.write(pin->storage.context, record) == AUTH_OK) return true;
    pin->faulted = true;
    return false;
}

static uint8_t new_pin(CtapClientPin *pin, const uint8_t keys[64], const uint8_t encrypted[80], AuthPinRecord *record)
{
    uint8_t plain[64] = {0}, digest[32] = {0};
    const AuthSecretCrypto *crypto = &pin->service->secrets;
    uint8_t status = CTAP_STATUS_PIN_AUTH_INVALID;
    if (crypto->aes256_cbc(crypto->context, false, keys + 32U, encrypted, encrypted + 16U, 64U, plain) != AUTH_OK) goto done;
    size_t length = sizeof plain;
    while (length != 0U && plain[length - 1U] == 0U) --length;
    status = CTAP_STATUS_PIN_POLICY_VIOLATION;
    if (length > 63U || !cbor_utf8_valid(plain, length)) goto done;
    uint8_t points = 0U;
    for (size_t i = 0U; i < length; ++i) {
        if (plain[i] == 0U) goto done; /* Reject embedded U+0000, as an additional PIN constraint. */
        if ((plain[i] & 0xC0U) != 0x80U) ++points;
    }
    if (points < 4U) goto done;
    status = CTAP_STATUS_OTHER;
    if (pin->service->crypto.sha256(pin->service->crypto.context, plain, length, digest) != AUTH_OK) goto done;
    record->set = true; record->code_points = points; record->retries = AUTH_PIN_MAX_RETRIES;
    memcpy(record->hash, digest, 16U);
    status = CTAP_STATUS_OK;
done:
    auth_secure_zero(plain, sizeof plain); auth_secure_zero(digest, sizeof digest);
    return status;
}

uint8_t ctap_client_pin_execute(CtapClientPin *pin, const CtapClientPinRequest *request,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (pin == NULL || pin->service == NULL || request == NULL || output == NULL || length == NULL || pin->faulted)
        return CTAP_STATUS_OTHER;
    if (request->subcommand == 2U) return ctap_pin_key_agreement_encode(&pin->service->secrets, output, capacity, length);
    if (request->subcommand != 1U && request->subcommand != 3U && request->subcommand != 4U)
        return CTAP_STATUS_INVALID_SUBCOMMAND;
    AuthPinRecord record = {0};
    uint8_t keys[64] = {0}, message[112] = {0}, current_hash[16] = {0};
    const AuthSecretCrypto *crypto = &pin->service->secrets;
    uint8_t status = CTAP_STATUS_OTHER;
    if (pin->storage.read(pin->storage.context, &record) != AUTH_OK || !auth_pin_record_valid(&record)) {
        pin->faulted = true; goto done;
    }
    if (request->subcommand == 1U) {
        uint8_t encoded[8]; CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
        if (!cbor_write_map(&writer, 2U) || !cbor_write_uint(&writer, 3U) || !cbor_write_uint(&writer, record.retries) ||
            !cbor_write_uint(&writer, 4U) || !cbor_write_bool(&writer, pin->consecutive_failures >= 3U) || writer.length > capacity) goto done;
        memcpy(output, encoded, writer.length); *length = writer.length; status = CTAP_STATUS_OK; goto done;
    }
    if (request->subcommand == 3U && record.set) { status = CTAP_STATUS_PIN_AUTH_INVALID; goto done; }
    if (request->subcommand == 4U) {
        if (!record.set) { status = CTAP_STATUS_PIN_NOT_SET; goto done; }
        if (record.retries == 0U) { status = CTAP_STATUS_PIN_BLOCKED; goto done; }
        if (pin->consecutive_failures >= 3U) { status = CTAP_STATUS_PIN_AUTH_BLOCKED; goto done; }
    }
    status = ctap_pin_protocol_shared(crypto, request->peer, keys);
    if (status != CTAP_STATUS_OK) goto done;
    memcpy(message, request->new_pin_enc, 80U);
    if (request->subcommand == 4U) memcpy(message + 80U, request->pin_hash_enc, 32U);
    status = ctap_pin_protocol_verify(crypto, keys, message, request->subcommand == 4U ? 112U : 80U,
        request->auth, request->auth_length);
    if (status != CTAP_STATUS_OK) goto done;
    if (request->subcommand == 4U) {
        /* Persist before decrypting/trying the verifier, including crash recovery. */
        --record.retries;
        status = CTAP_STATUS_OTHER;
        if (!persist(pin, &record)) goto done;
        if (crypto->aes256_cbc(crypto->context, false, keys + 32U, request->pin_hash_enc,
            request->pin_hash_enc + 16U, 16U, current_hash) != AUTH_OK || !ctap_pin_equal(record.hash, current_hash, 16U)) {
            ++pin->consecutive_failures;
            if (crypto->regenerate(crypto->context) != AUTH_OK) { pin->faulted = true; goto done; }
            status = record.retries == 0U ? CTAP_STATUS_PIN_BLOCKED :
                (pin->consecutive_failures >= 3U ? CTAP_STATUS_PIN_AUTH_BLOCKED : CTAP_STATUS_PIN_INVALID);
            goto done;
        }
        record.retries = AUTH_PIN_MAX_RETRIES;
        if (!persist(pin, &record)) goto done;
        pin->consecutive_failures = 0U;
    }
    status = new_pin(pin, keys, request->new_pin_enc, &record);
    if (status != CTAP_STATUS_OK) goto done;
    if (!persist(pin, &record)) { status = CTAP_STATUS_OTHER; goto done; }
    pin->consecutive_failures = 0U;
    *length = 0U;
done:
    auth_secure_zero(&record, sizeof record); auth_secure_zero(keys, sizeof keys);
    auth_secure_zero(message, sizeof message); auth_secure_zero(current_hash, sizeof current_hash);
    return status;
}
