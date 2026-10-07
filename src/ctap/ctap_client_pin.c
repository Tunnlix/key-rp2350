#include "ctap/ctap_client_pin.h"
#include "ctap/ctap_pin_protocol.h"
#include "ctap/ctap_request.h"
#include "ctap/cbor_writer.h"

#include <string.h>

static bool reset_token(CtapClientPin *pin)
{
    ctap_client_pin_invalidate(pin);
    if (pin->token_generation == UINT64_MAX) { pin->faulted = true; return false; }
    ++pin->token_generation;
    if (pin->service->crypto.random(pin->service->crypto.context, pin->token, sizeof pin->token) == AUTH_OK) return true;
    auth_secure_zero(pin->token, sizeof pin->token); pin->faulted = true; return false;
}

bool ctap_client_pin_init(CtapClientPin *pin, AuthCredentialService *service, const AuthPinStorage *storage)
{
    if (pin == NULL || service == NULL || storage == NULL || storage->read == NULL || storage->write == NULL ||
        !auth_secret_crypto_valid(&service->secrets) || service->secrets.regenerate == NULL ||
        service->crypto.random == NULL || service->crypto.sha256 == NULL) return false;
    AuthPinRecord record = {0};
    bool valid = storage->read(storage->context, &record) == AUTH_OK && auth_pin_record_valid(&record);
    bool set = record.set;
    auth_secure_zero(&record, sizeof record);
    if (!valid) return false;
    uint8_t fresh[32] = {0};
    if (service->crypto.random(service->crypto.context, fresh, sizeof fresh) != AUTH_OK) {
        auth_secure_zero(fresh, sizeof fresh); return false;
    }
    AuthPinStorage copied = *storage;
    auth_secure_zero(pin, sizeof *pin);
    pin->service = service; pin->storage = copied; pin->pin_set = set;
    pin->credential_management = auth_credentials_resident_supported(service);
    memcpy(pin->token, fresh, sizeof fresh); auth_secure_zero(fresh, sizeof fresh);
    return true;
}

void ctap_client_pin_reset_state(CtapClientPin *pin)
{
    if (pin != NULL) {
        pin->consecutive_failures = 0U; pin->faulted = false; pin->pin_set = false;
        (void)reset_token(pin);
    }
}

uint8_t ctap_client_pin_prepare(const uint8_t *input, size_t length, CtapClientPinRequest *request)
{
    if (request == NULL) return CTAP_STATUS_OTHER;
    CborValue fields[11] = {{0}}; bool present[11] = {false};
    uint8_t status = ctap_request_map(input, length, 11U, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    if (!present[2]) return CTAP_STATUS_MISSING_PARAMETER;
    if (fields[2].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    /* Known optional members retain their declared types even on subcommands
     * that do not use their values. Unknown members remain ignored (§8). */
    if ((present[3] && fields[3].major != 5U) ||
        (present[4] && fields[4].major != 2U) || (present[5] && fields[5].major != 2U) ||
        (present[6] && fields[6].major != 2U) || (present[9] && fields[9].major != 0U) ||
        (present[10] && fields[10].major != 3U)) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    uint64_t command = fields[2].value;
    if ((command < 1U || command > 4U) && command != 9U) return CTAP_STATUS_INVALID_SUBCOMMAND;
    if (present[1] && fields[1].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (command != 1U && !present[1]) return CTAP_STATUS_MISSING_PARAMETER;
    if (present[1] && fields[1].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    CtapClientPinRequest prepared = {0}; prepared.subcommand = (uint8_t)command;
    if (command == 9U) {
        if (!present[3] || !present[6] || !present[9]) return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[6].major != 2U || fields[9].major != 0U || (present[10] && fields[10].major != 3U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        /* RP ID is mandatory for MC/GA, before permission availability (§6.5.5.7.2). */
        if ((fields[9].value & 3U) != 0U && !present[10]) return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[6].value != 32U || fields[9].value == 0U) return CTAP_STATUS_INVALID_PARAMETER;
        /* Known unavailable permissions are rejected; undefined bits ignored. */
        if ((fields[9].value & 0x78U) != 0U) return CTAP_STATUS_UNAUTHORIZED_PERMISSION;
        if (present[10] && (fields[10].value == 0U || fields[10].value > sizeof prepared.rp_id))
            return CTAP_STATUS_INVALID_PARAMETER;
        prepared.permissions = fields[9].value & 7U;
        prepared.rp_present = present[10];
        if (present[10]) {
            prepared.rp_length = (size_t)fields[10].value;
            memcpy(prepared.rp_id, fields[10].data, prepared.rp_length);
        }
        if (fields[3].major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        status = ctap_pin_public_key_parse(&fields[3], prepared.peer);
        if (status != CTAP_STATUS_OK) return status;
        memcpy(prepared.pin_hash_enc, fields[6].data, 32U);
        *request = prepared; return CTAP_STATUS_OK;
    }
    if (command >= 3U) {
        if (!present[3] || !present[4] || !present[5] || (command == 4U && !present[6]))
            return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[4].major != 2U || fields[5].major != 2U || (command == 4U && fields[6].major != 2U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (fields[5].value != 80U || (command == 4U && fields[6].value != 32U)) return CTAP_STATUS_INVALID_PARAMETER;
        if (fields[4].value != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
        /* ClientPIN COSE keys cannot include optional parameters other than alg. */
        if (fields[3].major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
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
    ctap_client_pin_invalidate(pin);
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
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (pin == NULL || pin->service == NULL || request == NULL || output == NULL || length == NULL || pin->faulted)
        return CTAP_STATUS_OTHER;
    if (request->subcommand == 2U) return ctap_pin_key_agreement_encode(&pin->service->secrets, output, capacity, length);
    ctap_client_pin_poll(pin, now_ms);
    if (request->subcommand != 1U && request->subcommand != 3U && request->subcommand != 4U && request->subcommand != 9U)
        return CTAP_STATUS_INVALID_SUBCOMMAND;
    AuthPinRecord record = {0};
    uint8_t keys[64] = {0}, message[112] = {0}, current_hash[16] = {0};
    const AuthSecretCrypto *crypto = &pin->service->secrets;
    uint8_t status = CTAP_STATUS_OTHER;
    if (pin->storage.read(pin->storage.context, &record) != AUTH_OK || !auth_pin_record_valid(&record)) {
        pin->faulted = true; ctap_client_pin_invalidate(pin); goto done;
    }
    if (request->subcommand == 1U) {
        uint8_t encoded[8]; CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
        if (!cbor_write_map(&writer, 2U) || !cbor_write_uint(&writer, 3U) || !cbor_write_uint(&writer, record.retries) ||
            !cbor_write_uint(&writer, 4U) || !cbor_write_bool(&writer, pin->consecutive_failures >= 3U) || writer.length > capacity) goto done;
        memcpy(output, encoded, writer.length); *length = writer.length; status = CTAP_STATUS_OK; goto done;
    }
    if (request->subcommand == 3U && record.set) { status = CTAP_STATUS_PIN_AUTH_INVALID; goto done; }
    if (request->subcommand == 9U && (request->permissions & CTAP_PIN_PERMISSION_CM) != 0U && !pin->credential_management) {
        status = CTAP_STATUS_UNAUTHORIZED_PERMISSION; goto done;
    }
    if (request->subcommand == 4U || request->subcommand == 9U) {
        if (!record.set) { status = CTAP_STATUS_PIN_NOT_SET; goto done; }
        if (record.retries == 0U) { status = CTAP_STATUS_PIN_BLOCKED; goto done; }
        if (pin->consecutive_failures >= 3U) { status = CTAP_STATUS_PIN_AUTH_BLOCKED; goto done; }
    }
    status = ctap_pin_protocol_shared(crypto, request->peer, keys);
    /* ClientPIN defines decapsulation/verification wire errors independently
     * of the provider's failure category (§§6.5.5.5–6, 6.5.5.7.2). */
    if (status != CTAP_STATUS_OK) { status = CTAP_STATUS_INVALID_PARAMETER; goto done; }
    if (request->subcommand != 9U) {
        memcpy(message, request->new_pin_enc, 80U);
        if (request->subcommand == 4U) memcpy(message + 80U, request->pin_hash_enc, 32U);
        status = ctap_pin_protocol_verify(crypto, keys, message, request->subcommand == 4U ? 112U : 80U,
            request->auth, request->auth_length);
        if (status != CTAP_STATUS_OK) { status = CTAP_STATUS_PIN_AUTH_INVALID; goto done; }
    }
    if (request->subcommand == 4U || request->subcommand == 9U) {
        /* Persist before decrypting/trying the verifier, including crash recovery. */
        --record.retries;
        status = CTAP_STATUS_OTHER;
        if (!persist(pin, &record)) goto done;
        if (crypto->aes256_cbc(crypto->context, false, keys + 32U, request->pin_hash_enc,
            request->pin_hash_enc + 16U, 16U, current_hash) != AUTH_OK || !ctap_pin_equal(record.hash, current_hash, 16U)) {
            ++pin->consecutive_failures;
            if (crypto->regenerate(crypto->context) != AUTH_OK) {
                pin->faulted = true; ctap_client_pin_invalidate(pin); goto done;
            }
            status = record.retries == 0U ? CTAP_STATUS_PIN_BLOCKED :
                (pin->consecutive_failures >= 3U ? CTAP_STATUS_PIN_AUTH_BLOCKED : CTAP_STATUS_PIN_INVALID);
            goto done;
        }
        record.retries = AUTH_PIN_MAX_RETRIES;
        if (!persist(pin, &record)) goto done;
        pin->consecutive_failures = 0U;
    }
    if (request->subcommand == 9U) {
        /* Successful PIN verification invalidates every previously issued token.
         * Publish the new state only after RNG, encryption and encoding succeed. */
        ctap_client_pin_invalidate(pin);
        uint8_t token[32] = {0}, encrypted[48] = {0}, rp_hash[32] = {0}, encoded[52];
        CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
        status = CTAP_STATUS_OTHER;
        if (request->rp_length > sizeof request->rp_id ||
            (request->permissions & ~7ULL) != 0U || ((request->permissions & 3U) != 0U && !request->rp_present)) goto token_done;
        if (request->rp_present && pin->service->crypto.sha256(pin->service->crypto.context,
            request->rp_id, request->rp_length, rp_hash) != AUTH_OK) goto token_done;
        if (pin->token_generation == UINT64_MAX ||
            pin->service->crypto.random(pin->service->crypto.context, token, sizeof token) != AUTH_OK ||
            pin->service->crypto.random(pin->service->crypto.context, encrypted, 16U) != AUTH_OK ||
            crypto->aes256_cbc(crypto->context, true, keys + 32U, encrypted, token, 32U, encrypted + 16U) != AUTH_OK ||
            !cbor_write_map(&writer, 1U) || !cbor_write_uint(&writer, 2U) ||
            !cbor_write_bytes(&writer, encrypted, sizeof encrypted) || writer.length > capacity) goto token_done;
        memcpy(pin->token, token, 32U); memcpy(pin->token_rp_hash, rp_hash, 32U);
        pin->permissions = (uint8_t)request->permissions;
        pin->token_rp_bound = request->rp_present;
        pin->issued_at_ms = now_ms; pin->token_active = true; pin->token_used = false;
        ++pin->token_generation;
        memcpy(output, encoded, writer.length); *length = writer.length; status = CTAP_STATUS_OK;
token_done:
        auth_secure_zero(token, sizeof token); auth_secure_zero(encrypted, sizeof encrypted);
        auth_secure_zero(rp_hash, sizeof rp_hash); goto done;
    }
    status = new_pin(pin, keys, request->new_pin_enc, &record);
    if (status != CTAP_STATUS_OK) goto done;
    if (!persist(pin, &record)) { status = CTAP_STATUS_OTHER; goto done; }
    pin->consecutive_failures = 0U;
    pin->pin_set = true;
    if (!reset_token(pin)) { status = CTAP_STATUS_OTHER; goto done; }
    *length = 0U;
done:
    auth_secure_zero(&record, sizeof record); auth_secure_zero(keys, sizeof keys);
    auth_secure_zero(message, sizeof message); auth_secure_zero(current_hash, sizeof current_hash);
    return status;
}

void ctap_client_pin_invalidate(CtapClientPin *pin)
{
    if (pin == NULL) return;
    auth_secure_zero(pin->token, sizeof pin->token);
    auth_secure_zero(pin->token_rp_hash, sizeof pin->token_rp_hash);
    pin->permissions = 0U; pin->token_active = false; pin->token_used = false;
    pin->token_rp_bound = false;
}

void ctap_client_pin_poll(CtapClientPin *pin, uint32_t now_ms)
{
    if (pin == NULL || !pin->token_active) return;
    uint32_t elapsed = now_ms - pin->issued_at_ms;
    if (elapsed >= CTAP_PIN_MAX_TIMEOUT_MS || (!pin->token_used && elapsed >= CTAP_PIN_INITIAL_TIMEOUT_MS))
        ctap_client_pin_invalidate(pin);
}

uint8_t ctap_client_pin_status(CtapClientPin *pin, bool *set)
{
    if (pin == NULL || set == NULL || pin->faulted) return CTAP_STATUS_OTHER;
    AuthPinRecord record = {0};
    bool valid = pin->storage.read(pin->storage.context, &record) == AUTH_OK && auth_pin_record_valid(&record);
    if (valid) { pin->pin_set = record.set; *set = record.set; }
    auth_secure_zero(&record, sizeof record);
    if (!valid) { pin->faulted = true; ctap_client_pin_invalidate(pin); return CTAP_STATUS_OTHER; }
    return CTAP_STATUS_OK;
}

uint8_t ctap_client_pin_probe(CtapClientPin *pin)
{
    bool set;
    uint8_t status = ctap_client_pin_status(pin, &set);
    return status != CTAP_STATUS_OK ? status : (set ? CTAP_STATUS_PIN_INVALID : CTAP_STATUS_PIN_NOT_SET);
}

uint8_t ctap_pin_auth_parse(CtapClientPin *pin, const CborValue *param,
    const CborValue *protocol, CtapPinAuth *auth)
{
    if (auth == NULL) return CTAP_STATUS_OTHER;
    *auth = (CtapPinAuth){0};
    if (param != NULL && param->major != 2U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (pin != NULL && param != NULL && param->value == 0U) { auth->present = auth->probe = true; return CTAP_STATUS_OK; }
    if (protocol != NULL && protocol->major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (param == NULL) return CTAP_STATUS_OK;
    if (protocol == NULL) return CTAP_STATUS_MISSING_PARAMETER;
    if (pin == NULL || protocol->value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    if (param->value != 32U) return CTAP_STATUS_PIN_AUTH_INVALID;
    auth->present = true; memcpy(auth->mac, param->data, 32U);
    return CTAP_STATUS_OK;
}

uint8_t ctap_client_pin_authorize(CtapClientPin *pin, CtapPinAuth *auth,
    const uint8_t rp_hash[32], const uint8_t client_data_hash[32], uint8_t permission,
    uint32_t now_ms, bool mark_used)
{
    if (auth == NULL || rp_hash == NULL || client_data_hash == NULL) return CTAP_STATUS_OTHER;
    if (!auth->present) return pin != NULL && pin->faulted ? CTAP_STATUS_OTHER : CTAP_STATUS_OK;
    if (pin == NULL || auth->probe) return CTAP_STATUS_PIN_AUTH_INVALID;
    ctap_client_pin_poll(pin, now_ms);
    if (pin->faulted) return CTAP_STATUS_OTHER;
    if (!pin->pin_set) return CTAP_STATUS_PIN_NOT_SET;
    if (!pin->token_active || (pin->permissions & permission) == 0U ||
        (auth->token_generation != 0U && auth->token_generation != pin->token_generation) ||
        !ctap_pin_equal(pin->token_rp_hash, rp_hash, 32U)) return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t keys[64] = {0}; memcpy(keys, pin->token, 32U);
    uint8_t status = ctap_pin_protocol_verify(&pin->service->secrets, keys, client_data_hash, 32U, auth->mac, 32U);
    auth_secure_zero(keys, sizeof keys);
    /* MC/GA return PIN_AUTH_INVALID for any token verification error,
     * including a provider failure (§§6.1.2, 6.2.2). */
    if (status != CTAP_STATUS_OK) return CTAP_STATUS_PIN_AUTH_INVALID;
    if (mark_used) {
        auth->token_generation = pin->token_generation; pin->token_used = true;
    }
    return status;
}

uint8_t ctap_client_pin_authorize_management(CtapClientPin *pin, const uint8_t *rp_hash,
    const uint8_t *message, size_t message_length, const uint8_t mac[32], uint32_t now_ms)
{
    if (pin == NULL || mac == NULL || message == NULL) return CTAP_STATUS_PIN_AUTH_INVALID;
    ctap_client_pin_poll(pin, now_ms);
    if (pin->faulted) return CTAP_STATUS_OTHER;
    if (!pin->token_active || (pin->permissions & CTAP_PIN_PERMISSION_CM) == 0U ||
        (pin->token_rp_bound && (rp_hash == NULL || !ctap_pin_equal(pin->token_rp_hash, rp_hash, 32U))))
        return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t keys[64] = {0}; memcpy(keys, pin->token, 32U);
    uint8_t status = ctap_pin_protocol_verify(&pin->service->secrets, keys, message, message_length, mac, 32U);
    auth_secure_zero(keys, sizeof keys);
    if (status != CTAP_STATUS_OK) return CTAP_STATUS_PIN_AUTH_INVALID; /* §6.8 verification failure. */
    pin->token_used = true;
    return CTAP_STATUS_OK;
}
