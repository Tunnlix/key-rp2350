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
    uint8_t status = ctap_request_client_pin_map(input, length, fields, present);
    if (status != CTAP_STATUS_OK) return status;
    uint64_t command = fields[2].value;
    if ((command < 1U || command > 5U) && command != 9U) return CTAP_STATUS_INVALID_SUBCOMMAND;
    if (present[1] && fields[1].major != 0U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    if (command != 1U && !present[1]) return CTAP_STATUS_MISSING_PARAMETER;
    if (present[1] && fields[1].value != 1U && fields[1].value != 2U) return CTAP_STATUS_INVALID_PARAMETER;
    uint8_t protocol = present[1] ? (uint8_t)fields[1].value : 2U;
    size_t prefix = ctap_pin_protocol_prefix(protocol);
    size_t auth_length = ctap_pin_protocol_auth_length(protocol);
    uint8_t peer[65] = {0};
    if (command == 5U || command == 9U) {
        if (command == 5U && (present[9] || present[10])) return CTAP_STATUS_INVALID_PARAMETER;
        if (!present[3] || !present[6] || (command == 9U && !present[9])) return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[6].major != 2U || (command == 9U && fields[9].major != 0U) || (present[10] && fields[10].major != 3U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        /* RP ID is mandatory for MC/GA, before permission availability (§6.5.5.7.2). */
        if (command == 9U && (fields[9].value & 3U) != 0U && !present[10]) return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[6].value != 16U + prefix || (command == 9U && fields[9].value == 0U)) return CTAP_STATUS_INVALID_PARAMETER;
        /* Known unavailable permissions are rejected; undefined bits ignored. */
        if ((fields[9].value & 0x78U) != 0U) return CTAP_STATUS_UNAUTHORIZED_PERMISSION;
        if (present[10] && (fields[10].value == 0U || fields[10].value > sizeof request->rp_id))
            return CTAP_STATUS_INVALID_PARAMETER;
        if (fields[3].major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        status = ctap_pin_public_key_parse(&fields[3], peer);
        if (status != CTAP_STATUS_OK) return status;
    } else if (command >= 3U) {
        if (!present[3] || !present[4] || !present[5] || (command == 4U && !present[6]))
            return CTAP_STATUS_MISSING_PARAMETER;
        if (fields[4].major != 2U || fields[5].major != 2U || (command == 4U && fields[6].major != 2U))
            return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        if (fields[5].value != 64U + prefix || (command == 4U && fields[6].value != 16U + prefix)) return CTAP_STATUS_INVALID_PARAMETER;
        if (fields[4].value != auth_length) return CTAP_STATUS_PIN_AUTH_INVALID;
        /* ClientPIN COSE keys cannot include optional parameters other than alg. */
        if (fields[3].major != 5U) return CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        status = ctap_pin_public_key_parse(&fields[3], peer);
        if (status != CTAP_STATUS_OK) return status;
    }
    /* Publish only after validation; the caller owns the message-sized RP buffer. */
    memset(request, 0, sizeof *request);
    request->subcommand = (uint8_t)command; request->protocol = protocol;
    memcpy(request->peer, peer, sizeof peer);
    if (command == 5U || command == 9U) {
        request->permissions = command == 5U ? 3U : fields[9].value & 7U;
        request->rp_present = present[10];
        if (present[10]) {
            request->rp_length = (size_t)fields[10].value;
            memcpy(request->rp_id, fields[10].data, request->rp_length);
        }
        memcpy(request->pin_hash_enc, fields[6].data, 16U + prefix);
    } else if (command >= 3U) {
        memcpy(request->new_pin_enc, fields[5].data, 64U + prefix);
        memcpy(request->auth, fields[4].data, auth_length);
        request->auth_length = auth_length;
        if (command == 4U) memcpy(request->pin_hash_enc, fields[6].data, 16U + prefix);
    }
    return CTAP_STATUS_OK;
}

static bool persist(CtapClientPin *pin, const AuthPinRecord *record)
{
    if (pin->storage.write(pin->storage.context, record) == AUTH_OK) return true;
    pin->faulted = true;
    ctap_client_pin_invalidate(pin);
    return false;
}

static uint8_t new_pin(CtapClientPin *pin, const uint8_t keys[64], const uint8_t encrypted[80], uint8_t protocol, AuthPinRecord *record)
{
    uint8_t plain[64] = {0}, digest[32] = {0};
    const AuthSecretCrypto *crypto = &pin->service->secrets;
    uint8_t status = CTAP_STATUS_PIN_AUTH_INVALID;
    if (ctap_pin_protocol_decrypt(crypto, protocol, keys, encrypted, 64U + ctap_pin_protocol_prefix(protocol), plain) != CTAP_STATUS_OK) goto done;
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

/* Preconditions are checked before ECDH, request authentication or retry writes. */
static uint8_t check_pin_state(const CtapClientPin *pin, const CtapClientPinRequest *request,
    const AuthPinRecord *record)
{
    if (request->subcommand == 3U && record->set) return CTAP_STATUS_PIN_AUTH_INVALID;
    if (request->subcommand == 9U && (request->permissions & CTAP_PIN_PERMISSION_CM) != 0U &&
        !pin->credential_management) return CTAP_STATUS_UNAUTHORIZED_PERMISSION;
    if (request->subcommand == 4U || request->subcommand == 5U || request->subcommand == 9U) {
        if (!record->set) return CTAP_STATUS_PIN_NOT_SET;
        if (record->retries == 0U) return CTAP_STATUS_PIN_BLOCKED;
        if (pin->consecutive_failures >= 3U) return CTAP_STATUS_PIN_AUTH_BLOCKED;
    }
    return CTAP_STATUS_OK;
}

static uint8_t authenticate_pin_change(const AuthSecretCrypto *crypto,
    const CtapClientPinRequest *request, const uint8_t keys[64])
{
    uint8_t message[112] = {0};
    size_t prefix = ctap_pin_protocol_prefix(request->protocol);
    size_t length = 64U + prefix;
    memcpy(message, request->new_pin_enc, length);
    if (request->subcommand == 4U) {
        memcpy(message + length, request->pin_hash_enc, 16U + prefix); length += 16U + prefix;
    }
    uint8_t status = ctap_pin_protocol_verify_version(crypto, request->protocol, keys, message,
        length, request->auth, request->auth_length);
    auth_secure_zero(message, sizeof message);
    return status == CTAP_STATUS_OK ? CTAP_STATUS_OK : CTAP_STATUS_PIN_AUTH_INVALID;
}

/* Charge an attempt durably before decrypting or comparing the PIN verifier,
 * so interruption cannot restore retries. Restore retries only after a match. */
static uint8_t verify_current_pin(CtapClientPin *pin, const CtapClientPinRequest *request,
    const uint8_t keys[64], AuthPinRecord *record)
{
    const AuthSecretCrypto *crypto = &pin->service->secrets;
    uint8_t current_hash[16] = {0};
    uint8_t status = CTAP_STATUS_OTHER;
    --record->retries;
    if (!persist(pin, record)) goto done;
    if (ctap_pin_protocol_decrypt(crypto, request->protocol, keys, request->pin_hash_enc,
        16U + ctap_pin_protocol_prefix(request->protocol), current_hash) != CTAP_STATUS_OK ||
        !ctap_pin_equal(record->hash, current_hash, sizeof current_hash)) {
        ++pin->consecutive_failures;
        if (crypto->regenerate(crypto->context) != AUTH_OK) {
            pin->faulted = true;
            ctap_client_pin_invalidate(pin);
            goto done;
        }
        status = record->retries == 0U ? CTAP_STATUS_PIN_BLOCKED :
            (pin->consecutive_failures >= 3U ? CTAP_STATUS_PIN_AUTH_BLOCKED : CTAP_STATUS_PIN_INVALID);
        goto done;
    }
    record->retries = AUTH_PIN_MAX_RETRIES;
    if (!persist(pin, record)) goto done;
    pin->consecutive_failures = 0U;
    status = CTAP_STATUS_OK;
done:
    auth_secure_zero(current_hash, sizeof current_hash);
    return status;
}

/* Called only after successful PIN verification. Retire the old token first;
 * publish a replacement only after RNG, encryption and complete encoding succeed. */
static uint8_t publish_token(CtapClientPin *pin, const CtapClientPinRequest *request,
    const uint8_t keys[64], uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    ctap_client_pin_invalidate(pin);
    const AuthSecretCrypto *crypto = &pin->service->secrets;
    uint8_t token[32] = {0}, encrypted[48] = {0}, rp_hash[32] = {0}, encoded[52];
    CborWriter writer; cbor_writer_init(&writer, encoded, sizeof encoded);
    uint8_t status = CTAP_STATUS_OTHER;
    if (request->rp_length > sizeof request->rp_id || (request->permissions & ~7ULL) != 0U ||
        ((request->permissions & 3U) != 0U && !request->rp_present && request->subcommand != 5U) ||
        (request->subcommand == 5U && (request->permissions != 3U || request->rp_present))) goto done;
    if (request->rp_present && pin->service->crypto.sha256(pin->service->crypto.context,
        request->rp_id, request->rp_length, rp_hash) != AUTH_OK) goto done;
    if (pin->token_generation == UINT64_MAX ||
        pin->service->crypto.random(pin->service->crypto.context, token, sizeof token) != AUTH_OK ||
        ctap_pin_protocol_encrypt(&pin->service->crypto, crypto, request->protocol, keys,
            token, 32U, encrypted) != CTAP_STATUS_OK ||
        !cbor_write_map(&writer, 1U) || !cbor_write_uint(&writer, 2U) ||
        !cbor_write_bytes(&writer, encrypted, 32U + ctap_pin_protocol_prefix(request->protocol)) || writer.length > capacity) goto done;
    memcpy(pin->token, token, sizeof token);
    memcpy(pin->token_rp_hash, rp_hash, sizeof rp_hash);
    pin->permissions = (uint8_t)request->permissions;
    pin->token_rp_bound = request->rp_present;
    pin->issued_at_ms = now_ms;
    pin->token_active = true;
    pin->token_used = false;
    ++pin->token_generation;
    memcpy(output, encoded, writer.length);
    *length = writer.length;
    status = CTAP_STATUS_OK;
done:
    auth_secure_zero(token, sizeof token);
    auth_secure_zero(encrypted, sizeof encrypted);
    auth_secure_zero(rp_hash, sizeof rp_hash);
    return status;
}

static uint8_t commit_new_pin(CtapClientPin *pin, const CtapClientPinRequest *request,
    const uint8_t keys[64], AuthPinRecord *record)
{
    uint8_t status = new_pin(pin, keys, request->new_pin_enc, request->protocol, record);
    if (status != CTAP_STATUS_OK) return status;
    if (!persist(pin, record)) return CTAP_STATUS_OTHER;
    pin->consecutive_failures = 0U;
    pin->pin_set = true;
    return reset_token(pin) ? CTAP_STATUS_OK : CTAP_STATUS_OTHER;
}

uint8_t ctap_client_pin_execute(CtapClientPin *pin, const CtapClientPinRequest *request,
    uint8_t *output, size_t capacity, size_t *length, uint32_t now_ms)
{
    if (pin == NULL || pin->service == NULL || request == NULL || output == NULL || length == NULL || pin->faulted)
        return CTAP_STATUS_OTHER;
    if (request->protocol > 2U) return CTAP_STATUS_INVALID_PARAMETER;
    if (request->subcommand == 2U) return ctap_pin_key_agreement_encode(&pin->service->secrets, output, capacity, length);
    ctap_client_pin_poll(pin, now_ms);
    if (request->subcommand != 1U && request->subcommand != 3U && request->subcommand != 4U && request->subcommand != 5U && request->subcommand != 9U)
        return CTAP_STATUS_INVALID_SUBCOMMAND;
    AuthPinRecord record = {0};
    uint8_t keys[64] = {0};
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
    status = check_pin_state(pin, request, &record);
    if (status != CTAP_STATUS_OK) goto done;
    status = ctap_pin_protocol_shared_version(&pin->service->crypto, crypto, request->protocol, request->peer, keys);
    /* ClientPIN maps decapsulation errors to INVALID_PARAMETER (§6.5.5). */
    if (status != CTAP_STATUS_OK) { status = CTAP_STATUS_INVALID_PARAMETER; goto done; }
    if (request->subcommand == 3U || request->subcommand == 4U) {
        status = authenticate_pin_change(crypto, request, keys);
        if (status != CTAP_STATUS_OK) goto done;
    }
    if (request->subcommand == 4U || request->subcommand == 5U || request->subcommand == 9U) {
        status = verify_current_pin(pin, request, keys, &record);
        if (status != CTAP_STATUS_OK) goto done;
    }
    if (request->subcommand == 5U || request->subcommand == 9U) {
        status = publish_token(pin, request, keys, output, capacity, length, now_ms);
    } else {
        status = commit_new_pin(pin, request, keys, &record);
        if (status == CTAP_STATUS_OK) *length = 0U;
    }
done:
    auth_secure_zero(&record, sizeof record);
    auth_secure_zero(keys, sizeof keys);
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
    if (pin == NULL || (protocol->value != 1U && protocol->value != 2U)) return CTAP_STATUS_INVALID_PARAMETER;
    if (param->value != ctap_pin_protocol_auth_length((uint8_t)protocol->value)) return CTAP_STATUS_PIN_AUTH_INVALID;
    auth->present = true; auth->protocol = (uint8_t)protocol->value; memcpy(auth->mac, param->data, (size_t)param->value);
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
        (pin->token_rp_bound && !ctap_pin_equal(pin->token_rp_hash, rp_hash, 32U))) return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t keys[64] = {0}; memcpy(keys, pin->token, 32U);
    uint8_t status = ctap_pin_protocol_verify_version(&pin->service->secrets, auth->protocol, keys,
        client_data_hash, 32U, auth->mac, ctap_pin_protocol_auth_length(auth->protocol));
    auth_secure_zero(keys, sizeof keys);
    /* MC/GA return PIN_AUTH_INVALID for any token verification error,
     * including a provider failure (§§6.1.2, 6.2.2). */
    if (status != CTAP_STATUS_OK) return CTAP_STATUS_PIN_AUTH_INVALID;
    /* First authenticated use binds a legacy token before credential lookup,
     * including when a later lookup returns NO_CREDENTIALS. Invalid MACs never
     * establish a binding. Scoped command-9 tokens already have their RP. */
    if (!pin->token_rp_bound) {
        memcpy(pin->token_rp_hash, rp_hash, 32U);
        pin->token_rp_bound = true;
    }
    if (mark_used) {
        auth->token_generation = pin->token_generation; pin->token_used = true;
    }
    return status;
}

uint8_t ctap_client_pin_authorize_management_version(CtapClientPin *pin, uint8_t protocol, const uint8_t *rp_hash,
    const uint8_t *message, size_t message_length, const uint8_t *mac, uint32_t now_ms)
{
    if (pin == NULL || mac == NULL || message == NULL) return CTAP_STATUS_PIN_AUTH_INVALID;
    ctap_client_pin_poll(pin, now_ms);
    if (pin->faulted) return CTAP_STATUS_OTHER;
    if (!pin->token_active || (pin->permissions & CTAP_PIN_PERMISSION_CM) == 0U ||
        (pin->token_rp_bound && (rp_hash == NULL || !ctap_pin_equal(pin->token_rp_hash, rp_hash, 32U))))
        return CTAP_STATUS_PIN_AUTH_INVALID;
    uint8_t keys[64] = {0}; memcpy(keys, pin->token, 32U);
    uint8_t status = ctap_pin_protocol_verify_version(&pin->service->secrets, protocol, keys,
        message, message_length, mac, ctap_pin_protocol_auth_length(protocol));
    auth_secure_zero(keys, sizeof keys);
    if (status != CTAP_STATUS_OK) return CTAP_STATUS_PIN_AUTH_INVALID; /* §6.8 verification failure. */
    pin->token_used = true;
    return CTAP_STATUS_OK;
}

uint8_t ctap_client_pin_authorize_management(CtapClientPin *pin, const uint8_t *rp_hash,
    const uint8_t *message, size_t length, const uint8_t mac[32], uint32_t now_ms)
{ return ctap_client_pin_authorize_management_version(pin, 2U, rp_hash, message, length, mac, now_ms); }
