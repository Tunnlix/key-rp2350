#include "protocol/ctaphid_device.h"

#include <string.h>

#define ERR_INVALID_CMD 0x01U
#define ERR_INVALID_PAR 0x02U
#define ERR_INVALID_LEN 0x03U
#define ERR_INVALID_SEQ 0x04U
#define ERR_MSG_TIMEOUT 0x05U
#define ERR_CHANNEL_BUSY 0x06U
#define ERR_INVALID_CHANNEL 0x0BU
#define ERR_OTHER 0x7FU
#define CTAP2_ERR_KEEPALIVE_CANCEL 0x2DU

static uint32_t report_channel(const uint8_t *report)
{
    return ((uint32_t)report[0] << 24) | ((uint32_t)report[1] << 16) |
        ((uint32_t)report[2] << 8) | report[3];
}

/* Transaction ownership is independent of reception and the transport slot. */
static void release_transaction(CtaphidDevice *device)
{
    device->phase = CTAPHID_DEVICE_IDLE;
    device->active_channel_id = 0U;
    device->cbor_running = false;
    device->response_count = device->response_next = 0U;
    ctaphid_reassembler_reset(&device->reassembler);
}

static void discard_owned_control(CtaphidDevice *device)
{
    size_t kept = 0U;
    for (size_t i = 0; i < device->control_count; ++i) {
        if (device->control[i].owner != device->transaction_id) {
            device->control[kept++] = device->control[i];
        }
    }
    device->control_count = kept;
}

static void abort_transaction(CtaphidDevice *device)
{
    if (device->cbor_running) {
        device->config.abort_cbor(device->config.cbor_context, device->transaction_id);
    }
    if (device->in_flight && (device->flight.owner == device->transaction_id ||
        report_channel(device->flight.bytes) == device->active_channel_id)) {
        device->config.abort_report(device->config.transport_context, device->flight_id);
        device->in_flight = false;
    }
    discard_owned_control(device);
    /* INIT resynchronization also flushes queued error replies on this CID.
     * Preserve replies addressed to competing channels. */
    size_t kept = 0U;
    for (size_t i = 0; i < device->control_count; ++i) {
        if (report_channel(device->control[i].bytes) != device->active_channel_id) {
            device->control[kept++] = device->control[i];
        }
    }
    device->control_count = kept;
    release_transaction(device);
}

/* Serializer callback: copy response reports into device-owned storage. It does
 * not send them or release busy ownership; only transport completion does that. */
static bool capture_response(void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    CtaphidDevice *device = context;
    if (device->response_count == CTAPHID_DEVICE_RESPONSE_REPORTS) return false;
    CtaphidQueuedReport *entry = &device->response[device->response_count++];
    memcpy(entry->bytes, report, CTAPHID_REPORT_SIZE);
    entry->owner = device->transaction_id;
    entry->final_response = false;
    return true;
}

static void finish_queued_response(CtaphidDevice *device)
{
    discard_owned_control(device); /* No stale keepalive after the final reply. */
    device->response[device->response_count - 1U].final_response = true;
    device->phase = CTAPHID_DEVICE_SENDING;
    device->reassembler.has_complete_message = false;
}

static CtaphidDeviceResult queue_response(CtaphidDevice *device,
    uint8_t command, const uint8_t *payload, size_t length)
{
    if (length > CTAPHID_MAX_MESSAGE_SIZE || (length != 0U && payload == NULL)) {
        return CTAPHID_DEVICE_INVALID_RESPONSE;
    }
    device->response_count = device->response_next = 0U;
    CtaphidResponseResult result = ctaphid_send_response(device->active_channel_id,
        command, payload, length, capture_response, device);
    if (result != CTAPHID_RESPONSE_OK) return CTAPHID_DEVICE_INVALID_RESPONSE;
    finish_queued_response(device);
    return CTAPHID_DEVICE_OK;
}

static bool capture_control(void *context, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    CtaphidQueuedReport *entry = context;
    memcpy(entry->bytes, report, CTAPHID_REPORT_SIZE);
    return true;
}

/* Errors to other CIDs and keepalives do not end the active transaction. */
static CtaphidDeviceResult queue_control(CtaphidDevice *device,
    uint32_t cid, uint8_t command, uint8_t value, uint64_t owner)
{
    if (device->control_count == CTAPHID_DEVICE_CONTROL_REPORTS) return CTAPHID_DEVICE_QUEUE_FULL;
    CtaphidQueuedReport entry = {0};
    entry.owner = owner;
    (void)ctaphid_send_response(cid, command, &value, 1U, capture_control, &entry);
    device->control[device->control_count++] = entry;
    return CTAPHID_DEVICE_OK;
}

static CtaphidDeviceResult report_error(CtaphidDevice *device, uint32_t cid, uint8_t error)
{
    return queue_control(device, cid, CTAPHID_COMMAND_ERROR, error, 0U);
}

static CtaphidDeviceResult expire_reception(CtaphidDevice *device, uint32_t now_ms)
{
    if (device->phase != CTAPHID_DEVICE_RECEIVING) return CTAPHID_DEVICE_OK;
    /* Reserve the error slot before resetting so backpressure cannot lose the CID. */
    if ((uint32_t)(now_ms - device->reassembler.last_activity_time_ms) <
        CTAPHID_TRANSACTION_TIMEOUT_MS) return CTAPHID_DEVICE_OK;
    if (device->control_count == CTAPHID_DEVICE_CONTROL_REPORTS) return CTAPHID_DEVICE_QUEUE_FULL;
    uint32_t cid = device->active_channel_id;
    if (ctaphid_reassembler_expire_if_timed_out(&device->reassembler, now_ms)) {
        release_transaction(device);
        return report_error(device, cid, ERR_MSG_TIMEOUT);
    }
    return CTAPHID_DEVICE_OK;
}

CtaphidDeviceResult ctaphid_device_init(CtaphidDevice *device,
    const CtaphidDeviceConfig *config)
{
    if (device == NULL || config == NULL || config->submit_report == NULL ||
        (config->asynchronous_transport && config->abort_report == NULL) ||
        ((config->start_cbor == NULL) != (config->abort_cbor == NULL))) {
        return CTAPHID_DEVICE_INVALID_ARGUMENT;
    }
    CtaphidDeviceConfig copied = *config;
    memset(device, 0, sizeof *device);
    device->config = copied;
    device->next_transfer_id = 1U;
    ctaphid_channels_reset(&device->channels);
    return CTAPHID_DEVICE_OK;
}

static void start_transaction(CtaphidDevice *device, uint32_t cid)
{
    ++device->transaction_id;
    if (device->transaction_id == 0U) ++device->transaction_id;
    device->active_channel_id = cid;
    device->phase = CTAPHID_DEVICE_RECEIVING;
}

static CtaphidDeviceResult handle_cancel(CtaphidDevice *device,
    uint32_t cid, const CtaphidParsedPacket *packet, CtaphidParseResult parsed)
{
    /* Ignore malformed, idle, receiving, sending, and non-active CANCELs. */
    if (parsed != CTAPHID_PARSE_OK || packet->message_length != 0U ||
        device->phase != CTAPHID_DEVICE_PROCESSING || !device->cbor_running ||
        cid != device->active_channel_id) return CTAPHID_DEVICE_IGNORED;
    device->config.abort_cbor(device->config.cbor_context, device->transaction_id);
    device->cbor_running = false;
    const uint8_t status = CTAP2_ERR_KEEPALIVE_CANCEL;
    /* This is the original CBOR request's response, never a CANCEL/HID error. */
    return queue_response(device, CTAPHID_COMMAND_CBOR, &status, 1U);
}

CtaphidDeviceResult ctaphid_device_receive_report(CtaphidDevice *device,
    const uint8_t *report, size_t length, uint32_t now_ms)
{
    if (device == NULL || report == NULL || device->config.submit_report == NULL) {
        return CTAPHID_DEVICE_INVALID_ARGUMENT;
    }
    if (length != CTAPHID_REPORT_SIZE) return CTAPHID_DEVICE_INVALID_REPORT_LENGTH;
    CtaphidDeviceResult expired = expire_reception(device, now_ms);
    if (expired != CTAPHID_DEVICE_OK) return expired;

    uint32_t cid = report_channel(report);
    bool initial = (report[4] & 0x80U) != 0U;
    uint8_t command = report[4] & 0x7FU;
    CtaphidParsedPacket packet = {0};
    CtaphidParseResult parsed = ctaphid_parse_packet(report, length, &packet);

    if (initial && command == CTAPHID_COMMAND_CANCEL) {
        return handle_cancel(device, cid, &packet, parsed);
    }
    /* Spurious continuations are ignored, including unallocated/foreign CIDs. */
    if (!initial && (device->phase != CTAPHID_DEVICE_RECEIVING ||
        cid != device->active_channel_id)) return CTAPHID_DEVICE_IGNORED;

    if (cid == 0U || (cid == CTAPHID_BROADCAST_CHANNEL_ID &&
        (!initial || command != CTAPHID_COMMAND_INIT)) ||
        (cid != CTAPHID_BROADCAST_CHANNEL_ID &&
        !ctaphid_channels_is_allocated(&device->channels, cid))) {
        return report_error(device, cid, ERR_INVALID_CHANNEL);
    }

    /* Valid same-CID INIT is the only initial request that can resynchronize
     * processing/sending. Invalid INIT cannot destroy an existing transaction. */
    bool resync = initial && command == CTAPHID_COMMAND_INIT &&
        cid == device->active_channel_id && device->phase != CTAPHID_DEVICE_IDLE;
    if (resync) {
        if (parsed != CTAPHID_PARSE_OK || packet.message_length != 8U) {
            return report_error(device, cid, ERR_INVALID_LEN);
        }
        abort_transaction(device);
    } else if (initial && device->phase != CTAPHID_DEVICE_IDLE &&
        (cid != device->active_channel_id || device->phase != CTAPHID_DEVICE_RECEIVING)) {
        return report_error(device, cid, ERR_CHANNEL_BUSY);
    }
    if (parsed != CTAPHID_PARSE_OK) {
        if (device->phase == CTAPHID_DEVICE_IDLE) {
            /* A known CID's rejected initial request still owns its error reply
             * until that reply finishes transmitting. */
            start_transaction(device, cid);
            const uint8_t error = ERR_INVALID_LEN;
            return queue_response(device, CTAPHID_COMMAND_ERROR, &error, 1U);
        }
        return report_error(device, cid, ERR_INVALID_LEN);
    }
    if (device->phase == CTAPHID_DEVICE_IDLE) start_transaction(device, cid);

    CtaphidReassembleResult assembled = ctaphid_reassemble_packet(
        &device->reassembler, &packet, now_ms);
    switch (assembled) {
    case CTAPHID_REASSEMBLE_COMPLETE:
        device->phase = CTAPHID_DEVICE_PROCESSING;
        return CTAPHID_DEVICE_OK;
    case CTAPHID_REASSEMBLE_INCOMPLETE: return CTAPHID_DEVICE_OK;
    case CTAPHID_REASSEMBLE_IGNORED: return CTAPHID_DEVICE_IGNORED;
    case CTAPHID_REASSEMBLE_INVALID_SEQUENCE: {
        const uint8_t error = ERR_INVALID_SEQ;
        return queue_response(device, CTAPHID_COMMAND_ERROR, &error, 1U);
    }
    case CTAPHID_REASSEMBLE_MESSAGE_TOO_LARGE: {
        const uint8_t error = ERR_INVALID_LEN;
        return queue_response(device, CTAPHID_COMMAND_ERROR, &error, 1U);
    }
    default: return CTAPHID_DEVICE_INVALID_STATE;
    }
}

static uint8_t dispatch_error(CtaphidDispatchResult result)
{
    switch (result) {
    case CTAPHID_DISPATCH_INVALID_COMMAND:
    case CTAPHID_DISPATCH_UNSUPPORTED_COMMAND: return ERR_INVALID_CMD;
    case CTAPHID_DISPATCH_INVALID_LENGTH: return ERR_INVALID_LEN;
    case CTAPHID_DISPATCH_INVALID_PARAMETER: return ERR_INVALID_PAR;
    case CTAPHID_DISPATCH_INVALID_CHANNEL: return ERR_INVALID_CHANNEL;
    default: return ERR_OTHER;
    }
}

static CtaphidDeviceResult process_request(CtaphidDevice *device, uint32_t now_ms)
{
    if (device->reassembler.command == CTAPHID_COMMAND_INIT && device->reassembler.received_length == 8U &&
        device->active_channel_id != CTAPHID_BROADCAST_CHANNEL_ID && device->config.resync_channel != NULL)
        device->config.resync_channel(device->config.cbor_context, device->active_channel_id);
    if (device->reassembler.command == CTAPHID_COMMAND_CBOR &&
        device->reassembler.received_length != 0U && device->config.start_cbor != NULL) {
        device->cbor_running = true;
        device->keepalive_status = CTAPHID_STATUS_PROCESSING;
        device->last_keepalive_ms = now_ms;
        device->reassembler.has_complete_message = false;
        device->config.start_cbor(device->config.cbor_context, device->transaction_id,
            device->reassembler.buffer, device->reassembler.received_length);
        return CTAPHID_DEVICE_OK;
    }
    device->response_count = device->response_next = 0U;
    uint8_t capabilities = CTAPHID_CAPABILITY_NMSG;
    if (device->config.start_cbor != NULL) capabilities |= CTAPHID_CAPABILITY_CBOR;
    if (device->config.wink_action != NULL) capabilities |= CTAPHID_CAPABILITY_WINK;
    if (device->reassembler.command == CTAPHID_COMMAND_WINK &&
        device->reassembler.received_length == 0U && device->config.wink_action != NULL) {
        device->config.wink_action(device->config.wink_context, device->active_channel_id);
    }
    CtaphidDispatchResult dispatched = ctaphid_dispatch_message_with_capabilities(
        &device->reassembler, &device->channels, capabilities,
        capture_response, device);
    if (dispatched == CTAPHID_DISPATCH_OK && device->response_count != 0U) {
        finish_queued_response(device);
        return CTAPHID_DEVICE_OK;
    }
    if (dispatched == CTAPHID_DISPATCH_RESPONSE_FAILED) {
        abort_transaction(device);
        return CTAPHID_DEVICE_INVALID_RESPONSE;
    }
    const uint8_t error = dispatch_error(dispatched);
    return queue_response(device, CTAPHID_COMMAND_ERROR, &error, 1U);
}

CtaphidDeviceResult ctaphid_device_complete_cbor(CtaphidDevice *device,
    uint64_t operation_id, const uint8_t *payload, size_t length)
{
    if (device == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    if (!device->cbor_running || device->phase != CTAPHID_DEVICE_PROCESSING ||
        operation_id != device->transaction_id) return CTAPHID_DEVICE_INVALID_STATE;
    if (payload == NULL || length == 0U || length > CTAPHID_MAX_MESSAGE_SIZE) {
        return CTAPHID_DEVICE_INVALID_RESPONSE;
    }
    CtaphidDeviceResult result = queue_response(device, CTAPHID_COMMAND_CBOR, payload, length);
    if (result == CTAPHID_DEVICE_OK) device->cbor_running = false;
    return result;
}

CtaphidDeviceResult ctaphid_device_set_keepalive(CtaphidDevice *device,
    uint64_t operation_id, uint8_t status, uint32_t now_ms)
{
    if (device == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    if (!device->cbor_running || device->phase != CTAPHID_DEVICE_PROCESSING ||
        operation_id != device->transaction_id) return CTAPHID_DEVICE_INVALID_STATE;
    if (status != CTAPHID_STATUS_PROCESSING && status != CTAPHID_STATUS_UPNEEDED) {
        return CTAPHID_DEVICE_INVALID_ARGUMENT;
    }
    /* Coalesce unsent keepalives so polling cannot fill the control queue. */
    for (size_t i = 0; i < device->control_count; ++i) {
        if (device->control[i].owner == device->transaction_id) {
            device->control[i].bytes[7] = status;
            device->keepalive_status = status;
            device->last_keepalive_ms = now_ms;
            return CTAPHID_DEVICE_OK;
        }
    }
    CtaphidDeviceResult result = queue_control(device, device->active_channel_id,
        CTAPHID_COMMAND_KEEPALIVE, status, device->transaction_id);
    if (result == CTAPHID_DEVICE_OK) {
        device->keepalive_status = status;
        device->last_keepalive_ms = now_ms;
    }
    return result;
}

CtaphidDeviceResult ctaphid_device_report_sent(CtaphidDevice *device,
    uint64_t transfer_id, bool success)
{
    if (device == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    if (!device->in_flight || transfer_id != device->flight_id) return CTAPHID_DEVICE_IGNORED;
    CtaphidQueuedReport sent = device->flight;
    device->in_flight = false;
    if (!success) {
        if (sent.owner != 0U && sent.owner == device->transaction_id) abort_transaction(device);
        return CTAPHID_DEVICE_TRANSPORT_FAILED;
    }
    if (sent.final_response && sent.owner == device->transaction_id &&
        device->phase == CTAPHID_DEVICE_SENDING) release_transaction(device);
    return CTAPHID_DEVICE_OK;
}

/* Controls get priority to return BUSY promptly. They never clear transaction
 * ownership. The single transport slot has a unique completion token. */
static CtaphidDeviceResult submit_queued_reports(CtaphidDevice *device, uint32_t now_ms)
{
    while (!device->in_flight) {
        if (device->control_count != 0U) {
            device->flight = device->control[0];
            --device->control_count;
            memmove(device->control, device->control + 1U,
                device->control_count * sizeof device->control[0]);
        } else if (device->response_next < device->response_count) {
            device->flight = device->response[device->response_next++];
        } else {
            break;
        }
        device->in_flight = true;
        device->flight_id = device->next_transfer_id++;
        if (device->next_transfer_id == 0U) ++device->next_transfer_id;
        device->flight_started_ms = now_ms;
        bool accepted = device->config.submit_report(device->config.transport_context,
            device->flight.bytes, device->flight_id);
        if (!accepted) return ctaphid_device_report_sent(device, device->flight_id, false);
        if (device->config.asynchronous_transport) break;
        (void)ctaphid_device_report_sent(device, device->flight_id, true);
    }
    return CTAPHID_DEVICE_OK;
}

CtaphidDeviceResult ctaphid_device_poll(CtaphidDevice *device, uint32_t now_ms)
{
    if (device == NULL || device->config.submit_report == NULL) return CTAPHID_DEVICE_INVALID_ARGUMENT;
    if (device->in_flight && (uint32_t)(now_ms - device->flight_started_ms) >= CTAPHID_SEND_TIMEOUT_MS) {
        device->config.abort_report(device->config.transport_context, device->flight_id);
        return ctaphid_device_report_sent(device, device->flight_id, false);
    }
    CtaphidDeviceResult result = expire_reception(device, now_ms);
    if (result == CTAPHID_DEVICE_QUEUE_FULL) {
        /* Drain output even under error backpressure; otherwise a full control
         * queue would prevent poll from ever freeing a slot for the timeout. */
        CtaphidDeviceResult sent = submit_queued_reports(device, now_ms);
        if (sent != CTAPHID_DEVICE_OK) return sent;
        result = expire_reception(device, now_ms);
    }
    if (result != CTAPHID_DEVICE_OK) return result;
    if (device->phase == CTAPHID_DEVICE_PROCESSING && !device->cbor_running) {
        result = process_request(device, now_ms);
        if (result != CTAPHID_DEVICE_OK) return result;
    }
    if (device->cbor_running && (uint32_t)(now_ms - device->last_keepalive_ms) >= CTAPHID_KEEPALIVE_INTERVAL_MS) {
        result = ctaphid_device_set_keepalive(device, device->transaction_id,
            device->keepalive_status, now_ms);
        if (result == CTAPHID_DEVICE_QUEUE_FULL) {
            CtaphidDeviceResult sent = submit_queued_reports(device, now_ms);
            return sent == CTAPHID_DEVICE_OK ? result : sent;
        }
        if (result != CTAPHID_DEVICE_OK) return result;
    }
    return submit_queued_reports(device, now_ms);
}
