#ifndef CTAPHID_DEVICE_H
#define CTAPHID_DEVICE_H

#include "protocol/ctaphid_dispatcher.h"

/* CTAP 2.3, section 11.2: device-level transaction coordination.
 * https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#usb-hid */
#define CTAPHID_DEVICE_RESPONSE_REPORTS 18U /* Enough for a 1024-byte response. */
#define CTAPHID_DEVICE_CONTROL_REPORTS 4U
#define CTAPHID_KEEPALIVE_INTERVAL_MS 100U
#define CTAPHID_SEND_TIMEOUT_MS 3000U /* Local transport watchdog, not a CTAP mandate. */
#define CTAPHID_STATUS_PROCESSING 1U
#define CTAPHID_STATUS_UPNEEDED 2U

typedef enum {
    CTAPHID_DEVICE_IDLE = 0,
    CTAPHID_DEVICE_RECEIVING,
    CTAPHID_DEVICE_PROCESSING,
    CTAPHID_DEVICE_SENDING
} CtaphidDevicePhase;

typedef enum {
    CTAPHID_DEVICE_OK = 0,
    CTAPHID_DEVICE_IGNORED,
    CTAPHID_DEVICE_INVALID_ARGUMENT,
    CTAPHID_DEVICE_INVALID_REPORT_LENGTH,
    CTAPHID_DEVICE_QUEUE_FULL,
    CTAPHID_DEVICE_TRANSPORT_FAILED,
    CTAPHID_DEVICE_INVALID_STATE,
    CTAPHID_DEVICE_INVALID_RESPONSE
} CtaphidDeviceResult;

/* A synchronous transport returns true only after transmission finishes.
 * An asynchronous transport returns true after copying/accepting the report,
 * then calls report_sent() later with transfer_id. False rejects the report.
 * abort_report must quiesce/cancel the transfer before returning; stale completion
 * events are ignored. It is required for asynchronous transports. */
typedef bool (*CtaphidSubmitReport)(void *context,
    const uint8_t report[CTAPHID_REPORT_SIZE], uint64_t transfer_id);
typedef void (*CtaphidAbortReport)(void *context, uint64_t transfer_id);

/* Optional CBOR backend. start returns promptly and schedules/prepares work.
 * Complete later with complete_cbor(), or update status with set_keepalive().
 * request includes the CTAP command byte and remains valid until completion or
 * abort. abort must stop all access/work before returning. Both hooks are required
 * together. A configured backend causes INIT to advertise CAPABILITY_CBOR. */
typedef void (*CtaphidStartCbor)(void *context, uint64_t operation_id,
    const uint8_t *request, size_t request_length);
typedef void (*CtaphidAbortCbor)(void *context, uint64_t operation_id);

/* Platform action: PC logging or embedded LED indication. Return promptly;
 * schedule any animation separately. WINK is advertised only when this is set. */
typedef void (*CtaphidWinkAction)(void *context, uint32_t channel_id);

typedef struct {
    CtaphidSubmitReport submit_report;
    CtaphidAbortReport abort_report;
    void *transport_context;
    bool asynchronous_transport;
    CtaphidStartCbor start_cbor;
    CtaphidAbortCbor abort_cbor;
    void *cbor_context;
    CtaphidWinkAction wink_action;
    void *wink_context;
} CtaphidDeviceConfig;

typedef struct {
    uint8_t bytes[CTAPHID_REPORT_SIZE];
    uint64_t owner; /* Zero for errors to other channels; transaction ID otherwise. */
    bool final_response;
} CtaphidQueuedReport;

/* Owned once per device. Fields are exposed for allocation without a heap;
 * callers must not modify them. All API calls must be serialized, and callbacks
 * must not reenter this API. Marshal USB interrupts/backend events to one loop. */
typedef struct {
    CtaphidDeviceConfig config;
    CtaphidChannelManager channels;
    CtaphidReassembler reassembler;
    CtaphidDevicePhase phase;
    uint32_t active_channel_id;
    uint64_t transaction_id;
    uint64_t next_transfer_id;
    bool cbor_running;
    uint8_t keepalive_status;
    uint32_t last_keepalive_ms;
    CtaphidQueuedReport response[CTAPHID_DEVICE_RESPONSE_REPORTS];
    size_t response_count, response_next;
    CtaphidQueuedReport control[CTAPHID_DEVICE_CONTROL_REPORTS];
    size_t control_count;
    CtaphidQueuedReport flight;
    bool in_flight;
    uint64_t flight_id;
    uint32_t flight_started_ms;
} CtaphidDevice;

/* Initialize once; failure leaves device unchanged. To reset an existing device,
 * first stop its transport/backend externally, then initialize again. */
CtaphidDeviceResult ctaphid_device_init(CtaphidDevice *device,
    const CtaphidDeviceConfig *config);

/* Accept exactly one raw report. Validates CIDs before assembly; CANCEL is
 * intercepted and never receives its own reply. Errors are queued as wire replies.
 * Expired assembly is discarded without stopping processing of the new report.
 * QUEUE_FULL means an error could not be queued; apply input backpressure rather
 * than silently ignoring it. Malformed report lengths have no wire reply.
 * now_ms is a shared monotonic uint32_t millisecond clock, including wraparound. */
CtaphidDeviceResult ctaphid_device_receive_report(CtaphidDevice *device,
    const uint8_t *report, size_t length, uint32_t now_ms);

/* Call regularly even without input. Checks reception/transport deadlines,
 * starts handlers/backend work, generates keepalives, and submits queued reports.
 * Busy ownership ends only on final response completion or transaction abort. */
CtaphidDeviceResult ctaphid_device_poll(CtaphidDevice *device, uint32_t now_ms);

CtaphidDeviceResult ctaphid_device_report_sent(CtaphidDevice *device,
    uint64_t transfer_id, bool success);

/* CBOR payload includes its CTAP status byte; current storage allows 1..1024
 * bytes. Stale completion tokens cannot complete a resynchronized transaction.
 * No generic 3-second processing deadline is imposed on user-presence operations. */
CtaphidDeviceResult ctaphid_device_complete_cbor(CtaphidDevice *device,
    uint64_t operation_id, const uint8_t *payload, size_t length);
CtaphidDeviceResult ctaphid_device_set_keepalive(CtaphidDevice *device,
    uint64_t operation_id, uint8_t status, uint32_t now_ms);

#endif
