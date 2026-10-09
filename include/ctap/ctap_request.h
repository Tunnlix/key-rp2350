#ifndef CTAP_REQUEST_H
#define CTAP_REQUEST_H

#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"

/* Common structural validation for CTAP request maps and credential descriptors.
 * Values borrow immutable request storage. No policy, lookup, UP or signing.
 * Known parameter keys are unsigned integers; all unknown keys are validated
 * then ignored. Text-member lookup likewise ignores keys outside its namespace.
 * Caller supplies zeroed fields/present arrays of field_count elements. */
uint8_t ctap_request_map(const uint8_t *input, size_t length, size_t field_count,
    CborValue *fields, bool *present);
/* Shared ClientPIN map/type checks for full PIN and key-agreement-only paths.
 * Caller supplies zeroed arrays. Subcommand/protocol policy remains with caller. */
uint8_t ctap_request_client_pin_map(const uint8_t *input, size_t length,
    CborValue fields[11], bool present[11]);
uint8_t ctap_request_text_map(const CborValue *map);
/* Require byte-string id, text type, and validate optional transports array.
 * Unknown descriptor members/types are retained/ignored by the policy caller. */
uint8_t ctap_request_descriptor(const CborValue *map, CborValue *id, CborValue *type);

#endif
