#ifndef CTAP_ENTITIES_H
#define CTAP_ENTITIES_H

#include "ctap/ctap.h"
#include "ctap/cbor_reader.h"
#include "ctap/cbor_writer.h"
#include "authenticator/auth_platform.h"

/* User names are retained up to 64 UTF-8 bytes, without splitting a code point.
 * RP IDs are retained completely up to maxMsgSize, never truncated for binding. */
uint8_t ctap_user_entity_parse(const CborValue *value, AuthCredential *metadata);
uint8_t ctap_rp_entity_parse(const CborValue *value, AuthCredential *metadata);
bool ctap_user_entity_write(CborWriter *writer, const AuthCredential *credential, bool identifying);
bool ctap_rp_entity_write(CborWriter *writer, const AuthCredential *credential);
bool ctap_credential_descriptor_write(CborWriter *writer, const uint8_t id[32]);
bool ctap_credential_descriptor_write_id(CborWriter *writer, const uint8_t *id, size_t length);
bool ctap_public_key_write(CborWriter *writer, const uint8_t public_key[65]);

#endif
