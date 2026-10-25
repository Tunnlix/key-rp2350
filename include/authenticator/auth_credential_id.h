#ifndef AUTH_CREDENTIAL_ID_H
#define AUTH_CREDENTIAL_ID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Protocol bound, independent of the compact 32-byte resident locator and
 * provider key handles. Never allocate this maximum for every resident index. */
#define AUTH_CREDENTIAL_ID_MAX_SIZE 256U
bool auth_credential_id_length_valid(size_t length);

#endif
