#ifndef CTAPHID_HOST_STORAGE_H
#define CTAPHID_HOST_STORAGE_H

#include <stdbool.h>
#include <stdint.h>

/* Volatile test fixture, not a production credential/PIN implementation. The
 * records/verifier are dummy data used to verify that confirmed reset erases
 * state and rotates identifiers. No existing user data or physical keys accessed. */
typedef struct {
    uint8_t mock_records[2][32];
    uint8_t mock_pin_verifier[32];
    uint32_t mock_credential_count;
    bool mock_pin_set;
    uint8_t device_identifier[16], credential_store_state[16];
    uint32_t generation;
    char snapshot_path[1024], temporary_path[1024];
} HostStorage;

bool ctaphid_host_storage_init(HostStorage *storage, const char *control_directory);
bool ctaphid_host_storage_reset(void *context);

#endif
