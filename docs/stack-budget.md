# Core stack budgeting

Allocate `CtaphidCtapBackend` and its embedded `CtapCredentialManagement` in
static or other caller-owned persistent RAM. Moving the backend onto a task's
stack defeats the credential-management workspace allocation. Serialize calls
on each instance, including provider callbacks; buffers must not alias the
management state. Providers may not retain pointers to workspace records.

Credential management uses two temporary metadata records, a shared MAC/response
buffer and an RP-hash table. MAC verification finishes before response encoding
reuses the byte buffer. Every execution exit securely clears the workspace;
only the authenticated enumeration snapshot survives between successful calls.
The workspace contains opaque key handles, not private keys.

On native x64 GCC 16.2, the workspace occupies 4,352 bytes and the complete
management state 4,944 bytes. Use `sizeof` with the firmware compiler for its RAM
budget; structure alignment and configuration affect these values.

Allocate `AuthCredentialService` in persistent caller-owned RAM as well. Resident
creation owns a 2,968-byte workspace on native x64 GCC: two records, the previous
credential's ID/opaque handle, store-state random and generated public key.
Only the old ID and handle survive the enumeration scan. The scan validates
provider records directly, avoiding a second full-record stack copy. Creation
wipes the workspace on success and every failure. A nested resident-creation
call on the same service is rejected without clearing the active workspace.
Callbacks borrow their arguments only for the duration of the call.

Registration finish takes a `CtapMakeCredentialWorkspace *` as its second
argument. The backend owns and initializes one; direct callers must allocate
and zero-initialize their own in persistent RAM. It holds the temporary
credential, public key and response, using 2,000 bytes on native x64 GCC.
Both finish entry points clear idle scratch on return; reuse while busy is
rejected without touching the active operation. Response bytes are copied to
the caller only after successful persistence and cleanup.

## Regression check

GCC builds emit `.su` stack-usage reports for every core source. CMake also sets
`-Wstack-usage=1024` for `ctap_credential_management.c`; the core's `-Werror`
turns excess or unbounded per-function usage into a build failure. Configure
`CTAP_CM_STACK_BUDGET` to a positive byte count when establishing a different
target/compiler baseline. Review the reports before increasing this limit.
Other compilers print that this check is unavailable. MSVC test success does
not validate the stack budget.

`auth_resident.c` has a separate 512-byte per-function limit configured through
`CTAP_RESIDENT_STACK_BUDGET`. Keeping creation in its own source file applies
this limit without allowing the larger, unmigrated credential-service frames.

`ctap_make_credential_finish.c` has a 512-byte per-function limit configured
through `CTAP_MC_FINISH_STACK_BUDGET`. Registration preparation remains in a
separate source file and is not covered by that limit.

For example, with GCC and Ninja available:

```sh
cmake -S . -B build/stack-review -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-O2
cmake --build build/stack-review
ctest --test-dir build/stack-review --output-on-failure
```

Native GCC 16.2 x64 measurements, in bytes:

| Credential-management function | `-O2` | `-O0` |
| --- | ---: | ---: |
| Public execute/cleanup wrapper | 112 | 112 |
| Internal command execution | 720 | 784 |
| Entry response encoding | 192 | 192 |
| Sum of these simultaneously live frames | 1,024 | 1,088 |

Before migration, execution and entry encoding alone totalled 7,616 bytes at
`-O2`. The new sums exclude callers, other callees, providers and interrupts;
they are **not** a required firmware stack size. Credential-service mutation
and lookup frames still contribute substantial stack on other branches.

Resident creation's helper uses 128 bytes at `-O2` and 208 bytes at `-O0`; its
public cleanup wrapper uses 80 bytes in both builds. Their combined contribution
is 208/288 bytes, compared with the previous 4,432-byte creation frame at `-O2`.
These values exclude the convenience entry point, registration caller, callees
and provider callbacks. Caller-owned workspace RAM is additional to the stack.

Registration finish's helper uses 240 bytes at `-O2` and 224 bytes at `-O0`;
its cleanup wrapper uses 96 bytes in both builds. The combined contribution
is 336/320 bytes, compared with the previous 2,240-byte finish frame at `-O2`.
The response callback adds 272/304 bytes when active. These figures exclude
credential-service calls, attestation/crypto helpers and provider stack.

## Establishing the firmware budget

The checks are per function and cover credential management, resident creation
and registration finish. Preparation and other credential-service scratch migration remain in
`tasks.md`. A complete stack bound is not established yet.

With final firmware optimization/LTO settings, account for each simultaneously
live call chain through the coordinator, command handler, credential service,
CBOR reader and provider. The CBOR reader permits depth values 0 through 4,
so its recursive frame can be live five times. Include library calls, callback
targets, exception/interrupt stacking and the platform's nesting policy.
Measure the target's high-water mark under maximum-size and failure requests,
then reserve margin in the firmware task stack. Native mock-provider results
cannot establish that RP2350 bound.
