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

Allocate `AuthCredentialService` in persistent caller-owned RAM as well. Both
creation paths share a 2,968-byte workspace on native x64 GCC: two records, the previous
credential's ID/opaque handle, store-state random and generated public key.
Only the old ID and handle survive the enumeration scan. The scan validates
provider records directly, avoiding a second full-record stack copy. Creation
wipes the workspace on success and every failure. Any nested creation call on
the same service is rejected without clearing the active workspace. Non-resident
creation reuses its records and public-key buffer, adding no RAM to the service.
Callbacks borrow their arguments only for the duration of the call.

Lookup, enumeration, signing, counter updates, deletion and user updates share
a separate 1,408-byte credential record. A single operation owns it through
validation and its dependent provider action, then wipes it on every acquired
exit. Rejected nested operations do not clear the active record. Keeping it
separate permits stored-record reads during resident preparation; mutations
during creation and creation during an active lookup are rejected. The service
now occupies 4,616 bytes on native x64 GCC, a 1,416-byte increase with alignment
and the lookup guard. Input/output must not alias either internal workspace.

Registration preparation and finish take a `CtapMakeCredentialWorkspace *` as their second
argument. The backend owns and initializes one; direct callers must allocate
and zero-initialize their own in persistent RAM. It holds the temporary
credential, public key and response, sharing a union with preparation's request
and exclusion-lookup record. It uses 3,232 bytes on native x64 GCC, an increase
of 1,232 bytes. All prepare/finish entry points clear acquired scratch on return; reuse while busy is
rejected without touching the active operation. Response bytes are copied to
the caller only after successful persistence and cleanup. Preparation copies
its result to separate caller-owned output only on success.

Assertion preparation, finish and GetNextAssertion take a
`CtapGetAssertionWorkspace *` as their second argument. Allocate and
zero-initialize it in persistent RAM; the backend owns one automatically.
Request state and the credential record are shared across these operations;
discovery ordering and finish buffers occupy a union. The workspace uses
3,432 bytes on native x64 GCC, an increase of 992 bytes over preparation alone.
Every acquired exit wipes scratch; nested use preserves the active workspace.
Prepared output is separate and published only on success. Finish encodes into
scratch and copies the response only after counter persistence, signing and
encoding succeed. Continuation copies its request into scratch before selecting
the next ID; its authenticated sequence remains separate between calls.

## Regression check

GCC builds emit `.su` stack-usage reports for every core source. CMake also sets
`-Wstack-usage=1024` for `ctap_credential_management.c`; the core's `-Werror`
turns excess or unbounded per-function usage into a build failure. Configure
`CTAP_CM_STACK_BUDGET` to a positive byte count when establishing a different
target/compiler baseline. Review the reports before increasing this limit.
Other compilers print that this check is unavailable. MSVC test success does
not validate the stack budget.

`auth_resident.c` has a separate 512-byte per-function limit configured through
`CTAP_RESIDENT_STACK_BUDGET`.

`auth_credentials.c` has a 512-byte per-function limit configured through
`CTAP_CREDENTIALS_STACK_BUDGET`, covering lookup, enumeration and mutations.

`auth_nonresident.c` has a 512-byte per-function limit configured through
`CTAP_NONRESIDENT_STACK_BUDGET`; collision checks and insertion cleanup remain
inside this checked module.

`ctap_make_credential_finish.c` has a 512-byte per-function limit configured
through `CTAP_MC_FINISH_STACK_BUDGET`. `ctap_make_credential.c` has a separate
1,024-byte per-function limit through `CTAP_MC_PREPARE_STACK_BUDGET`.

`ctap_get_assertion_prepare.c` has a 1,024-byte per-function limit through
`CTAP_GA_PREPARE_STACK_BUDGET`. `ctap_get_assertion.c` has a 512-byte
per-function limit through `CTAP_GA_FINISH_STACK_BUDGET`, covering finish and
continuation entry points.

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
they are **not** a required firmware stack size.

Resident creation's helper uses 128 bytes at `-O2` and 208 bytes at `-O0`; its
public cleanup wrapper uses 80 bytes in both builds. Their combined contribution
is 208/288 bytes, compared with the previous 4,432-byte creation frame at `-O2`.
These values exclude the convenience entry point, registration caller, callees
and provider callbacks. Caller-owned workspace RAM is additional to the stack.

Non-resident creation's helper uses 112 bytes at `-O2` and 128 bytes at `-O0`;
its cleanup wrapper uses 96 bytes in both builds. Their combined contribution
is 208/224 bytes, compared with the previous 2,992-byte creation frame at `-O2`.
These values exclude the convenience entry point and provider callees.

Registration finish's helper uses 240 bytes at `-O2` and 224 bytes at `-O0`;
its cleanup wrapper uses 96 bytes in both builds. The combined contribution
is 336/320 bytes, compared with the previous 2,240-byte finish frame at `-O2`.
The response callback adds 272/304 bytes when active. These figures exclude
credential-service calls, attestation/crypto helpers and provider stack.

Registration preparation's helper uses 960 bytes at `-O2` and 832 bytes at
`-O0`; its cleanup wrapper uses 80/96 bytes. At `-O2` the helper includes
inlined exclusion lookup, replacing the previous 4,144-byte helper frame.
At `-O0` exclusion lookup adds 224 bytes, down from 1,632 bytes; preparation
previously used 2,640 bytes. These figures exclude the convenience entry point,
CBOR and credential-service callees, and provider stack.

Assertion preparation's helper uses 640 bytes at `-O2` and 768 bytes at
`-O0`; its cleanup wrapper adds 80/96 bytes. The previous preparation frame
used 3,008/3,168 bytes. These figures exclude the convenience entry point,
CBOR, credential-service and provider callees.

Assertion finish's helper uses 240 bytes at `-O2` and 304 bytes at `-O0`,
down from 2,720/2,768 bytes. Its timed wrapper adds 80 bytes; the convenience
wrapper adds 96 bytes. GetNextAssertion uses 96 bytes in both builds, down
from 992, and calls the same finish helper. These totals exclude backend,
credential-service, CBOR, extension and provider callees.

The migrated lookup/mutation functions use 64–96 bytes at `-O2`; the shared
lookup helper uses 80 bytes. At `-O0` those functions use 64–80 bytes, lookup
uses 64 bytes and cleanup uses 48 bytes. For example, the `get` and lookup
frames total 144 bytes at `-O2`, replacing the previous 1,472-byte `get` frame;
deletion plus lookup totals 176 bytes, replacing 1,520 + 1,472 bytes. These
totals exclude their provider, validation and erasure callees.

## Establishing the firmware budget

The checks are per function and cover credential management, credential service,
both creation paths, registration and assertion preparation/finish, and assertion
continuation. A complete firmware stack bound remains outstanding in `tasks.md`.

With final firmware optimization/LTO settings, account for each simultaneously
live call chain through the coordinator, command handler, credential service,
CBOR reader and provider. The CBOR reader permits depth values 0 through 4,
so its recursive frame can be live five times. Include library calls, callback
targets, exception/interrupt stacking and the platform's nesting policy.
Measure the target's high-water mark under maximum-size and failure requests,
then reserve margin in the firmware task stack. Native mock-provider results
cannot establish that RP2350 bound.
