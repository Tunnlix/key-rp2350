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

## Regression check

GCC builds emit `.su` stack-usage reports for every core source. CMake also sets
`-Wstack-usage=1024` for `ctap_credential_management.c`; the core's `-Werror`
turns excess or unbounded per-function usage into a build failure. Configure
`CTAP_CM_STACK_BUDGET` to a positive byte count when establishing a different
target/compiler baseline. Review the reports before increasing this limit.
Other compilers print that this check is unavailable. MSVC test success does
not validate the stack budget.

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

## Establishing the firmware budget

The 1,024-byte check is per function and currently covers only credential
management. Registration and credential-service scratch migration remain in
`tasks.md`. A complete stack bound is not established yet.

With final firmware optimization/LTO settings, account for each simultaneously
live call chain through the coordinator, command handler, credential service,
CBOR reader and provider. The CBOR reader permits depth values 0 through 4,
so its recursive frame can be live five times. Include library calls, callback
targets, exception/interrupt stacking and the platform's nesting policy.
Measure the target's high-water mark under maximum-size and failure requests,
then reserve margin in the firmware task stack. Native mock-provider results
cannot establish that RP2350 bound.
