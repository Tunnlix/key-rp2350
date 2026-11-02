# Focused native checks

These exercise the actual production storage and crypto providers for the
recovery, performance and protocol changes. They never open a USB device. Synthetic
entropy belongs only to these executables; it must never be used in firmware.

With a native GCC/Clang compiler, CMake and Ninja:

```sh
cmake -S tools/native-checks -B build/native-checks -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/native-checks
./build/native-checks/storage_check
./build/native-checks/crypto_check
./build/native-checks/device_feature_check
```

On Windows, the executables end in `.exe`. For offline builds pass
`-DRP2350_MBEDTLS_PATH=/absolute/path/to/mbedtls-3.6.7`; otherwise the build fetches
the same hash-pinned dependency as the firmware. Assertions remain enabled in
Release. These checks are separate from the firmware and ordinary library build.

`storage_check` creates 32 ES256/Ed25519 credentials, measures PIN writes and a
deletion, interrupts each program-page boundary of deletion/compaction/selector
switching, checks durable PIN charges and rejects a corrupted committed MAC.
It verifies read-only trial recovery followed by post-confirmation cleanup and
injects prefix and interleaved-bit partial NOR programs and partial
selector-sector erases. These are representative fault patterns, not exhaustive
hardware qualification, physical-tampering resistance or ROM rollback tests.
An optional argument names a 512 KiB synthetic v1.3 store snapshot: the check
then verifies 32 old keys, signatures, a new-format PIN update and compaction.
Never supply a dump containing real private keys to this development tool.
Use `--bench` for just the native work-count/timing fixture, or `--policy` for
the shorter PIN/blob checks while working on those paths. The default run also
checks wrong permissions, token expiry, fragment timeouts, interrupted blob
commits, three-try power-cycle blocking, durable retry exhaustion and forced PIN
change. A CM-style benchmark requests public and blob keys for every synthetic
credential; it is not a measurement of a particular manager's full UI refresh.

The PIN/blob checks also exercise both PIN protocols through assertion and
registration completion: user presence preserves only Large Blob Write
permission, including excluded credentials and deferred extension failures.
Silent assertions preserve permissions. Removed permissions, old tokens, stale
prepared-token generations and expired tokens are rejected.

Minimum-PIN-length checks exercise authenticated RP allowlist configuration under
both PIN protocols, duplicate/empty/replaced/oversized lists, legacy and extended
PIN records, cold recovery and every page boundary of a policy append. They also
parse actual MakeCredential CBOR and verify packed self-attestation signatures
for authorized, unauthorized, unrequested and false minPinLength inputs.

`crypto_check` verifies ECDH against a peer, rejects an invalid point, verifies a
signature and rejects a modified digest. It also verifies automatic reseed
limits and terminal failures with cleared output when entropy fails. CPU timings
are native timings, not RP2350 performance claims.

Entropy checks inject start, hardware status, timeout, poll-limit, repeated/stuck
output and configuration faults, including faults after EHR reads and before
buffered delivery. They verify status retention, output clearing and terminal
latching. CRNGT recovery checks require fresh valid output, enforce a shared
three-retry request budget without extending collection deadlines, and reject
simultaneous valid/error flags, other health faults, adapter refusal, cached or
post-read errors and missing fresh output. LED checks count each pulse and its width for every entropy failure
type/status combination; the diagnostic emits only a failure code and status.

Use `storage_check --identifiers` for the focused GetInfo/reset checks. It verifies
pre-PIN discovery without granting permissions, stable tokens across reboot,
fresh IVs, reset separation, interrupted migration recovery and read-only trial
initialization. `--policy` also covers persistent read-only inventory, payment
attributes, long-touch reset and optional attestation providers.

`device_feature_check` covers WINK, LOCK ownership/release/expiry, five-second
reset consent, UVM output and GetInfo encoding. LOCK tests do not set the reserved
legacy capability bit merely to activate the official tool's conditional cases.

For a configured attestation lab, set `TUNNLIX_ENTERPRISE_TEST_OUTPUT` to an empty
local directory when running `storage_check --policy`. Verify its public response
fixtures independently with:

```sh
python3 tools/native-checks/verify-enterprise-results.py \
  build/enterprise-lab/identity build/attestation-replies \
  --batch-identity build/ordinary-lab/identity
```

The verifier requires Python with `cryptography` and `fido2`. It checks certificate
chains, signatures, tamper rejection, credential algorithms, ordinary/enterprise
identity separation and explicit `none` attestation. Omit `--batch-identity` when
no ordinary identity is configured. Generated replies and all identities stay
outside the public source tree.

PIN complexity is enabled by default. Configure another build directory with
`-DCTAP_PIN_COMPLEXITY=OFF` to check the excluded-feature profile. Both profiles
exercise setPIN/changePIN for protocols 1/2, sticky configuration, interrupted
policy writes, legacy policy transition, discovery and signed RP-authorized
extension output. The OFF profile also rejects an enabled persisted policy.
`device_feature_check` covers whole-value/case matching, repeated Unicode, numeric
PINs/spaces and absence of the optional URL. `storage_check --policy` runs the
focused policy/credential suite; the full invocation adds synthetic power cuts.
These programs use synthetic flash and never reset a connected device.
