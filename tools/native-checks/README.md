# Focused native checks

These exercise the actual production storage and crypto providers for the
v1.4.0 recovery and performance changes. They never open a USB device. Synthetic
entropy belongs only to these executables; it must never be used in firmware.

With a native GCC/Clang compiler, CMake and Ninja:

```sh
cmake -S tools/native-checks -B build/native-checks -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/native-checks
./build/native-checks/storage_check
./build/native-checks/crypto_check
```

On Windows, the executables end in `.exe`. For offline builds pass
`-DRP2350_MBEDTLS_PATH=/absolute/path/to/mbedtls-3.6.7`; otherwise the build fetches
the same hash-pinned dependency as the firmware. Assertions remain enabled in
Release. These checks are separate from the firmware and ordinary library build.

`storage_check` creates 32 ES256/Ed25519 credentials, measures PIN writes and a
deletion, interrupts each program-page boundary of deletion/compaction/selector
switching, checks durable PIN charges and rejects a corrupted committed MAC.
It also verifies read-only trial recovery followed by post-confirmation cleanup.
It also injects prefix and interleaved-bit partial NOR programs and partial
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

`crypto_check` verifies ECDH against a peer, rejects an invalid point, verifies a
signature and rejects a modified digest. It also verifies automatic reseed
limits and terminal failures with cleared output when entropy fails. CPU timings
are native timings, not RP2350 performance claims.
