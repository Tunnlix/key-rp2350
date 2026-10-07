# Project instructions

- Do not create README files.
- When asked for the next task, give the next implementation step directly. Keep tasks small; prioritize portable implementation and reuse existing targeted checks.
- Follow `tasks.md` in execution order unless the user changes priorities.
- This repository now contains the portable C17 core and native C tests only. Do not reintroduce Windows implementations, Python clients/helpers, host examples or platform-specific runtime dependencies.
- Keep `src/` and `include/` independent of console I/O, heap allocation and host APIs. Inject platform actions through callbacks; providers own private keys and credential randoms.
- CTAP2 only: no CTAP1/U2F or legacy compatibility paths. Keep CTAPHID_MSG unsupported and advertise CAPABILITY_NMSG.
- Follow the [CTAP 2.3 Proposed Standard (2026-02-26)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html). Claim full compliance only after applicable requirements have been verified.
- Target RP2350 onboard resources, then a possible custom board/external security chip. Separate credential metadata from crypto providers; use opaque key handles without private-key exports or persistent-format dependencies.
- USB integration, descriptors, endpoints and USB/WebAuthn hardware testing are explicitly out of scope for this refactoring. Preserve the portable CTAPHID codec/coordinator; do not add a USB driver.
- Maintain only outstanding work below. Remove completed items; do not restore implementation-history tables or treat optional features as mandatory.

## Remaining CTAP 2.3 work

Reviewed against current code on 2026-10-07. Section numbers refer to the standard above.

### Build and review boundaries

Use `cmake --preset native-tests`, `cmake --build --preset native-tests`, then
`ctest --preset native-tests`. The `core-only` configure/build presets produce
the library without tests. Firmware can use `add_subdirectory()` and link
`ctap_core` with `BUILD_TESTING=OFF`; it supplies providers and its main loop.

Retain native protocol, state-machine, failure and bounds tests. Their mock
primitives verify orchestration, not crypto algorithms, flash durability or
physical touch. Do not advertise optional capabilities until their complete
provider/handler requirements are bound. Full claims require the applicable
checks on the actual providers, independent of this core-only refactoring.

### Remaining work outside the portable core

- [ ] Bind RP2350 touch, monotonic timing, secure RNG, crypto and durable storage providers. Verify primitive known-answer vectors, power-loss recovery, PIN retry persistence, counters and complete Reset erasure.
- [ ] Validate applicable CTAP behavior with the final providers before claiming device compliance; USB remains outside this task.
- [ ] Remove ignored local tooling/binary remnants (`.venv`, old `main.exe`, Python bytecode and obsolete build outputs). Automatic shell safety review rejected their deletion with "blocked by policy" during this task. Tracked PC/Python sources were removed; do not bypass the safety check to erase the remaining artifacts.
