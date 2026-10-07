# Project instructions

- Do not create README files.
- When asked for the next task, give the next implementation step directly. Keep tasks small; prioritize portable implementation and reuse existing targeted checks.
- Keep Python clients, dependencies and test helpers in `tools/python-client/`; PC transport and actions in `examples/host/`.
- Keep `src/` and `include/` independent of Python, console I/O and host APIs. Inject platform actions through callbacks.
- CTAP2 only: no CTAP1/U2F or legacy compatibility paths. Keep CTAPHID_MSG unsupported and advertise CAPABILITY_NMSG.
- Follow the [CTAP 2.3 Proposed Standard (2026-02-26)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html). Claim full compliance only after applicable requirements have been verified.
- Platform stages: PC development → RP2350 onboard resources → custom board/external chips. Separate credential metadata from crypto providers; use opaque key handles without private-key exports or PC-format dependencies.
- Windows is temporary. Keep simulations minimal; defer disproportionate Windows work and hardware-dependent decisions to RP2350, explain the tradeoff, and continue useful portable work.
- Maintain only outstanding work below. Remove completed items; do not restore implementation-history tables or treat optional features as mandatory.

## Remaining CTAP 2.3 work

Reviewed against current code on 2026-10-07. Section numbers refer to the standard above.

### Portable review

- [ ] Finish the clause-by-clause review of supported commands: validation/error precedence, PIN/token lifecycle, continuation state, CBOR bounds and extension processing (§§6, 8, 12). Record only concrete remaining fixes.

### RP2350 integration and final validation

- [ ] Implement USB HID interface/report descriptors, IN/OUT endpoints and transport callbacks (§11.2).
- [ ] Connect physical touch, monotonic timing, secure RNG, crypto and durable storage providers. Verify power-loss recovery, PIN retry persistence, counters and complete Reset erasure.
- [ ] Run applicable CTAP 2.3 conformance checks and real USB/WebAuthn interoperability on the final firmware; fix failures before claiming compliance.
