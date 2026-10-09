# Hardware tasks — waiting for board

Target: Seeed XIAO RP2350. The board is not ready yet. Tasks 8–12 are deferred; resume when the hardware arrives and the user asks to proceed. Confirm touch wiring and set up the target SDK/compiler then. USB integration remains out of scope.

- [ ] **8. Bind the final target providers.** Complete the RP2350 touch, monotonic timing, secure RNG, crypto and durable storage bindings already tracked in `AGENTS.md`. Keep platform implementations outside `src/` and `include/`; preserve opaque key handles and provider-owned credential randoms. Account for any external storage or security-chip provider in the following validation tasks.

- [ ] **9. Validate final cryptographic providers.** Verify SHA-256, HMAC-SHA-256, protocol-2 HKDF, AES-CBC, P-256 ECDH and ECDSA with independent known-answer/interoperability vectors. Exercise invalid/off-curve peer coordinates, key-generation/RNG failure and UV/non-UV credential-secret separation. Confirm errors prevent token, credential or assertion publication.

- [ ] **10. Verify erasure and side-channel behavior with the production toolchain.** Inspect optimized `auth_secure_zero` and `ctap_pin_equal`, and provider code for secret-dependent branches/accesses in scalar, nonce, AES and HMAC operations. Instrument success/failure paths for cleanup of PIN plaintext/verifiers, ECDH/HKDF intermediates, tokens and provider-owned copies. Perform applicable target timing checks and document limitations; volatile writes alone do not prove complete hardware erasure or side-channel resistance.

- [ ] **11. Verify durable failure handling.** Inject interruptions around PIN retry writes, credential replacement/deletion, counter updates and combined Reset using final storage/key providers. Verify retries cannot be restored, counters cannot roll back, abandoned staged keys are recovered and successful Reset leaves no usable old credentials or PIN/token state. Reuse native failure scenarios and coordinate with `AGENTS.md`.

- [ ] **12. Establish the complete firmware stack budget and finish provider-dependent CTAP validation.** Follow `docs/stack-budget.md` with the RP2350 compiler, final optimization/LTO settings and providers. Account for complete live call chains, CBOR recursion, library calls, callbacks, interrupts and persistent workspace RAM; measure high-water usage and reserve a documented margin. Per-function native limits are not firmware stack guarantees. Resolve applicable provider-dependent CTAP checks before claiming device compliance; USB remains outside this task.
