# Project instructions

- Do not create or add README files in this project. The user explicitly forbids them.
- When the user asks for the next task, state the next implementation step directly. Avoid recurring certification/conformance caveats in routine planning replies; provide those details when the user asks about compliance or when needed for a concrete implementation decision.
- Keep the optional Python test client, its dependencies, tests, and build helper in tools/python-client/. PC-only C transport and actions belong in examples/host/. Keep src/ and include/ independent of Python, console I/O, and host OS APIs; inject platform actions through callbacks for embedded use.
- This is a modern CTAP2-only authenticator. Do not implement CTAP1/U2F or legacy compatibility paths. Keep CTAPHID_MSG unsupported and advertise CAPABILITY_NMSG in INIT. Focus future authenticator work on current CTAP2 capabilities.
- Follow the published CTAP 2.3 Proposed Standard (2026-02-26): https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html . Do not claim full authenticator conformance while mandatory CTAP operations remain unimplemented.
- Maintain three platform stages: PC development, RP2350 using onboard resources, and a later custom board with external chips. Keep credential metadata storage separate from key generation/signing providers. Portable code uses opaque key handles and must never depend on exporting private-key bytes or PC file formats.
- Windows is a temporary development/test base while waiting for RP2350 hardware, not a product to expand or harden for its own sake. Prefer simple, small, maintainable implementations and minimal PC simulations that validate portable behavior. Avoid large platform-specific subsystems, speculative abstractions, and work that will need to be implemented again on RP2350. When Windows-specific work becomes disproportionate or hardware-dependent decisions would cause rework, tell the user plainly, explain the tradeoff, and recommend deferring that part until RP2350 is available. Continue useful portable work and testing where possible.

## Implementation and CTAP 2.3 checklist

Last reviewed: 2026-10-06. Maintain this checklist whenever commands, capabilities,
providers or their tests change. Confirm entries from code and tests; do not mark
planned work as implemented or advertise unsupported capabilities.

Reference: [CTAP 2.3 Proposed Standard, 2026-02-26](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).

- **Implemented: Yes** means the listed scope exists in this repository.
- **CTAP checks: Yes** means project tests cover the stated CTAP behavior. This
  is engineering evidence for that scope, not a complete compliance audit or
  FIDO certification. Platform callbacks must fulfill their documented contracts.
- **No** means missing, intentionally unsupported, or not established, as noted.
  An unsupported optional feature is not automatically a conformance failure.
- **Full CTAP 2.3 conformance established: No.** hmac-secret is implemented with
  protocol 2; the complete normative audit and real USB/embedded validation
  remain pending. Treat the version as a development target.
- **FIDO certification completed: No.** Local tests and python-fido2 interoperability
  do not establish certification or production hardware security.

### HID framing and transaction coordination

| Feature | Implemented | CTAP checks | Current scope / evidence |
| --- | --- | --- | --- |
| Report parser | Yes | Yes | Fixed 64-byte reports, initial/continuation decoding, CID, command, length and sequence fields. `ctaphid_parser.c`, `test_ctaphid.c`. |
| Request reassembler | Yes | Yes | Bounded 1024-byte requests; sequence, length, channel and packet validation. `ctaphid_reassembler.c`, `test_ctaphid.c`. |
| Assembly expiry | Yes | Yes | Partial-message timeout and wrap-safe timestamps; expiry clears old state and incoming reports continue processing. Reassembler/device tests. |
| Response serializer | Yes | Yes | Initial/continuation framing, zero-length replies, zero padding and callback delivery. Standalone serializer covers payloads through 7609 bytes; device queues support 1024 bytes. `test_ctaphid_response.c`. |
| Channel allocation and validation | Yes | Yes | Fixed capacity of 16 allocated CIDs; reject invalid/unallocated CIDs; broadcast allocation and reserved-CID handling. Channels/INIT/device tests. |
| Transaction coordinator | Yes | Yes | Receiving, processing and sending ownership; other-channel busy errors; queued replies; same-CID INIT abort/resynchronization. `ctaphid_device.c`, device tests. |
| Async report completion | Yes | Yes | Transfer tokens, stale-completion rejection, abort hook and transport watchdog. Core behavior tested with simulated transport. |
| `CTAPHID_INIT` | Yes | Yes | Nonce echo, CID assignment, HID protocol version 2, configured capabilities and same-channel resynchronization. INIT/Python tests. |
| `CTAPHID_PING` | Yes | Yes | Exact payload echo from zero through 1024 bytes, including fragmentation. PING/Python tests. |
| `CTAPHID_CBOR` | Yes | Yes | CTAP backend bridge, status-byte replies, configured CBOR capability and command routing. Backend/Python tests. |
| `CTAPHID_CANCEL` | Yes | Yes | Cancels a running CBOR operation on its CID; original request gets `KEEPALIVE_CANCEL`; CANCEL receives no reply. Stale/idle/other-CID events cannot authorize work. Device/operation tests. |
| `CTAPHID_KEEPALIVE` | Yes | Yes | PROCESSING/UPNEEDED status and 100 ms scheduling while processing, with regular device polling. Device/presence tests. |
| `CTAPHID_ERROR` | Yes | Yes | Transport errors are framed separately from CTAP status replies. Device/response/Python tests. |
| `CTAPHID_WINK` | Yes | Yes | Empty acknowledgement and injected identification action; advertised only when the callback is configured. PC action logs; embedded LED action remains to be supplied. |
| `CTAPHID_LOCK` | No | No | Optional command intentionally unsupported; no lock capability is advertised. Rejection is tested. |
| CTAP1/U2F `CTAPHID_MSG` execution | No | No | Intentionally forbidden for this project. Unsupported-command response and `CAPABILITY_NMSG` are implemented and tested. Do not add CTAP1 compatibility. |
| Actual USB HID device/descriptors | No | No | Current host uses a subprocess transport, not a physical USB authenticator. RP2350 USB integration and hardware interoperability are pending. |

### CTAP commands and credential behavior

| Feature | Implemented | CTAP checks | Current scope / evidence |
| --- | --- | --- | --- |
| Canonical CBOR reader/writer | Yes | Yes | Definite lengths, shortest integers, ordered/nonduplicate map keys, UTF-8, four nesting levels and no tags. Unknown supported CBOR value types can be skipped. CBOR/operation tests. |
| Shared request validation | Yes | Yes | Parameter maps, text-key maps and credential descriptors, including transports; malformed input rejected before touch or key/counter effects. `ctap_request.c`, MakeCredential/GetAssertion tests. |
| `authenticatorGetInfo` | Yes | Yes | Reports development FIDO_2_3, model AAGUID, maxMsgSize=1024, rk=false, configured UP, plat=false; configured credentials add ES256, packed and makeCredUvNotRqd=true. Complete secret provider adds hmac-secret and pinUvAuthProtocols=[2]; no clientPin/uv/token capability is claimed. |
| `authenticatorMakeCredential` | Yes | Yes | Non-discoverable ES256 credentials, request validation, fresh UP, RP-bound exclusion, capacity errors, cancellation and provider failure cleanup. Native/Python tests. |
| Registration authenticator data | Yes | Yes | RP hash, UP/AT flags, zero initial counter, AAGUID, 32-byte credential ID and EC2/P-256 COSE key. Requested hmac-secret adds signed boolean extension output and ED. Attestation/Python tests. |
| Packed self-attestation | Yes | Yes | Credential key signs authenticatorData plus clientDataHash through the crypto provider; canonical DER signature independently verified. No attestation certificate infrastructure. |
| `none` attestation | Yes | Yes | Single `none` format preference produces empty attStmt and zero AAGUID. MakeCredential tests. |
| `authenticatorGetAssertion` | Yes | Yes | Validates the entire allowList, selects one RP-bound credential and collects fresh UP. Base authenticator data is 37 bytes; hmac-secret appends signed encrypted outputs and sets ED. Native/Python tests. |
| Silent assertion (`up=false`) | Yes | Yes | No touch gate for ordinary assertions; UP=0 and UV=0. hmac-secret with up=false is rejected with UNSUPPORTED_OPTION. GetAssertion/extension tests. |
| Durable signature counters | Yes | Yes | Per-credential increment persisted before signing; cancellation while waiting changes nothing; signing failure may skip a value; overflow fails closed. Counter/GetAssertion/provider tests. |
| Assertion privacy and RP binding | Yes | Yes | Wrong RP/unknown credentials return NO_CREDENTIALS; no user details, userSelected or account count returned for current allowList flow. Tests verify signatures and RP hashes. |
| `authenticatorSelection` | Yes | Yes | Fresh operation-specific touch, denial, timeout and cancellation. Presence/backend/Python tests. |
| `authenticatorReset` | Yes | Yes | No-display power-on eligibility window, fresh UP and combined application reset callback. PC reset atomically clears records/keys/PIN verifier and retries, clears volatile PIN blocking on success, and rotates identifiers; INIT/reset does not restart the power-on clock. Reset/provider/Python tests. |
| Discoverable credentials (`rk=true`) | No | No | Advertise rk=false; creation request rejected. GetAssertion without allowList does not discover non-discoverable records. Unsupported behavior tested. |
| `authenticatorGetNextAssertion` | No | No | Not implemented; no enumeration state or multiple-assertion count is produced. Current allowList flow returns one assertion. |
| ClientPIN getKeyAgreement / protocol 2 crypto | Yes | Yes | Reusable protocol 2 helpers: ephemeral P-256 ECDH, two independent HKDF expansions, HMAC-SHA-256 authentication and AES-256-CBC (16/32/64-byte plaintext) with random IVs. Key regenerated on power-on/Reset and wrong PIN. hmac-secret regression tests and genuine python-fido2 PIN crypto tests. |
| PIN setup/change and retries | Yes | Yes | Development maintenance handler supports protocol 2 getPINRetries, setPIN and changePIN; UTF-8/code-point policy, durable decrement before verifier checks, eight-attempt permanent blocking, three-mismatch power-cycle blocking, agreement regeneration, persistence failures, CANCEL/INIT and Reset cleanup. Native tests and portable python-fido2 crypto tests pass; Windows CNG/DPAPI vault integration tests are present but were not run in the Linux review environment. No clientPin/uv/pinUvAuthToken capability is advertised until authorization is complete. |
| PIN tokens and UV authentication | No | No | No tokens, permissions or PIN authorization for MakeCredential/GetAssertion. clientPin/uv/pinUvAuthToken options omitted; unsupported PIN/UV auth parameters rejected. PIN maintenance alone does not set returned UV flags. |
| Built-in user verification / biometrics | No | No | No UV provider or biometric enrollment. UP is not UV; uv=true requests are rejected and returned UV flags stay clear. |
| `authenticatorCredentialManagement` | No | No | No CTAP enumeration, deletion or user-update command. Internal credential-service deletion exists but is not this command. |
| `authenticatorBioEnrollment` | No | No | No biometric enrollment command or capability. |
| `authenticatorLargeBlobs` | No | No | No large-blob storage protocol or largeBlobKey output. |
| `authenticatorConfig` | No | No | No enterprise-attestation enablement, alwaysUV, minimum PIN length or long-touch configuration. |
| `hmac-secret` | Yes | Yes | Protocol 2, one/two salts, fresh UP, authenticated encryption input and signed encrypted output. Provider creates independent WithUV/WithoutUV randoms with every new key; current requests use WithoutUV. Legacy keys without randoms omit extension output. Secret material stays provider-owned and is erased by key deletion/Reset. Native/Python tests include determinism, salt/credential separation, persistence, legacy vaults and invalid authentication. |
| `hmac-secret-mc` | No | No | Not implemented or advertised. |
| `credProtect` | No | No | Not implemented or advertised; reevaluate its conditional requirements before adding PIN/UV. |
| `credBlob`, `largeBlobKey`, `minPinLength`, PIN complexity and payment extensions | No | No | Not implemented or advertised; unsupported extension inputs are ignored without extension outputs. |
| Enterprise/batch certificate attestation | No | No | Only packed self-attestation and none are supported; enterprise-attestation requests rejected. Production attestation identity/certificates are pending. |
| Always-UV and long-touch Reset | No | No | Neither feature is advertised or configured; normal fresh-touch Reset is implemented. |
| NFC, BLE and hybrid transports | No | No | No transport adapters for these bindings; optional future scope. |

### Platform, storage and test support

These are implementation/test facilities, not separate CTAP conformance claims.

| Facility | Implemented | Current scope / evidence |
| --- | --- | --- |
| Portable core | Yes | `src/` and `include/` use injected callbacks; no Python, console, OS APIs or private-key exports. Freestanding compilation and static analysis checked. |
| Separate crypto and metadata storage interfaces | Yes | AuthCrypto, AuthStorage and optional AuthSecretCrypto use opaque key handles; private keys and per-credential randoms stay in providers. AuthCredentialService composes application-owned interfaces. |
| Credential lifecycle and failure handling | Yes | Random IDs, RP binding, key creation, persistence, deletion, counter updates and cleanup attempts. Provider failures do not produce successful CTAP replies. Native service/operation tests. |
| Current PC crypto provider | Yes | Windows CNG RNG, SHA-256, P-256 signing/ECDH, HMAC-SHA-256 and AES-256-CBC; opaque handles and provider-owned credential randoms. Real signatures and protocol 2 interoperability checked by python-fido2. |
| Current PC persistent vault | Yes | DPAPI-encrypted v3 key/random/metadata/PIN-verifier vault, exclusive access, atomic writes and fail-closed corruption handling. Reads v1/v2 with an unset PIN; v1 keys retain their missing secrets. Successful writes upgrade it. Windows v3 integration checks remain pending in the current Linux environment. Development storage, not a secure element or protection against owner-controlled whole-file rollback. |
| PC transport and action adapters | Yes | Optional stdio/hex harness, monotonic clock, WINK action, simulated touch/denial and temporary or explicit persistent vault. All under `examples/host/`. |
| Optional python-fido2 client | Yes | Genuine library HID/CTAP requests over the subprocess peer, plus a small test-only portable PIN bridge with real Python crypto callbacks. Build helper, bridge, tests and interactive demos remain under `tools/python-client/`. |
| WebAuthn registration/authentication interoperability | Yes | Local python-fido2 server accepts registration and authentication; tests validate challenge, origin, RP binding, UP and ES256 signature. This is not physical USB/browser interoperability or certification. |
| Native failure/timing tests | Yes | Parser/serializer boundaries, virtual deadlines, cancellation/resynchronization, stale tokens, storage/signing failures, counter durability, PIN policy/retry persistence, power-cycle blocking and PIN Reset cleanup. |
| RP2350 transport, touch, crypto and storage adapters | No | Architecture is ready for provider replacement; real embedded integration and hardware checks remain pending. |
| External security-chip provider/custom board | No | Future third platform stage; no chip-specific implementation yet. |

### Conformance gates for future work

- Preserve hmac-secret/protocol 2 behavior and provider-owned secrets as storage,
  transports and PIN/UV support evolve.
- If rk=true is introduced, review section 9 requirements for PIN/UV and credential
  management, plus discovery, user-handle responses and multiple-assertion state.
- If PIN/UV is introduced, review protocol two, token/permission state and
  credential-protection requirements before changing GetInfo.
- Recheck dependencies whenever a new option or extension is advertised. Keep
  unsupported options absent/false as appropriate; omission and false have
  different meanings for capabilities such as clientPin and uv.
- Complete the applicable normative audit and real transport/provider validation
  before marking full conformance Yes. Mark certification Yes only after the
  relevant FIDO certification process is actually completed.
