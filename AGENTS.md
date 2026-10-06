# Project instructions

- Do not create or add README files in this project. The user explicitly forbids them.
- Keep the optional Python test client, its dependencies, tests, and build helper in tools/python-client/. PC-only C transport and actions belong in examples/host/. Keep src/ and include/ independent of Python, console I/O, and host OS APIs; inject platform actions through callbacks for embedded use.
- This is a modern CTAP2-only authenticator. Do not implement CTAP1/U2F or legacy compatibility paths. Keep CTAPHID_MSG unsupported and advertise CAPABILITY_NMSG in INIT. Focus future authenticator work on current CTAP2 capabilities.
- Follow the published CTAP 2.3 Proposed Standard (2026-02-26): https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html . Do not claim full authenticator conformance while mandatory CTAP operations remain unimplemented.
