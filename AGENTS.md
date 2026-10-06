# Project instructions

- Do not create or add README files in this project. The user explicitly forbids them.
- This is a modern CTAP2-only authenticator. Do not implement CTAP1/U2F or legacy compatibility paths. Keep CTAPHID_MSG unsupported and advertise CAPABILITY_NMSG in INIT. Focus future authenticator work on current CTAP2 capabilities.
