# Firmware roadmap

## 1.1.0

Last built candidate: **1.1.0-rc.1**. Current source includes an unreleased
resident-enumeration compatibility fix. A new image and hardware acceptance
are pending.

Implemented:

- Ed25519 credentials alongside ES256/P-256, including resident and sealed
  non-discoverable credentials, COSE encoding and message signing.
- PIN protocols 1 and 2, legacy `getPinToken`, scoped tokens, RP binding,
  credential management and hmac-secret support.
- Accept matching RP-scoped credential-management tokens for credential
  enumeration and its continuations; global inventory still requires unscoped
  tokens. Native libfido2 checks pass for P-256 and Ed25519.
- Product name **Key**, manufacturer **Tunnlix**.
- Existing P-256 credential and counter compatibility; shared capacity remains
  32 resident credentials.

Required before stable release:

- [ ] **Mandatory:** verify iPhone Safari registration, authentication and
  authentication after reconnect.
- [ ] Verify OpenSSH `ed25519-sk` enrollment and authentication on hardware.
- [ ] Recheck existing P-256 credentials on macOS, Windows and Linux.
- [ ] Verify Windows OpenSSH resident recovery with the scoped-token fix.
- [ ] Investigate the reported Keyroost correct-PIN unlock timeout after SSH
  enrollment. Test with stored SSH credentials; an empty factory-reset device
  can hide the trigger. This timeout has not been confirmed resolved.
- [ ] Measure target key-generation/restoration/signing latency and runtime
  stack headroom, including operation at full resident capacity.

The previous candidate passed native protocol/storage and sanitizer checks.
Its RP2350 build reserves 208,752 bytes of flash, 225,368 bytes of main RAM and
16 KiB of stack. These figures are not runtime high-water measurements.

See [building and upgrade notes](building.md) and the
[security scope](../.github/SECURITY.md). FIDO certification is not claimed.
