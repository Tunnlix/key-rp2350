# Firmware roadmap

## 1.1.0

Current candidate: **1.1.0-rc.1**. Stable release acceptance is pending.

Implemented:

- Ed25519 credentials alongside ES256/P-256, including resident and sealed
  non-discoverable credentials, COSE encoding and message signing.
- PIN protocols 1 and 2, legacy `getPinToken`, scoped tokens, RP binding,
  credential management and hmac-secret support.
- Product name **Key**, manufacturer **Tunnlix**.
- Existing P-256 credential and counter compatibility; shared capacity remains
  32 resident credentials.

Required before stable release:

- [ ] **Mandatory:** verify iPhone Safari registration, authentication and
  authentication after reconnect.
- [ ] Verify OpenSSH `ed25519-sk` enrollment and authentication on hardware.
- [ ] Recheck existing P-256 credentials on macOS, Windows and Linux.
- [ ] Measure target key-generation/restoration/signing latency and runtime
  stack headroom, including operation at full resident capacity.

The candidate has passed native protocol/storage checks and sanitizer checks.
The RP2350 build reserves 208,752 bytes of flash, 225,368 bytes of main RAM and
16 KiB of stack. These figures are not runtime high-water measurements.

See [building and upgrade notes](building.md) and the
[security scope](../.github/SECURITY.md). FIDO certification is not claimed.
