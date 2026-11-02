# Tunnlix Key

**Open-source security for your passkeys.**

Tunnlix Key is a USB security-key project that puts you in control. Use a physical
key, a PIN and a button press to register passkeys and sign in. Inspect the code,
build your own key, or adapt the firmware to your hardware.

The project aims to keep pace with the latest FIDO standards and bring useful
new authentication features to an open, owner-controlled key. Its portable C core
keeps protocol logic separate from hardware providers, providing a foundation for
ports to other boards.

**Self-validated using FIDO Alliance conformance tools.**

[Build your key](docs/building.md) · [Security overview](.github/SECURITY.md) ·
[MIT license](LICENSE)

## Features

✅ Available · ❌ Unavailable · 🕒 Planned

| Feature | Status | Details |
| --- | :---: | --- |
| USB FIDO2 authentication | ✅ | Create passkeys and authenticate through supported FIDO clients. |
| ES256 and Ed25519 | ✅ | Supported for stored and non-discoverable credentials. |
| Discoverable passkeys | ✅ | 32 shared storage slots. |
| Sealed non-discoverable credentials | ✅ | Do not consume discoverable-passkey slots. |
| PIN verification | ✅ | Set/change PIN, retry limits and blocking protection. |
| PIN length and forced change | ✅ | Configurable minimum; maximum UTF-8 PIN size is 63 bytes. |
| Credential management | ✅ | Enumerate, update user information and delete passkeys. |
| Persistent read-only inventory (`pcmr`) | ✅ | Separate authorization for listing credentials; no signing or changes. |
| LED identification (WINK) and channel lock | ✅ | LOCK supports up to ten seconds. |
| Long-touch reset | ✅ | Optional five-second hold; enabled through authenticated configuration. |
| `hmac-secret` / `hmac-secret-mc` | ✅ | Supported for both credential types and PIN protocols. |
| `credProtect`, `credBlob`, `minPinLength` | ✅ | Credential protection, small blobs and authorized PIN-length reporting. |
| `largeBlobKey` and LargeBlobs storage | ✅ | 4 KiB encrypted blob array, managed by the client. |
| `uvm` and `thirdPartyPayment` | ✅ | Reports verification methods used and stores the payment attribute. |
| Encrypted GetInfo identifiers | ✅ | Fresh IVs; reset replaces the device identifier and credential-store state. |
| Enterprise attestation | ✅ | Optional provisioned identity; disabled by default. Not needed for ordinary passkeys. |
| Ordinary batch attestation | ✅ | Optional separate identity. Default builds use packed self-attestation. |
| PIN complexity policy | ✅ | Blocks common and repeated PINs by default; numeric PINs allowed. Custom builds can exclude it. |
| NFC, Bluetooth, display and biometrics | ❌ | Require hardware absent from the current reference board. |
| Alternative CTAP `largeBlob` extension | ❌ | Uses the mutually exclusive `largeBlobKey` / LargeBlobs approach instead. |

See the [enterprise-attestation guide](docs/enterprise-attestation.md) for identity
configuration and the [security status](.github/SECURITY.md) for physical-access,
storage and signed-boot assumptions.

## Tested on real hardware

The USB attestation lab configuration completed a full FIDO Alliance
conformance-tool run successfully.

The run covers passkey creation and authentication, PIN verification, credential
management, supported extensions and enterprise attestation. Separate hardware
checks verify USB channel locking, which the tool skips because of its legacy
feature-detection gate. Cases requiring unavailable hardware or other unmet
prerequisites remain skipped.

These results describe the tested lab configuration. See the
[test configuration and scope](docs/building.md#conformance-test-configuration)
for build settings and differences from the default build. Lab metadata, raw
reports, private keys and signed lab images remain outside the public source tree.

Native regression and sanitizer checks also cover reset behavior, cryptography
and recovery from interrupted storage writes. FIDO certification has not been obtained.

## Bring your own hardware

The protocol core is designed to be portable. Contributions that add hardware
providers, support more boards, or improve existing ports are welcome. Share
what you are building and help make Tunnlix Key available on more hardware.

The current firmware targets Raspberry Pi's RP2350 microcontroller. The reference
build uses a Seeed Studio XIAO RP2350 board with a user-presence button connected
between D0 (GPIO26) and GND. Seeed publishes
[hardware resources, including schematics and editable PCB design files](https://wiki.seeedstudio.com/xiao_rp2350_arduino/#assets--resources).
See [building and setup](docs/building.md) to build this target.

The firmware is MIT-licensed. See the
[dependency notices](docs/third-party-notices.md) for third-party licenses.
