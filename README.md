# Key

Key is an open-source FIDO2/CTAP2 USB security key by Tunnlix for the Seeed XIAO
RP2350. It lets websites register passkeys and authenticate using a physical
device, a PIN and a button press.

**FIDO2/CTAP2.3-compliant USB authenticator, self-validated using FIDO Alliance
conformance tools.**

The firmware supports ES256 and Ed25519, PIN protocols 1 and 2, credential
management, 32 stored discoverable passkeys and sealed non-discoverable credentials that do not use
those slots. An external button connects D0 (GPIO26) to GND.

The code is written in C17, with a portable protocol core and separate RP2350
hardware providers. See
[Security status and limitations](.github/SECURITY.md) for the current security
assumptions, known limitations, and vulnerability reporting guidance.

[Building and setup](docs/building.md) · [Dependency notices](docs/third-party-notices.md) · [MIT license](LICENSE)

## Conformance testing

Version **1.5.0** completed a FIDO Conformance Tools **1.9.3 / CTAP2.3** run on
the XIAO RP2350 with **231 passes and zero failures** on October 29, 2026.
The unmarked cases were reviewed against the supported USB feature set and
their conditional prerequisites; no unexplained mandatory supported-feature
omission was identified. NFC, Bluetooth, display and biometric features are
not required for this USB-only hardware target.

Native regression and sanitizer checks, 400 hardware PIN-token requests,
51 functional hardware checks and 24 minimum-PIN-length checks also passed.
This is self-validated protocol conformance; FIDO certification has not been
obtained. See the [validation scope](.github/SECURITY.md#validation-status).

## Hardware targets

The working reference hardware is a Seeed Studio XIAO RP2350 with an external
user-presence button connected between D0 (GPIO26) and GND. Seeed publishes
[hardware resources, including schematics and editable PCB design files](https://wiki.seeedstudio.com/xiao_rp2350_arduino/#assets--resources).

XIAO RP2350 support will remain available. A custom RP2350 board is planned as
another hardware target under the same Tunnlix Key project; it is not yet
available. Its editable schematics and PCB layout will be published under a
recognized open-source hardware license. The firmware remains MIT-licensed.
