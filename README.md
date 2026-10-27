# Key

Key is an open-source FIDO2/CTAP2 USB security key by Tunnlix for the Seeed XIAO
RP2350. It lets websites register passkeys and authenticate using a physical
device, a PIN and a button press.

The firmware supports ES256 and Ed25519, PIN protocols 1 and 2, credential
management, 32 stored discoverable passkeys and sealed non-discoverable credentials that do not use
those slots. An external button connects D0 (GPIO26) to GND.

The code is written in C17, with a portable protocol core and separate RP2350
hardware providers. This branch is **1.2.0-dev**, with development additions
for PIN policies and blob storage. FIDO certification is not claimed. Read the [security limitations](.github/SECURITY.md)
before using it for important accounts.

[Building and setup](docs/building.md) · [Dependency notices](docs/third-party-notices.md)
· [1.2 features](docs/features-1.2.md) · [MIT license](LICENSE)
