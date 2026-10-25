# TunnlixKey

TunnlixKey is an open-source FIDO2/CTAP2 USB security key for the Seeed XIAO
RP2350. It lets websites register passkeys and authenticate using a physical
device, a PIN and a button press.

The firmware supports ES256, PIN protocol 2, credential management, 32 stored
discoverable passkeys and sealed non-discoverable credentials that do not use
those slots. An external button connects D0 (GPIO26) to GND.

The code is written in C17, with a portable protocol core and separate RP2350
hardware providers. The current version is **1.0.0-rc.1**, a release candidate;
FIDO certification is not claimed. Read the [security limitations](.github/SECURITY.md)
before using it for important accounts.

[Building and setup](docs/building.md) · [Dependency notices](docs/third-party-notices.md)
· [MIT license](LICENSE)
