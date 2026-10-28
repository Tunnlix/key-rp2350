# Key

Key is an open-source FIDO2/CTAP2 USB security key by Tunnlix for the Seeed XIAO
RP2350. It lets websites register passkeys and authenticate using a physical
device, a PIN and a button press.

The firmware supports ES256 and Ed25519, PIN protocols 1 and 2, credential
management, 32 stored discoverable passkeys and sealed non-discoverable credentials that do not use
those slots. An external button connects D0 (GPIO26) to GND.

The code is written in C17, with a portable protocol core and separate RP2350
hardware providers. FIDO certification is not claimed. Read the [security limitations](.github/SECURITY.md)
before using it for important accounts.

[Building and setup](docs/building.md) · [Dependency notices](docs/third-party-notices.md) · [MIT license](LICENSE)

## Hardware targets

The working reference hardware is a Seeed Studio XIAO RP2350 with an external
user-presence button connected between D0 (GPIO26) and GND. Seeed publishes
[hardware resources, including schematics and editable PCB design files](https://wiki.seeedstudio.com/xiao_rp2350_arduino/#assets--resources).

XIAO RP2350 support will remain available. A custom RP2350 board is planned as
another hardware target under the same Tunnlix Key project; it is not yet
available. Its editable schematics and PCB layout will be published under a
recognized open-source hardware license. The firmware remains MIT-licensed.
