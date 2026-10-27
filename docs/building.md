# Building and setup

## Portable core

Requires CMake 3.21+, Ninja and a native C17 compiler:

```sh
cmake --preset core-only
cmake --build --preset core-only
```

`src/` and `include/` contain the portable library. `firmware/rp2350/` contains
the USB application, GPIO, entropy, cryptography and persistent storage.

## XIAO RP2350 firmware

Use Pico SDK 2.3.1 with its required submodules and Arm GNU Toolchain 15.2.Rel1.
Set `PICO_SDK_PATH` and `PICO_TOOLCHAIN_PATH` to their installation directories:

```sh
cmake -S firmware/rp2350 --preset rp2350-release
cmake --build build/rp2350 --target rp2350_application
```

The output is `build/rp2350/rp2350_application.uf2`. Configuration downloads
Mbed TLS 3.6.7 and verifies its pinned SHA-256; a reviewed offline source tree
can be selected with `RP2350_MBEDTLS_PATH`. The `rp2350-lto` preset is an
optional mixed-LTO build. See [dependency pins and licenses](third-party-notices.md).

The default build contains only the authenticator. It reserves a separate 32 KiB
blob partition and preserves the 512 KiB credential partition and never automatically formats blank or corrupt storage.
Wire a normally open button between D0 (GPIO26) and GND. The firmware enables
the internal pull-up; no voltage source is needed on the button.

## Explicit first-time provisioning

The optional tool under `tools/provisioning/` initializes a blank board or
erases an existing store. **It destroys all stored credentials and the PIN.**
It uses the existing guarded erase/provisioning flow and requires a fresh
physical button press before destructive IO. It creates no sample credentials.
Factory setup installs the temporary PIN
`000000`, with a six-character minimum and a mandatory PIN change before
PIN-based authorization. Change it with a compatible FIDO manager. Standard
CTAP reset instead clears the PIN and restores the six-character minimum.
The tool is separate from normal firmware and is not built by default.

```sh
cmake -S firmware/rp2350 --preset rp2350-release -DRP2350_BUILD_PROVISIONING=ON
cmake --build build/rp2350 --target rp2350_factory_provision
```

With the board in ROM BOOTSEL mode, load the normal application without
executing it, then run the RAM-only setup tool:

```sh
picotool load -v build/rp2350/rp2350_application.uf2
picotool load -v -x build/rp2350/provisioning/rp2350_factory_provision.uf2
```

Briefly press and release D0 when requested. Success returns to ROM. Verify
the normal image and reboot it:

```sh
picotool verify build/rp2350/rp2350_application.uf2
picotool reboot
```

Setup uses real board entropy and can stop on the documented entropy fault.
Failure never automatically retries provisioning. The separated provisioning
tool is build-checked; it has not been physically requalified after extraction
from the earlier development utility.

## Firmware update entry

With USB disconnected, hold D0, connect USB, keep holding for five seconds,
then release when the fast indication begins. This enters ROM update mode.
The firmware also supports a PC-requested vendor command over FIDO HID,
confirmed by a fresh press within 30 seconds. Its desktop client is separate.

The USB product and update-information name are **Key**, with manufacturer
**Tunnlix**. Firmware identity comes from `include/ctap_device_version.h`;
numeric USB/CTAP fields cannot distinguish development builds from stable ones.
Building source does not imply release or completed hardware acceptance.

## Features and storage

ES256/P-256 and Ed25519 work with PIN protocols 1 and 2. Legacy `getPinToken`
remains available for older clients. OpenSSH uses these through `ecdsa-sk` and
`ed25519-sk`. CTAP protocol advertising does not claim FIDO certification.

The device stores 32 discoverable credentials. Sealed non-discoverable credential
IDs are held by clients and do not consume those slots. Credential management
supports listing, deletion and editable user names. PIN policy supports always-UV,
increasing the minimum length, and requiring a PIN change. The factory minimum
is six Unicode characters; existing stored policies remain unchanged by updates.

Resident credentials can carry a 32-byte `credBlob`. Large blobs share a 4 KiB
client-encrypted array, backed by four rotating banks. Credential-management
output of `largeBlobKey` is incomplete; full garbage-collection interoperability
is not yet established.

| Region | Flash offsets | Size |
| --- | --- | --- |
| Firmware | `0x000000`–`0x177fff` | 1504 KiB |
| Blob banks | `0x178000`–`0x17ffff` | 32 KiB |
| Credential store | `0x180000`–`0x1fffff` | 512 KiB |

Application flashing must preserve everything at or above `0x178000`, including
both blob and credential storage. Firmware images exclude those regions. ROM
BOOTSEL does not enforce this application-specific boundary.

Downgrading to firmware that cannot decode stored algorithms, blob metadata or
PIN policies can prevent recovery. Use compatible firmware or intentionally
reset and re-enroll. Product renaming does not change storage derivation labels.

See [status indications](indicators.md), [device identity](device-identity.md)
and [security limitations](../.github/SECURITY.md).
