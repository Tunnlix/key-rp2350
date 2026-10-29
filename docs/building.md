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

The default build contains only the authenticator. The 2 MiB flash layout uses
8 KiB of partition metadata, two 748 KiB firmware slots, a 32 KiB blob partition
and a 512 KiB credential partition. It never automatically formats blank or
corrupt storage. The firmware requires this partition table; it is not a
drop-in single-image replacement for the previous flash layout.
Wire a normally open button between D0 (GPIO26) and GND. The firmware enables
the internal pull-up; no voltage source is needed on the button.

## Signing and RAM recovery

Build the optional recovery probe alongside the application:

```sh
cmake -S firmware/rp2350 --preset rp2350-release -DRP2350_BUILD_RECOVERY=ON
cmake --build build/rp2350 --target rp2350_application rp2350_recovery rp2350_layout_recovery
python3 tools/sign-firmware.py --ab \
  --layout-recovery build/rp2350/recovery/rp2350_layout_recovery.elf \
  --picotool /path/to/picotool \
  /private/path/firmware-signing.pem /private/path/firmware-signing-public.pem \
  build/rp2350/rp2350_application.elf \
  build/rp2350/recovery/rp2350_recovery.elf build/signed
```

The signing helper requires Python 3, OpenSSL, picotool 2.3.1 and Linux
`/dev/shm`. OpenSSL prompts locally for an encrypted key's passphrase; the
unlocked copy exists temporarily in a private RAM-backed directory. Keep the
encrypted original and its backup outside the repository. The output directory
must be new. The helper checks the signing key, load bounds and ELF/UF2 signatures;
it never accesses the board or programs OTP. A signed image alone does not enable
secure boot.

The recovery probe is a separate RAM-only image. It flashes amber for three
seconds, then returns to ROM PICOBOOT mode without writing flash or OTP. Its
signed form is intended to qualify RAM recovery before enabling secure boot.

On a device explicitly provisioned for secure boot, both normal firmware and
RAM tools must be signed with an enrolled key. Debug and OTP permissions are
device-specific permanent settings, not properties of a normal firmware build.
Keep signed recovery artifacts and signing-key backups available before locking
a device. An empty reserved key slot may require owner-signed Secure firmware
to enroll later when ROM writes to the boot-key pages have been disabled.

## Initial A/B installation and updates

This layout targets the XIAO RP2350 A4 with its qualified 2 MiB flash. Do not add
the old RP2350-E10 absolute UF2 helper block: it targets storage outside the
firmware slots. The signing helper checks every UF2 payload address and family.

Initial conversion changes boot metadata. Keep a verified full-flash backup and
known-good signed recovery artifacts. In ROM BOOTSEL, stage and verify slot B
before replacing the old layout, then reload the table and trial-boot B:

```sh
picotool load -v build/signed/Key-initial-slot-B.bin -o 0x100bd000
picotool load -v build/signed/Key-partition-table.signed.uf2
picotool reboot -u
picotool load -u -v -x -p 1 build/signed/Key.signed.uf2
```

Run this conversion only once, on the intended board. It preserves the storage
regions. After the table is installed, its metadata and storage regions are
read-only through the ROM USB loader; application slots remain writable.
For later updates enter ROM using D0, then use only:

```sh
picotool load -v -x build/signed/Key.signed.uf2
```

Picotool routes the image to the inactive slot and requests a flash-update boot.
The ROM trial watchdog runs for about 16.7 seconds. Firmware confirms the image
only after read-only storage/crypto startup, stack checks and USB enumeration;
it does not execute CTAP requests or permit storage writes before confirmation.
A failed trial leaves the previous confirmed image available for normal boot.
USB must be connected to an awake host for trial confirmation.

ROM confirmation changes the image's mutable TBYB flag and can erase the old
slot header when needed for version selection. Verify the incoming file with
`load -v` before execution; a byte comparison afterward against that original
file is not expected to match. A/B protects unconfirmed startup, not faults
discovered after confirmation or incompatible future storage-format migrations.
Initial conversion and physical rollback qualification must be checked
separately from a successful build. These commands do not program OTP.

For boot-layout repair, ROM can execute the signed RAM-only layout-reset tool:

```sh
picotool load -v -x build/signed/Key-layout-recovery.signed.uf2
```

Approve with a fresh three-second D0 hold and release. This erases **only the
first 8 KiB of flash**, removing boot metadata, then returns to ROM so the table
can be reinstalled. It leaves both A/B slots and stored credentials untouched.
It does not make a broken firmware image bootable or recover a lost signing key.
On the older single-image layout it also removes the old application's header;
restore a known-good image through ROM afterward. This is separate from the
read-only RAM recovery probe and is not part of ordinary updates.

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

With the board in ROM BOOTSEL mode, run the RAM-only setup tool before the
initial A/B installation. A secure-boot device requires an owner-signed setup
image as well:

```sh
picotool load -v -x build/rp2350/provisioning/rp2350_factory_provision.uf2
```

Briefly press and release D0 when requested. Success returns to ROM. Continue
with the initial A/B installation above to load and confirm normal firmware.

Setup uses real board entropy and can stop on the documented entropy fault.
Failure never automatically retries provisioning. The separated provisioning
tool is build-checked; it has not been physically requalified after extraction
from the earlier development utility.

## Firmware update entry

With USB disconnected, hold D0, connect USB, keep holding for five seconds,
then release when the fast indication begins. This enters ROM update mode.
The firmware also supports a PC-requested vendor command over FIDO HID,
confirmed by a fresh three-second hold followed by release within 30 seconds.
The amber indication becomes fast when it is time to release. A short login tap
does not approve an update. Protocol revision 2 is required for entry; revision 1
information queries remain supported. PC-requested entry exposes PICOBOOT only;
the physical power-on recovery gesture retains both ROM USB interfaces.
Power-on D0 recovery runs in the application: it cannot recover a signed image
that fails before its button handler. ROM can fall back to USB when no valid
image exists and USB boot remains enabled. A/B provides an independent ROM
fallback while the new image remains unconfirmed.

The USB product and update-information name are **Key**, with manufacturer
**Tunnlix**. Firmware identity comes from `include/ctap_device_version.h`;
numeric USB/CTAP fields cannot distinguish development builds from stable ones.
Building source does not imply release or completed hardware acceptance.

## Features and storage

ES256/P-256 and Ed25519 work with PIN protocols 1 and 2. Legacy `getPinToken`
remains available for older clients. OpenSSH uses these through `ecdsa-sk` and
`ed25519-sk`. Version 1.5.0 passed the FIDO Conformance Tools 1.9.3 / CTAP2.3
run with 231 passes and zero failures; see the [testing status](../README.md#conformance-testing).

The device stores 32 discoverable credentials. Sealed non-discoverable credential
IDs are held by clients and do not consume those slots. Credential management
supports listing, deletion and editable user names. PIN policy supports always-UV,
increasing the minimum length, and requiring a PIN change. The factory minimum
is six Unicode characters; existing stored policies remain unchanged by updates.
The signed `minPinLength` extension reports the current minimum only to
configured RP IDs. The authenticated RP policy supports up to four distinct IDs.

Resident credentials can carry a 32-byte `credBlob`. Large blobs share a 4 KiB
client-encrypted array, backed by four rotating banks. Credential management
returns `largeBlobKey` for credentials created with that support. The
large-blob-key, blob-array and credential-management groups passed the recorded
conformance run.

| Region | Flash offsets | Size |
| --- | --- | --- |
| Firmware | `0x000000`–`0x177fff` | 1504 KiB |
| Blob banks | `0x178000`–`0x17ffff` | 32 KiB |
| Credential store | `0x180000`–`0x1fffff` | 512 KiB |

Application flashing must preserve everything at or above `0x178000`, including
both blob and credential storage. Firmware images exclude those regions. ROM
BOOTSEL does not enforce this application-specific boundary.

Version 1.4 reads existing v1.3 credential stores without resetting them. New
writes use envelope v3: the encrypted body, MACs and digest are written and
read back before a separate page programs one commit bit. This distinguishes
an interrupted write from corruption of an acknowledged record, including
partial page programming. Root capsules and typed credential records retain
their previous encodings. Some frame sizes increase by one page.

After the first v1.4 storage write, v1.3 cannot read the mixed/new envelopes.
Keep compatible firmware available; do not downgrade a used v1.4 key to v1.3.
A/B trial startup validates storage read-only and makes no format change before
ROM confirmation, preserving pre-confirmation rollback to the stable image.

Version 1.5.0 retains the existing PIN encoding while no RP allowlist is stored.
Configuring an RP allowlist writes an extended PIN record. Older firmware rejects
that record, so downgrading after configuring the list is unsupported. Resetting
the list does not establish compatibility with older firmware journals.

Downgrading to firmware that cannot decode stored algorithms, blob metadata or
PIN policies can prevent recovery. Use compatible firmware or intentionally
reset and re-enroll. Product renaming does not change storage derivation labels.

See [status indications](indicators.md), [device identity](device-identity.md)
and [security limitations](../.github/SECURITY.md).
