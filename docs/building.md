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

The default build contains only the authenticator. It preserves the 512 KiB
credential partition and never automatically formats blank or corrupt storage.
Wire a normally open button between D0 (GPIO26) and GND. The firmware enables
the internal pull-up; no voltage source is needed on the button.

## Explicit first-time provisioning

The optional tool under `tools/provisioning/` initializes a blank board or
erases an existing store. **It destroys all stored credentials and the PIN.**
It uses the existing guarded erase/provisioning flow and requires a fresh
physical button press before destructive IO. It creates no sample credentials
or default PIN. It is separate from normal firmware and is not built by default.

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

Current numeric USB/INIT/GetInfo fields report 1.0.0. ELF/UF2 metadata includes
the `-rc.1` suffix; numeric fields cannot distinguish a candidate from stable.
Build and generated firmware files belong in ignored build directories.
