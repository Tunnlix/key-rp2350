# Security status and limitations

This document describes the current security assumptions, validation scope and
reporting process for Tunnlix Key. See the [build instructions](../docs/building.md)
and source code for supported features and configuration details.

## Validation status

Tunnlix Key v1.5.0 is a FIDO2/CTAP2.3-compliant USB authenticator, self-validated
using FIDO Alliance conformance tools. A Tools 1.9.3 / CTAP2.3 run on the Seeed
XIAO RP2350 completed on October 29, 2026 with 231 passes and zero failures.
Unmarked cases were reviewed against advertised capabilities and conditional
prerequisites; no unexplained mandatory supported-feature omission was found.
FIDO certification has not been obtained.

Native regression and sanitizer checks cover policy, cryptography and storage
recovery, including simulated interrupted writes. Hardware validation also
includes 400 PIN-token requests, 51 functional checks, 16 credential cleanup
checks and 24 minimum-PIN-length checks. This establishes the recorded protocol
test results; hardware endurance, environmental behavior and resistance to
physical attacks require separate qualification.

## PIN setup

Explicit factory setup installs the temporary PIN `000000` and requires changing
it before PIN-based authorization. The factory minimum is six Unicode characters.
CTAP reset clears the PIN and restores that minimum; it does not reinstall a
shared PIN. Existing PINs and configured policies are not changed by an update.

## Physical access and signed boot

The current onboard configuration assumes the owner maintains physical control
of the device. Protection against physical theft, direct flash reads, executable
replacement and restoration of old flash snapshots is outside its validated
security scope. The storage root is readable from flash.

Owner-signed boot is available on explicitly provisioned devices; default builds
do not provision OTP. Signed boot controls which firmware can execute. Direct
storage reads and replay of credential-store snapshots remain outside that
protection.

## Firmware updates and storage

A/B confirmation covers read-only startup and USB enumeration, not every
possible runtime failure. Future storage-format changes need a separate
compatibility strategy: both firmware slots share credential and blob storage.

Version 1.5.0 adds an extended PIN record when a minimum-PIN-length RP list is
configured. Existing empty-policy records remain readable. Older firmware cannot
read the extended record; downgrade after configuring that policy is unsupported.

Storage-encryption lifetime limits are not enforced. The encoded attempt field
does not provide a durable reservation of storage-encryption usage.

## Randomness validation

Hardware random-source health checks remain enabled. Native fault-injection
checks cover bounded collection recovery and terminal failure behavior; the
hardware token stress run passed. Statistical and environmental entropy
qualification is separate from protocol conformance testing.

## USB identity and attestation

USB VID/PID 1209:0001 is a shared private-test identity. Obtain an allocated
identity before distributing devices. The configured model AAGUID is documented
in the device identity notes and does not imply certification. Attestation `none`
may expose an all-zero AAGUID by design.

## Reporting a vulnerability

For a suspected vulnerability, use GitHub's Security → Report a vulnerability
if enabled. Otherwise open an issue asking for a private reporting channel,
without including exploit details, PINs, keys or device dumps. Reporting currently
uses these GitHub channels; there is no dedicated security contact address or
guaranteed response time.
