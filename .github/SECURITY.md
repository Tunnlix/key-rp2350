# Security status and limitations

This document describes the current security assumptions, validation scope and
reporting process for Tunnlix Key. See the [build instructions](../docs/building.md)
and source code for supported features and configuration details.

## Validation status

FIDO certification and full protocol conformance have not yet been established.
Native regression checks cover software behavior; hardware timing, endurance and
behavior during interrupted writes require separate qualification.

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

Storage-encryption lifetime limits are not enforced. The encoded attempt field
does not provide a durable reservation of storage-encryption usage.

## Randomness validation

Hardware entropy qualification is still pending. Hardware health alarms have
been observed during sustained use. When an alarm occurs, the firmware stops
service until restart and does not return further random output. These
observations alone do not establish that previously generated keys are
predictable.

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
