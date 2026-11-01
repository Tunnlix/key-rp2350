# Security

## Security model

Tunnlix Key enforces PIN retry limits, permission-scoped authorization and
physical consent for reset. Owner-signed boot is available on provisioned devices
to control which firmware can execute.

The current hardware assumes the owner keeps physical control of the key.
Credential storage is encrypted, but its storage root is readable from onboard
flash. Physical extraction and replay of old flash snapshots are outside the
validated protection; signed boot does not add physical protection to storage.

See [building and setup](../docs/building.md) for configuration and storage details,
and the [README](../README.md#tested-on-real-hardware) for validation results.

## Report a vulnerability

Use GitHub's **Security → Report a vulnerability** if available. Otherwise, open
an issue requesting a private reporting channel. Keep exploit details, PINs,
private keys and device dumps out of public issues.

When a private channel is available, include the affected revision, hardware
and steps to reproduce. There is no guaranteed response time.
