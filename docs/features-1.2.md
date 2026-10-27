# 1.2 development features

These additions are implemented in source and require hardware acceptance before
release. They do not change the 32-discoverable-credential quota.
Credential-management output of largeBlobKey is still pending; client garbage-
collection compatibility is not yet qualified.

## PIN policy

`authenticatorConfig` supports `toggleAlwaysUv` and `setMinPINLength`. A configured
PIN requires a token with the `acfg` permission, using PIN protocol 1 or 2 and
the standard command MAC. Before a PIN is set, CTAP permits initial configuration
without a token. Always-UV can also be disabled without a token when no PIN is set.

The minimum defaults to four Unicode code points and can only increase, up to
63. PINs still fit the existing limit of 63 UTF-8 bytes. Raising the minimum
above the current PIN length, or explicitly requesting a change, requires a new
PIN before further PIN tokens are issued. Existing tokens are retired on policy
changes. Always-UV applies to registration and authentication, including requests
that otherwise omit verification. Factory reset restores the defaults.

The minimum-length extension discloses no policy to relying parties: there is
no configured RP disclosure list and `maxRPIDsForSetMinPINLength` is zero.
Enterprise attestation and PIN complexity policies are not added.

## Blob storage

`credBlob` stores up to **32 bytes with a resident credential**. Its signed output
indicates whether registration stored the requested blob. Authentication can
return that data under the credential's existing protection policy. Oversized
or non-resident registration requests return `credBlob: false`; authentication
without a stored blob returns an empty byte string. Replacement/deletion follows
the credential's normal atomic storage operations. Metadata is loaded on demand.

`largeBlobKey` and `authenticatorLargeBlobs` provide a **4 KiB shared serialized
array**, including its checksum and protocol overhead. This is shared by all
credentials. The client manages encryption and garbage collection. A credential's
large-blob key is derived inside the crypto provider, with a separate domain
from either hmac-secret branch. It is not derived from public credential handles.
Only resident registrations requesting this feature enable its key output.

Writes use bounded fragments, sequential offsets and `lbw` token permissions
when a PIN is configured or always-UV is enabled. The default 1024-byte CTAP
message size permits fragments up to 960 bytes. A 4096-byte staging buffer holds
one active replacement array; it does not load stored credentials into RAM.
Pending writes are cleared on interruption, disconnect, channel resynchronization
or a 30-second inactivity timeout. Reads return only committed data.

Four rotating 8 KiB banks protect the previous committed array from interrupted
writes. The final header page commits a replacement after data verification.
Bank headers are bound to the credential store's random identity and reset
generation, so reset and factory provisioning expose the standard empty array.
Old client-encrypted bytes can remain physically present until bank reuse; this
does not add physical flash-read/replay protection to the security claims.

## Flash boundaries and upgrades

| Region | Device flash offsets | Size |
| --- | --- | --- |
| Firmware | `0x000000`–`0x177fff` | 1504 KiB |
| Blob banks | `0x178000`–`0x17ffff` | 32 KiB |
| Existing credential store | `0x180000`–`0x1fffff` | 512 KiB |

The linker and physical flash guards enforce these separate regions. Blob banks
and credentials are not included as output sections in the firmware image.
Future PC flashing software must reject application-image writes at or above
`0x178000`; preserving only the credential partition is insufficient. ROM
BOOTSEL itself does not enforce this application-specific boundary.

Existing 1.1 credentials and PIN records remain readable. New blob metadata and
non-default PIN policies are not readable by older firmware. Do not downgrade
a device using these features without an intentional reset/re-enrollment or a
firmware version that understands the newer records.

The target ELF link check uses 218,312 bytes of firmware flash and 231,816 bytes
of main RAM, with a separate 16 KiB stack reservation. That leaves 1,321,784 bytes
of application flash and 276,088 bytes of main RAM, besides the reserved blob
and credential regions. Compared with 1.1, the additions use 9,560 bytes more
firmware flash and 6,448 bytes more main RAM. These are link-time figures, not
runtime stack or latency measurements. A release UF2 has not been generated.

See [status indications](indicators.md) and [model identity](device-identity.md).
Protocol definitions follow the
[FIDO CTAP specification](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html).
