# Optional enterprise attestation

Normal users do not need enterprise attestation, an attestation certificate or a
CA to use Tunnlix Key for passkeys. Ordinary registration and login keep their
existing behavior. This feature is for controlled organizational deployments
that want to recognize particular authenticators.

Enterprise attestation is separate from FIDO product certification. An
organization decides which attestation issuers it trusts. Creating a lab CA or
passing tests does not make a product FIDO Certified.

## Default behavior

- Normal builds contain no enterprise identity and omit GetInfo's `ep` option.
- A build with a provisioned identity reports `ep=false` initially.
- Administrators enable it with `authenticatorConfig` subcommand 1. When a PIN is
  set, a valid PIN/UV token with configuration permission is required.
- Enablement survives reconnects. Factory reset disables it and erases passkeys;
  it does not replace the provisioned identity.
- Enablement is bound to the identity and routing policy. Replacing either makes
  the earlier enablement inactive until an administrator enables the new policy.
- A registration must explicitly request enterprise attestation. Ordinary
  registrations never receive its certificate, including after enablement.
- A sole `attestationFormatsPreference: ["none"]` suppresses enterprise
  attestation too: no certificate or `epAtt` is returned, and the AAGUID is zero.

Vendor-facilitated requests (value 1) are restricted to the immutable configured
RP list. A vendor-only identity treats request value 2 in the same way. An
identity explicitly configured for platform-managed use permits value 2 after
the managed platform has vetted the RP, as required by CTAP. Value 1 continues
to use the RP list. RP matching uses exact hashes, without suffix matching.

Eligible requests return packed ES256 attestation with an X.509 `x5c` chain and
`epAtt=true`, regardless of whether the new credential itself uses ES256 or
Ed25519. The attestation key is separate from passkey keys and firmware signing.

## Local test identity

The optional helper requires Python with `cryptography`. Use an isolated output
directory under the ignored build folder:

```sh
python3 tools/enterprise-identity.py create-test build/enterprise-lab/identity \
  --rp audit.invalid --rp example.com
```

This generates a clearly marked TEST ONLY CA, a separate ES256 attestation key,
a matching leaf certificate and an `identity.json` RP policy. Add
`--platform-managed` only for a lab that also needs that routing mode. The
private key files use owner-only permissions on POSIX systems.

To build the RP2350 lab variant, add these settings to the normal firmware build:

```text
-DCTAP_MESSAGE_CAPACITY=2048
-DRP2350_ENTERPRISE_IDENTITY_DIR=/absolute/path/to/build/enterprise-lab/identity
-DRP2350_ENTERPRISE_ALLOW_TEST_IDENTITY=ON
-DRP2350_ENTERPRISE_PYTHON=/absolute/path/to/python-with-cryptography
```

The larger message capacity accommodates certificate-bearing responses. The
build validates the key/certificate match, issuer signature and purpose, validity,
packed-attestation subject, model AAGUID, RP policy and certificate-size bound.
It rejects test identities unless the explicit test option is enabled.

The built-in identity exporter embeds its private attestation scalar into a
private per-identity image. Keep its generated header, ELF, UF2 and private PEM
files private; do not put this lab identity into public release artifacts. This
mode validates protocol behavior, not production resistance to key extraction.

## Organizational deployment

A real deployment needs its own attestation identity, organization-controlled
trust policy and provisioning process. The portable `AuthEnterpriseAttestation`
interface supports signing through an opaque provider; a distributable public
firmware image should use separately provisioned keys rather than embedding a
shared private identity. Production provisioning and physical protection require
separate validation. The current RP2350 physical-security limitations still apply.

The lab CA certificate may be used as the trust anchor in local test metadata.
It does not need to be installed for ordinary passkey use. Do not submit lab
metadata as a production identity or a certification claim.

## Validation scope

Native checks cover default-off behavior, authenticated and idempotent enablement,
RP restrictions, platform-managed routing, ordinary-registration privacy,
explicit `none` preference overriding enterprise attestation,
identity/policy changes, both PIN protocols and credential algorithms/types,
signing failure, interrupted policy writes, reboot and reset. Public registration
fixtures are independently verified using Python's X.509 and signature APIs.
The attestation lab configuration passed the full conformance run described in
[the test configuration](building.md#conformance-test-configuration). Production
provisioning and physical key protection were not assessed by that run.

## Official conformance lab fixtures

Tools 1.9.3's Enterprise Profile compares the registration leaf certificate with
its bundled `EPBatchCertificate` fixture for
`enterprisetest.certinfra.fidoalliance.org`. A generated local CA/key is suitable
for independent tests but does not match that fixed certificate comparison.
Use a separate private identity folder for the tool fixture, mark it
`test_identity: true`, retain explicit test-build opt-in, and add that exact RP
to its allowlist. Never distribute a firmware image containing that shared test
private key as a product identity. Do not change the tool's expected certificate.

The exporter recognizes the exact leaf/root DER fingerprint pair from that
release solely for lab use. It permits that pair's legacy absent KeyUsage and
AAGUID extensions and its secp256k1 issuer; private-key matching, issuer signature,
validity, leaf ES256 and packed subject checks still apply. Other identities
retain the stricter certificate profile. The bundled leaf expires on
2026-11-03 at 13:19:08 UTC; expired fixtures require updated official test material,
not disabling validation.

PIN complexity is not implemented. GetInfo omits its extension, policy flag and
URL. Standard minimum length and explicit forced-PIN-change controls remain
supported.

## Optional ordinary batch attestation

A build may separately configure an ordinary model/batch identity using
`RP2350_BATCH_IDENTITY_DIR`. With it, normal registrations and unauthorized-RP
enterprise requests use ordinary packed full attestation. Without it, normal
registrations retain packed self-attestation. Enterprise requests still need
administrator enablement and the configured routing permission; the ordinary
provider does not grant enterprise access.

The batch provider must use a different key and certificate from the enterprise
identity. The build compares certificate public keys and rejects reuse. The
portable binding also rejects sharing the same leaf certificate. Ordinary
responses omit `epAtt` and never return the enterprise certificate. An explicit
sole `none` preference suppresses both certificate paths. Signing failure fails
closed; no replacement certificate or unverified signature is returned.

For an isolated lab, generate a separate identity with:

```sh
python3 tools/enterprise-identity.py create-test build/ordinary-lab/identity --batch
```

Then add `-DRP2350_BATCH_IDENTITY_DIR=/absolute/path/to/build/ordinary-lab/identity`
and `-DRP2350_BATCH_ALLOW_TEST_IDENTITY=ON` to the private 2 KiB-message build.
These options default to unset/OFF. The identity uses the same validated input
file names as the enterprise folder, but has no enterprise routing policy.
Its signing callback and scalar are separate from enterprise and firmware signing.

A batch certificate is intended to be shared across the units of a model/batch.
A locally generated certificate installed on one test unit does not demonstrate
anonymity across a population. Do not distribute the lab image or its keys as a
production trust identity. Production key protection/provisioning remains outside
this lab's validation scope.
