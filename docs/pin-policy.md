# Tunnlix Key PIN policy

This page describes the PIN policy implemented by the expanded v1.5.1 firmware.
Its additional features are awaiting a new official conformance run.

The factory minimum is six Unicode code points. An administrator can increase
the minimum, up to the firmware's maximum of 63 code points. The UTF-8 encoding
must also fit within 63 bytes, so some non-ASCII PINs reach the byte limit sooner.
U+0000 is not accepted. PINs are case-sensitive.

## Optional complexity

Additional complexity is **off by default**. When an administrator enables it,
new PINs must contain all of the following:

- An uppercase ASCII letter: `A`–`Z`.
- A lowercase ASCII letter: `a`–`z`.
- An ASCII digit: `0`–`9`.

Other valid UTF-8 characters and symbols are allowed, but do not replace those
three required categories. The configured minimum and byte limit still apply.

Enabling complexity requires an existing PIN to be changed. The key stores a
verifier rather than the plaintext PIN, so it cannot inspect an existing PIN's
characters. Complexity stays enabled until an authenticator reset. Reset also
erases stored passkeys and clears the PIN; it restores the six-code-point minimum
and turns optional complexity off.

Administrators enable the rule through `authenticatorConfig` → `setMinPINLength`
with `pinComplexityPolicy=true`. A false or omitted value does not disable an
already enabled rule. Clients can read its current state through GetInfo.

## Help links and privacy

The firmware's optional `pinComplexityPolicyURL` points to this public page.
Client software may show the link; support for displaying it varies by client.
The key does not browse the page or send a PIN, passkey or device identifier to
GitHub. The URL is public information shared by the project.

The URL is informational. PIN rules are enforced locally by the firmware even
when the client is offline or cannot display the page.
