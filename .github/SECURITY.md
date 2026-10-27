# Security scope and reporting

FIDO certification and complete conformance have not been established. Native
regression checks do not establish hardware timing, endurance or interrupted-write
qualification. See the source and build instructions for supported features.

Explicit factory setup installs the temporary PIN `000000` and requires changing
it before PIN-based authorization. The factory minimum is six Unicode characters.
CTAP reset clears the PIN and restores that minimum; it does not reinstall a
shared PIN. Existing PINs and configured policies are not changed by an update.

The onboard configuration does not claim resistance to physical theft, flash
reads, executable replacement or restoration of old flash snapshots. Its
storage root is readable from flash and signed boot is not enforced.

Hardware entropy remains unqualified. Sustained use has triggered hardware
health alarms; the firmware stops service until restart rather than returning
output after an alarm. This does not establish that earlier keys are predictable.
The store also claims no enforced storage-encryption lifetime; the encoded
attempt field is not a durable usage reservation mechanism.

USB VID/PID 1209:0001 is a shared private-test identity. Obtain an allocated
identity before distributing devices. The configured model AAGUID is documented
in the device identity notes and does not imply certification. Attestation `none`
may expose an all-zero AAGUID by design.

For a suspected vulnerability, use GitHub's Security → Report a vulnerability
if enabled. Otherwise open an issue asking for a private reporting channel,
without including exploit details, PINs, keys or device dumps. No dedicated
contact address or response-time guarantee has been established.
