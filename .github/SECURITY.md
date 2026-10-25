# Security scope and reporting

The current firmware is 1.0.0-rc.1, a release candidate. FIDO certification and
complete conformance have not been established. Basic browser registration,
PIN-backed login, reconnect, sleep/wake, presence and update entry have been
checked. Full workload resource margins and physical interrupted-write/Reset
qualification remain incomplete.

The onboard configuration does not claim resistance to physical theft, flash
reads, executable replacement or restoration of old flash snapshots. Its
storage root is readable from flash and signed boot is not enforced.

Hardware entropy remains unqualified. Sustained use has triggered hardware
health alarms; the firmware stops service until restart rather than returning
output after an alarm. This does not establish that earlier keys are predictable.
The store also claims no enforced storage-encryption lifetime; the encoded
attempt field is not a durable usage reservation mechanism.

USB VID/PID 1209:0001 is a shared private-test identity. Obtain an allocated
identity before distributing devices. The all-zero AAGUID is a development
identifier, not certification metadata.

For a suspected vulnerability, use GitHub's Security → Report a vulnerability
if enabled. Otherwise open an issue asking for a private reporting channel,
without including exploit details, PINs, keys or device dumps. No dedicated
contact address or response-time guarantee has been established.
