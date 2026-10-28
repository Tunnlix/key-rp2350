# Status LEDs

The XIAO RP2350 uses its RGB LED for status. The separate user LED is a
single-color fallback and also flashes on faults. The charging LED is independent.

| RGB indication | Meaning |
| --- | --- |
| Dim steady amber | Starting |
| Dim blue flash every three seconds | Ready |
| Blue blinking, on/off every 200 ms | A fresh press is needed |
| Brief green | A touch-confirmed operation completed locally and its reply was sent |
| Amber double flash followed by a pause | Hold a fresh press for three seconds to approve a PC firmware update |
| Fast amber flashes during an update request | Release to enter ROM update mode |
| Amber slow flashes while holding at startup, then fast flashes | Release to enter recovery |
| Groups of red flashes followed by a pause | Fault code below; normal credential operations are unavailable |

Release the button before starting a request. Press and release when prompted.
Holding it in advance does not approve a request. Cancelling a request returns
the LED to the ready pattern. Green does not confirm acceptance by a website.
The fallback LED uses the same timings without colors. LED indications do not
delay USB, cryptography or storage. The RGB LED powers off before ROM update mode.

Fault groups repeat after a pause: 1 = storage recovery/integrity, 2 = flash I/O,
3 = entropy health/timeout, 4 = cryptographic failure, 5 = stack limit,
6 = boot layout or update confirmation, 7 = USB transport. Count flashes in
one group. The fallback user LED repeats the same code. The first terminal
reason is retained in RAM until restart; no diagnostic flash writes or secret
data are recorded. A code identifies the failing subsystem, not an exact root
cause. Boot ROM failures before the application starts cannot display a code.
