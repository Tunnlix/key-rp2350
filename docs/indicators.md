# Status LEDs

The XIAO RP2350 uses its RGB LED for status. The separate user LED is a
single-color fallback and also flashes on faults. The charging LED is independent.

| RGB indication | Meaning |
| --- | --- |
| Dim steady amber | Starting |
| Dim blue flash every three seconds | Ready |
| Blue blinking, on/off every 200 ms | A fresh press is needed |
| Brief green | A touch-confirmed operation completed locally and its reply was sent |
| Amber double flash followed by a pause | A PC firmware-update request needs a fresh press |
| Amber slow flashes while holding at startup, then fast flashes | Release to enter recovery |
| Rapid red flashing | Fault; normal credential operations are unavailable |

Release the button before starting a request. Press and release when prompted.
Holding it in advance does not approve a request. Cancelling a request returns
the LED to the ready pattern. Green does not confirm acceptance by a website.
The fallback LED uses the same timings without colors. LED indications do not
delay USB, cryptography or storage. The RGB LED powers off before ROM update mode.
