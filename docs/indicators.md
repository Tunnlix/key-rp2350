# Status LED

The onboard user LED indicates the current state. The power LED is separate.

| Pattern | Meaning |
| --- | --- |
| One brief flash every three seconds | Ready |
| Even blinking, on/off every 200 ms | Authentication, registration, selection or reset needs a fresh press |
| Two short flashes followed by a pause | A PC firmware-update request needs a fresh press |
| Rapid flicker | Fault; normal credential operations are unavailable |

Release the button before starting a request. Press and release when prompted.
Holding it in advance does not approve a request. Cancelling a request returns
the LED to the ready pattern. No processing or success animation delays USB.
