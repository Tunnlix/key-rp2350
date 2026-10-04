# CTAPHID learning project

`main.c` passes a sample 64-byte CTAPHID packet to
`ctaphid_process_packet()` in `interfaces/ctaphid.c`. The current implementation
prints the channel ID, packet type, and command byte for initial packets.
It does not yet reassemble messages, generate responses, or communicate over USB.

Install the compiler on Fedora:

```sh
sudo dnf install -y gcc make
```

Open this folder in VS Code. Press **Ctrl+Shift+B** to build or **F5** to build and debug. The Microsoft C/C++ extension provides IntelliSense and debugging.

To build and run from a terminal:

```sh
gcc -std=c17 -Wall -Wextra -Wpedantic -g -O0 main.c interfaces/ctaphid.c -o main
./main
```

Use `main.c` for sample packets and calls, `interfaces/ctaphid.h` for public
declarations, and `interfaces/ctaphid.c` for protocol implementation. Both C
files must be compiled and linked together; including the header only supplies
declarations.

Next steps:

- Decode the initial packet payload length from bytes 5 and 6, and print the
  command name using the existing `ctaphid_command_name()` helper.
- Decode continuation sequence numbers and reassemble payloads across packets.
- Implement INIT and PING responses, channel state, and invalid-packet handling.
- Add USB HID transport once packet processing works with samples.

For a sample INIT request that allocates a channel, use the broadcast channel
ID `0xFFFFFFFF` and an 8-byte nonce. The current sample uses `0x3A7F21C4`, which
would represent an existing channel.

Reference: [FIDO CTAP specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid-init).
