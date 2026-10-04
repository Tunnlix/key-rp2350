# CTAPHID learning project

This plain-C project decodes individual 64-byte CTAPHID reports. The host example
passes a sample initial packet to the parser and prints the decoded fields and
payload. The project does not yet reassemble messages, generate responses, or
communicate over USB.

## Layout

```text
include/protocol/ctaphid_parser.h  Public parser API and packet representation
src/protocol/ctaphid_parser.c      Platform-independent report decoding
examples/host/main.c              Desktop sample packet and terminal output
tasks/01.md                       Recommended follow-up work
```

The protocol source depends only on its public header and standard C headers.
An embedded application can compile `src/protocol/ctaphid_parser.c`, add
`include/` to its header search path, and provide its own caller. The host
example is compiled separately from the protocol source and linked with it.
No host example or terminal I/O is required by the parser.

## Build and run the host example

Install the compiler on Fedora:

```sh
sudo dnf install -y gcc
```

From the project root:

```sh
gcc -std=c17 -Wall -Wextra -Wpedantic -g -O0 -Iinclude \
    examples/host/main.c src/protocol/ctaphid_parser.c -o main
./main
```

In VS Code, press **Ctrl+Shift+B** to build or **F5** to build and debug.
The Microsoft C/C++ extension provides IntelliSense and debugging. The example
executable remains at `main` in the project root and is ignored by Git.

## Parser contract

Include `protocol/ctaphid_parser.h` and call `ctaphid_parse_packet()` with a
complete report and caller-owned `CtaphidParsedPacket` storage. The report is
not modified, and no memory is allocated. The current API assumes the input
contains `CTAPHID_REPORT_SIZE` readable bytes; it does not accept an input length.

The refactor preserves the existing decoding behavior, including the marker
bit in initial command bytes, full payload capacity for continuation packets,
untouched bytes beyond the decoded payload, and partially modified output on
some failures. See the public header for the full contract and `tasks/01.md`
for proposed follow-up work.
