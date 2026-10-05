# CTAPHID report parser

A platform-independent C parser for individual 64-byte CTAPHID reports. The
project currently contains the parser and a host example that prints decoded
fields. It uses no heap allocation, platform APIs, or persistent parser state.

## Layout

```text
include/protocol/ctaphid_parser.h  Public parser API and decoded packet
src/protocol/ctaphid_parser.c      Initial and continuation report decoding
examples/host/main.c              Host sample and terminal output
```

## Build and run on the host

From the project root:

```sh
gcc -std=c17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -g -O0 \
    -Iinclude examples/host/main.c src/protocol/ctaphid_parser.c -o main
./main
```

In VS Code, use **Ctrl+Shift+B** to build or **F5** to build and debug.

## Parser API

Include `protocol/ctaphid_parser.h` and call:

```c
CtaphidParsedPacket parsed_packet;
CtaphidParseResult result = ctaphid_parse_packet(
    report, report_length, &parsed_packet);
```

The parser requires exactly 64 input bytes and rejects initial message lengths
above 7609. Errors distinguish null arguments, invalid report sizes, and invalid
message lengths. Input and output buffers are caller-owned and must not overlap.
On failure, output is unchanged. On success, all output fields are initialized
and unused payload storage is zeroed.

`command` contains the decoded seven-bit command, such as INIT `0x06`.
`fragment_length` is the number of copied bytes: up to 57 for an initial report
and 59 for a continuation report. Continuation bytes may include padding; a
single report does not contain enough information to identify the useful length
or verify message-level sequence order. The parser does not execute commands.

The intended hardware is Pico RP2350. Development and compilation currently
remain on the host; no Pico SDK or target-specific code is included.
