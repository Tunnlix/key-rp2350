# AGENTS.md
I FORBID CREATING README!
## Project purpose

This project is a C implementation used to study, test, and progressively implement a protocol that will later be moved to an embedded system.

The current codebase may contain experimental host-side code, debug output, hardcoded test values, temporary fixtures, and other development-only helpers.

The long-term target is production-quality embedded C.

Protocol logic should therefore be designed so that it can later be moved into an embedded environment with minimal restructuring.

## Core principles

Code added to the protocol implementation must be:

- deterministic
- explicit
- portable
- testable
- security-conscious
- suitable for constrained embedded systems
- independent from the current desktop test harness where practical

Prefer simple and auditable code over clever abstractions.

Do not introduce unnecessary frameworks, dependencies, abstractions, or architectural layers.

## Scope discipline

Only work on what the task explicitly requests.

Do not proactively refactor, clean up, rename, optimize, redesign, or review unrelated code.

Do not search for unrelated issues unless they directly affect the requested implementation.

Do not expand the task because another file looks unfinished or contains temporary code.

For example:

- If asked to implement or review a parser, work on the parser and code directly required by it.
- Do not start reviewing `main.c` merely because it contains hardcoded packets, magic numbers, `printf()` calls, or temporary test logic.
- Do not replace temporary testing code unless the task specifically asks for it.
- Do not implement future protocol functionality unless requested.
- Do not add speculative features because they may be useful later.

If something outside the requested scope prevents the requested code from being correct, mention it clearly instead of silently expanding the task.

## Architecture

Keep protocol logic separated from platform-specific code.

Prefer a structure conceptually similar to:

```text
src/
    protocol/
        parser.c
        ...
include/
    protocol/
        parser.h
        ...
tests/
    ...
```

The exact structure may evolve as the project grows.

Protocol modules should not depend on:

- terminal output
- files
- operating-system APIs
- dynamic desktop-specific facilities
- application-level test code

Platform-specific behavior should remain outside the core protocol implementation.

Core protocol code should operate on explicit inputs and outputs.

## Embedded compatibility

Write protocol code with future embedded use in mind.

Prefer:

- fixed-width integer types such as `uint8_t`, `uint16_t`, and `uint32_t`
- explicit buffer lengths
- caller-owned buffers
- deterministic memory usage
- bounded loops
- explicit state
- small focused functions
- compile-time constants where appropriate

Avoid without a specific reason:

- heap allocation
- recursion
- variable-length arrays
- hidden global state
- platform-specific APIs
- unnecessary standard-library dependencies
- unbounded operations

Do not assume:

- host endianness
- aligned memory access
- `char` signedness
- integer sizes beyond what the type guarantees

Protocol byte order must always be handled explicitly.

## Memory safety

Treat every externally supplied byte as untrusted input.

Every parser and decoder must validate input before using it.

Always consider:

- buffer boundaries
- integer overflow
- integer underflow
- length-field validation
- truncated packets
- malformed headers
- impossible field combinations
- invalid enum or command values
- sequence validation where applicable
- maximum protocol-defined sizes
- null pointers where the API permits them
- state-machine misuse
- duplicated or unexpected packets

Never read beyond the provided buffer.

Never trust a length field merely because it exists in the packet.

Validate lengths before copying, indexing, or advancing pointers.

Avoid unsafe functions where the size of the destination cannot be proven.

## Parsing

Parsing code should decode protocol data, validate it, and return structured results.

Parsing functions should not:

- print
- log
- terminate the process
- perform unrelated application behavior
- silently repair malformed input

Malformed input should result in an explicit error.

Keep packet parsing separate from higher-level protocol state where practical.

For example, decoding an individual frame and reassembling a multi-frame message should normally be separate responsibilities.

## Error handling

Errors must be explicit and meaningful.

Prefer project-specific result enums over ambiguous integer return values.

Example:

```c
typedef enum {
    CTAPHID_PARSE_OK = 0,
    CTAPHID_PARSE_NULL_ARGUMENT,
    CTAPHID_PARSE_INVALID_PACKET,
    CTAPHID_PARSE_INVALID_LENGTH,
    CTAPHID_PARSE_INVALID_COMMAND
} CtaphidParseResult;
```

Names should describe the actual failure.

Do not collapse different validation failures into a generic error unless distinguishing them provides no value.

Do not use `assert()` as validation for untrusted protocol input.

Assertions may be used for internal invariants during development, but runtime input validation must still exist.

## Naming

Use names that communicate protocol meaning.

Prefer:

```c
payload_length
sequence_number
command
channel_id
packet_type
```

over names such as:

```c
len
seq
cmd
x
tmp
data2
```

Common protocol abbreviations already defined by the specification are acceptable.

Functions should describe what they do.

Prefer:

```c
ctaphid_parse_packet()
ctaphid_decode_initial_packet()
ctaphid_validate_command()
```

over generic names such as:

```c
process()
handle()
parse_data()
do_packet()
```

Keep naming consistent across headers, implementations, tests, enums, and structures.

## Constants and magic numbers

Protocol-defined constants should be named.

Prefer:

```c
#define CTAPHID_PACKET_SIZE 64U
#define CTAPHID_INIT_PAYLOAD_SIZE 57U
#define CTAPHID_CONT_PAYLOAD_SIZE 59U
```

over repeating protocol values throughout implementation code.

However, do not refactor unrelated hardcoded values in development or test code unless requested.

A hardcoded test packet or temporary `main.c` value is not automatically part of the task.

## Bit operations

Bit manipulation must be explicit and readable.

Use masks and named constants where they represent protocol fields.

Pay attention to:

- operator precedence
- integer promotion
- signed versus unsigned operations
- shift width
- endian conversion

Prefer code whose intent can be verified directly against the protocol specification.

## API design

Public APIs should have clear ownership and mutation rules.

A function signature should make it apparent:

- which data is input
- which data is output
- how much input data exists
- whether input is modified
- who owns output storage

Use `const` for input data that must not be modified.

Example:

```c
CtaphidParseResult ctaphid_parse_packet(
    const uint8_t *packet,
    size_t packet_length,
    CtaphidParsedPacket *parsed_packet
);
```

Do not expose implementation details unnecessarily through public headers.

## Structures

Structures should represent protocol concepts rather than temporary implementation convenience.

Initialize output structures deliberately.

Do not leave fields containing indeterminate data after a successful operation.

For fields that do not apply to a particular packet type, choose an explicit project convention such as:

- zero
- a dedicated enum value
- a documented validity flag

Do not rely on callers knowing which uninitialized fields they should ignore.

## Security mindset

Assume malformed and intentionally hostile input will eventually reach the implementation.

When modifying protocol-facing code, consider whether an attacker could cause:

- out-of-bounds reads
- out-of-bounds writes
- integer wraparound
- excessive CPU work
- excessive memory usage
- inconsistent parser state
- stale state reuse
- packet confusion
- command confusion
- invalid state transitions
- information leakage

Reject invalid input as early as practical.

Do not sacrifice readability for micro-optimizations unless measurements justify them.

Security-sensitive behavior should be straightforward enough to audit manually.

## Testing

Production protocol logic should have automated tests.

Tests should cover normal behavior and malformed input.

Relevant test categories include:

- valid packets
- minimum values
- maximum values
- boundary values
- invalid lengths
- truncated input
- invalid flags
- invalid commands
- invalid sequence numbers
- unexpected packet types
- null arguments when relevant
- malformed multi-byte values
- state-transition errors
- duplicate packets where relevant

When fixing a bug, add a regression test when practical.

Tests should verify observable behavior rather than internal implementation details whenever possible.

## Fuzzing

Parsers and protocol decoders should be designed so they can eventually be fuzz-tested.

Keep parser entry points simple enough to accept arbitrary byte buffers without requiring unrelated application setup.

When specifically requested to improve parser robustness, consider malformed inputs that a fuzzer would discover.

Do not introduce a fuzzing framework unless requested.

## Compiler diagnostics

Production code should compile cleanly with strict warnings.

Code should be compatible with warning levels comparable to:

```text
-Wall
-Wextra
-Wpedantic
-Wconversion
-Wshadow
```

Do not silence warnings with casts unless the conversion is understood and intentional.

Do not change project-wide compiler options unless requested.

## Comments

Comments should explain:

- protocol rules
- non-obvious security checks
- unusual bit layouts
- reasoning that cannot be expressed clearly through code

Do not write comments that merely repeat the code.

Good:

```c
/* Bit 7 distinguishes an initial frame from a continuation frame. */
```

Avoid:

```c
/* Shift packet[0] left by 24 bits. */
```

Reference protocol terminology where possible.

## Specification behavior

When implementing a protocol rule, follow the relevant protocol specification rather than assumptions based on current test packets.

If the specification is ambiguous or the task requires a behavior choice that has not been defined, do not invent one silently.

State the ambiguity and ask for the required behavior when it materially affects the implementation.

Do not implement optional protocol functionality until requested.

## `main.c` and experimental code

`main.c` may be used purely as a temporary test harness.

Unless specifically requested, do not treat it as production application architecture.

The following may intentionally exist there:

- hardcoded byte arrays
- manually constructed packets
- magic numbers
- temporary `printf()` statements
- experimental calls
- incomplete examples

Do not clean these up merely because they would not be acceptable in production protocol code.

Production standards apply primarily to reusable protocol/library code.

## Refactoring

Refactor only when:

1. the task explicitly asks for it, or
2. a small local refactor is necessary to implement the requested change correctly.

Do not perform broad opportunistic refactoring.

If a larger architectural issue is noticed, mention it separately without changing it.

## Dependencies

Avoid new dependencies unless the task requires them.

The protocol core should preferably remain usable as plain C with a minimal runtime environment.

Do not add a library merely to simplify something that can be implemented safely and clearly with a small amount of C.

## Changes

Keep changes minimal and focused.

Before modifying code, identify which files are directly relevant to the requested task.

After the change:

- verify the requested behavior
- run relevant tests
- check for compiler warnings when possible
- report what was changed
- report any directly relevant unresolved issue

Do not report unrelated code-quality observations unless they materially affect the requested task.

## When reviewing code

When asked to review a specific function, module, or feature:

- review that requested scope
- verify correctness
- verify boundary handling
- verify security-sensitive behavior
- verify protocol compliance where applicable
- verify tests relevant to that code

Do not turn a targeted review into a whole-project audit.

For example, a request to review `ctaphid_parse_packet()` does not imply permission to review and rewrite `main.c`.

## Priority order

When requirements conflict, use this priority:

1. Explicit task instructions
2. Protocol correctness
3. Memory and security safety
4. Correct error handling
5. Embedded portability
6. Maintainability and readability
7. Performance
8. Convenience

Never expand the requested task merely to improve a lower-priority item.