# Third-party notices

Original project code uses the [MIT license](../LICENSE). Dependencies retain
their own licenses and copyright notices.

| Component | Reviewed source | License material |
| --- | --- | --- |
| ctaes | `3b10b89b05ca1ef5fff33316777249df25c8b930` | [Vendored MIT notice](../firmware/rp2350/vendor/ctaes/COPYING) and [source hashes](../firmware/rp2350/vendor/ctaes/UPSTREAM.md) |
| Monocypher | 4.0.3, commit `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f` | [License text](../licenses/monocypher-LICENCE.md), selected BSD-2-Clause, and [source hashes](../firmware/rp2350/vendor/monocypher/UPSTREAM.md) |
| Mbed TLS | 3.6.7 | [Dual-license text](../licenses/mbedtls.txt); this integration selects Apache-2.0 |
| Pico SDK | 2.3.1, commit `079c6f39023649b154152db30f1d781e884879bc` | [BSD license](../licenses/pico-sdk.txt), [selected source attributions](../licenses/pico-sdk-attributions.txt) |
| TinyUSB | `86ad6e56c1700e85f1c5678607a762cfe3aa2f47` | [MIT notice](../licenses/tinyusb.txt) |
| CMSIS | Bundled with SDK 2.3.1 | [Apache-2.0 text](../licenses/cmsis.txt) |
| SDK pico_printf | Bundled Marco Paland implementation | [MIT notice](../licenses/pico-printf.txt) |
| GCC runtime | Arm GNU Toolchain 15.2.Rel1 / GCC 15.2.1 | [GCC licenses and runtime exception](../licenses/gcc-runtime.txt) |
| Newlib/libgloss | Bundled with Arm GNU Toolchain 15.2.Rel1 | [Component notices](../licenses/newlib-libgloss.txt) |

The Mbed TLS archive is SHA-256 pinned to
`a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
The build selects bounded cryptographic units rather than TLS/X.509 applications.
The SDK and compiler are external build dependencies. Their versions are
reviewed pins, not claims to be the newest releases.

License texts preserve the upstream material. The compiler/runtime notice set
is conservative and may cover code that is discarded by the linker. Retain
applicable notices with distributed firmware and review the final link inputs
when dependencies or build settings change.
