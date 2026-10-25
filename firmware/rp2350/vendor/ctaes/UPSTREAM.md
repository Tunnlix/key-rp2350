# ctaes source provenance

Source: [bitcoin-core/ctaes](https://github.com/bitcoin-core/ctaes), commit
`3b10b89b05ca1ef5fff33316777249df25c8b930`. The three upstream files are unmodified;
MIT license and copyright are retained in `COPYING` and the source headers.

SHA-256:

- `ctaes.c`: `78913b0339766c3901825560aaba42f23081bd5ff20658ba4decd849c90e65e2`
- `ctaes.h`: `a1a62f394eda457b35d9126373d3216cebaff536ba924515162414337dc8e4db`
- `COPYING`: `705391f5c3000c942b63c028977a372a5fb12eb0abc6210b3d835115e2544a06`

The RP2350 provider uses upstream AES-256 block operations with its own CBC
chaining. It copies caller IVs and wipes its key context and CBC intermediates.
Upstream CBC helpers are unused. Compiled behavior, internal spills and physical
side-channel resistance remain separate qualification concerns.
