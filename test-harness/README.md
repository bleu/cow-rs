# wasm end-to-end harness

A static HTML page that loads the `cow-rs-wasm` crate and exercises the
cow-rs API surface from a browser. This goes one step beyond the
`cargo check --target wasm32-unknown-unknown` gate in CI: it actually
loads the wasm module, calls into it from JavaScript, and hits the live
orderbook through reqwest's browser-fetch backend.

## Run it

From the repository root:

```sh
just wasm-harness
open http://localhost:8765/test-harness/
```

Install `wasm-pack` with `cargo install wasm-pack --locked` if not present.

The recipe just chains the two raw commands, in case you prefer to run
them manually:

```sh
# 1. Build the wasm package (output is git-ignored).
(cd crates/cow-rs-wasm && wasm-pack build --target web --dev)
# 2. Serve the workspace over HTTP so ES-module imports resolve.
python3 -m http.server 8765
```

## What it verifies

1. **UID parity (pure compute)**: derives the 56-byte `OrderUid` for a
   fixed sell-only order against the mainnet `GPv2Settlement` domain. No
   network, no signing; proves the EIP-712 hashing path survives the
   wasm boundary byte-for-byte.

2. **Live `get_quote`**: calls `GET /api/v1/quote` against
   `api.cow.fi/mainnet`, deserialises the response across the
   wasm/JS bridge, and re-derives the UID from the orderbook's
   `OrderQuote`. Asserts the response carries `quote.buyAmount` and the
   computed `uid` is the expected 56-byte shape.

Both panels report ✅ / ❌ inline with the raw JSON beneath.
