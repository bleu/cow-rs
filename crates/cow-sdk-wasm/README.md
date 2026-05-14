# cow-sdk-wasm

Rust source for the `@cowdao-grants/cow-sdk-wasm` npm package: a thin
`wasm-bindgen` shim that exposes the `cowprotocol` SDK to JavaScript
callers.

Published to npm as `@cowdao-grants/cow-sdk-wasm`. Not published to
crates.io.

## Status

Alpha. The surface mirrors the cow-py / cow-sdk feature set we considered
most useful for browser and Node consumers, but the binding is young and
the API may evolve before a 1.0.

## Quick example

```js
import init, {
  chain_info,
  get_quote_simple,
  order_uid,
} from '@cowdao-grants/cow-sdk-wasm';

await init();

const info = chain_info('mainnet');
console.log(info.settlement, info.orderbookBaseUrl);

const { response, uid } = await get_quote_simple(
  'mainnet',
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
  '0x6B175474E89094C44Da98b954EedeAC495271d0F', // DAI
  '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  '100000000',
);
```

See `test-harness/index.html` in the repository root for a complete
end-to-end example running against the live orderbook.

## Cargo features

| Feature | Default | What it adds |
| --- | --- | --- |
| `in_shim_signing` | off | Exports `sign_eip712`, `sign_ethsign`, `cancel_order_signed`. Pulls in `alloy-signer-local` so the shim can accept a private-key hex string and produce signatures inside wasm linear memory. Adds ~80–120 KB to the wasm binary. |

Production integrations sign with viem / ethers / Safe outside the wasm
boundary and feed the `(r, s, v)` triple back through `build_order_creation`.
For tests, scripts, or browser playgrounds where private keys already
exist in JS memory, enabling `in_shim_signing` is convenient.

## Build targets

Three wasm-pack targets, all built via the workspace `justfile`:

```sh
just wasm-build-web      # ES modules; what the test-harness uses
just wasm-build-bundler  # webpack / Vite / Rollup
just wasm-build-nodejs   # Node 18+ CommonJS
just wasm-build-all      # all three
just wasm-size           # build all three, then print .wasm byte sizes
```

Each lands in its own `pkg-{web,bundler,nodejs}/` directory under
`crates/cow-sdk-wasm/`, all of which are git-ignored.

## Publishing to npm (maintainer flow)

The crate is configured to publish under the `@cowdao-grants` npm scope.
The Cargo `version` in `crates/cow-sdk-wasm/Cargo.toml` is the source of
truth; `wasm-pack` propagates it into the generated `package.json`.

```sh
# 1. Bump version in crates/cow-sdk-wasm/Cargo.toml.
# 2. Build each target you want to publish.
just wasm-build-all

# 3. Pick a target's pkg directory (usually pkg-bundler for general use)
#    and publish.
cd crates/cow-sdk-wasm/pkg-bundler
npm publish --access public
```

`wasm-pack publish` also works if you prefer one command; it accepts the
same `--scope cowdao-grants` flag the build commands use.

## Why is the crate name `cow-sdk-wasm` and not `cowprotocol-wasm`?

The Rust crate on crates.io is `cowprotocol`. The npm equivalent at
`@cowprotocol/cow-sdk` is the TypeScript SDK maintained by the
cowprotocol organisation. To avoid name collisions and signal that this
is a community-built wasm binding, the npm package uses
`@cowdao-grants/cow-sdk-wasm` (under the grants org, where the parent
repository lives) and the Cargo crate matches.
