# cow-rs

[![crates.io](https://img.shields.io/crates/v/cowprotocol.svg)](https://crates.io/crates/cowprotocol)
[![docs.rs](https://docs.rs/cowprotocol/badge.svg)](https://docs.rs/cowprotocol)
[![CI](https://github.com/cowdao-grants/cow-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/cowdao-grants/cow-rs/actions/workflows/ci.yml)
[![Licence: GPL-3.0-or-later](https://img.shields.io/badge/licence-GPL--3.0--or--later-blue)](./LICENSE)

The Rust SDK for the [CoW Protocol](https://cow.fi).

`cow-rs` is the idiomatic Rust client for trading on CoW Protocol:
build and sign orders, talk to the orderbook, decode on-chain
settlement events. Built on [alloy](https://github.com/alloy-rs/alloy);
ports the canonical types from
[`cowprotocol/services`](https://github.com/cowprotocol/services); locks
every protocol-critical path byte-for-byte against
[`@cowprotocol/cow-sdk`](https://github.com/cowprotocol/cow-sdk),
[`cowdao-grants/cow-py`](https://github.com/cowdao-grants/cow-py) and
`ethers`.

## At a glance

- **Full order lifecycle**: quote, sign, submit, look up, cancel.
- **All four signing schemes**: EIP-712, EthSign, EIP-1271, pre-sign.
- **All eleven chains**: Mainnet, BNB, Gnosis, Polygon, Base, Plasma,
  Arbitrum One, Avalanche, Ink, Linea, Sepolia, plus their barn
  staging endpoints where the orderbook team publishes them.
- **Conformance-locked**: 132 tests, with byte-exact goldens
  cross-checked against `cowprotocol/services`, `cowprotocol/contracts`,
  ethers, cow-sdk and cow-py.
- **Sync core, async client**: hashing, signing and contract decoding
  are pure-compute and need no runtime; the HTTP client is async-tokio
  and the only piece that depends on one.
- **WASM-ready**: compiles cleanly to `wasm32-unknown-unknown`; the
  poll helper is runtime-agnostic so you can drop in
  `gloo_timers::future::sleep` in the browser.

## Install

```toml
[dependencies]
cowprotocol = "1.0.0-alpha"
```

The crate is published as `cowprotocol` on crates.io (the `cow-rs` name was already taken on
crates.io by an unrelated publisher before this SDK existed); the source lives at
[`cowdao-grants/cow-rs`](https://github.com/cowdao-grants/cow-rs).

MSRV `1.91`, edition `2024`.

## Quick start: quote, sign, submit

```rust,no_run
use cowprotocol::{
    Chain, DomainSeparator, EcdsaSigningScheme, EMPTY_APP_DATA_HASH,
    EMPTY_APP_DATA_JSON, OrderBookApi, OrderCreation, QuoteRequest,
};
use alloy_primitives::{U256, address};
use alloy_signer_local::PrivateKeySigner;

# async fn run(signer: PrivateKeySigner) -> cowprotocol::Result<()> {
let api = OrderBookApi::new(Chain::Mainnet);

// 1. Quote.
let request = QuoteRequest::sell_amount_before_fee(
    address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), // USDC
    address!("6B175474E89094C44Da98b954EedeAC495271d0F"), // DAI
    signer.address(),
    U256::from(100_000_000_u64),
);
let quote = api.get_quote(&request).await?;

// 2. Build the order, sign it under the chain's GPv2Settlement domain.
let order_data = quote.to_signed_order_data(EMPTY_APP_DATA_HASH)?;
let domain = DomainSeparator::new(Chain::Mainnet.id(), Chain::Mainnet.settlement());
let signature = order_data.sign(EcdsaSigningScheme::Eip712, &domain, &signer)?;

// 3. Submit.
let creation = OrderCreation::from_signed_order_data(
    order_data,
    signature,
    signer.address(),
    EMPTY_APP_DATA_JSON.to_owned(),
    Some(quote.id),
)?;
let uid = api.post_order(&creation).await?;
println!("https://explorer.cow.fi/orders/{uid}");
# Ok(()) }
```

See [`examples/post_order.rs`](crates/cow-rs/examples/post_order.rs)
for the same flow on Sepolia, runnable with a private key in the
environment.

## No-async core

Every protocol-critical primitive is synchronous and runtime-free:
`OrderData::hash_struct`, `OrderData::uid`, `EcdsaSignature::sign`,
`Signature::recover`, `DomainSeparator::new`, the `sol!`-generated
contract bindings. You can use cow-rs in a Postgres extension
([`pgrx`](https://github.com/pgcentralfoundation/pgrx)), an FFI shim,
an embedded context, or anywhere else a tokio reactor is hostile,
without pulling in `reqwest` or `tokio`.

```rust
use cowprotocol::{OrderBuilder, OrderKind, DomainSeparator, Chain};
use alloy_primitives::{U256, address};

let order = OrderBuilder::new(
    address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
)
.sell_amount(U256::from(100_000_000_u64))
.buy_amount(U256::from(99_000_000_000_000_000_000_u128))
.valid_to(u32::MAX)
.kind(OrderKind::Sell)
.build();

let domain = DomainSeparator::new(Chain::Mainnet.id(), Chain::Mainnet.settlement());
let owner = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
let uid = order.uid(&domain, owner);
assert_eq!(uid.0.len(), 56);
```

## Surface

| Module | What it exposes |
|---|---|
| `order` | `OrderData` (12-field signed payload), `OrderBuilder`, `OrderUid`, `OrderKind`, `SellTokenSource`, `BuyTokenDestination`, `BUY_ETH_ADDRESS`, plus the full GET-orders `Order`, `OrderStatus`, `OrderClass` |
| `order_book` | `OrderBookApi` with quote / submit / lookup / status / cancel, trades, native price, account orders, app-data PUT / GET, version, total surplus; the runtime-agnostic `poll_until` helper and the tokio-bound `wait_for_order_fulfilled` convenience |
| `signature` | `Signature` (all four schemes), `EcdsaSignature`, `Recovered`, `SignatureError` |
| `domain` | `DomainSeparator`, `hashed_eip712_message`, `hashed_ethsign_message` |
| `chain` | `Chain` (eleven networks) with `orderbook_base_url`, `orderbook_barn_url`, `settlement`, `vault_relayer`, `subgraph_studio_url` |
| `cancellation` | `OrderCancellation` (single), `OrderCancellations` (collection), `SignedOrderCancellations` |
| `app_data` | `AppDataHash`, `AppDataDoc` (canonical JSON + keccak digest), `AppDataCid` (IPFS CIDv1 derivation) |
| `eth_flow` | `EthFlowOrder`, `ETH_FLOW_PRODUCTION`, `ETH_FLOW_STAGING` |
| `composable` | `ConditionalOrderParams`, `Proof`, `PollOutcome`, `ComposableCoW` events plus deployment addresses |
| `contracts` | `GPv2Settlement` (settle + events), `CoWSwapOnchainOrders` (ETH-flow events), `ERC20`, `WETH9`, `GPV2_SETTLEMENT`, `GPV2_VAULT_RELAYER` |
| `subgraph` | `SubgraphClient` typed access to CoW's subgraph; totals, daily / hourly volume; opt-in bearer-token auth for the gateway URL |

Everything is re-exported at the crate root: `use cowprotocol::...`.

## WASM

cow-rs targets `wasm32-unknown-unknown`:

- Reqwest's browser fetch backend kicks in automatically on wasm.
- `OrderBookApi::poll_until` is runtime-agnostic; pair it with
  `gloo_timers::future::sleep` instead of `tokio::time::sleep`.
- `wait_for_order_fulfilled` (the tokio-bound convenience) is
  non-wasm only.
- CI gates `cargo check --target wasm32-unknown-unknown` on every
  push.

## Conformance

cow-rs locks byte-exact equivalence on every protocol-critical path:

- ethers `TypedDataEncoder` for all eleven chains: signed UID, struct
  hash, domain separator, six order-shape permutations
- `cowprotocol/services` for signature recovery and cancellation
  struct hashes
- `cowprotocol/contracts` for the canonical `TYPE_HASH` derivation,
  `packOrderUidParams` layout, and event topic hashes
- ethers `Wallet.signTypedData` for the ECDSA `(r, s, v)` golden
- cow-py for the `ConditionalOrder` leaf-id derivation
- The empty-document app-data digest `keccak256("{}")`

Regenerate the cross-implementation vectors with:

```sh
cd tools/vector-gen && npm install && npm run gen > vectors.json
```

## Status

**1.0.0-alpha**: the public API is locked unless a critical conformance
issue forces a break. Patch releases (`1.0.0-alpha.N`) bring additive
features and bug fixes; breaking changes only on minor or major bumps.

Production readiness:

- ✅ Byte-conformance with services / contracts / cow-sdk / cow-py
- ✅ All eleven documented chains
- ✅ All four signing schemes
- ✅ Mock-server integration coverage for every `OrderBookApi` method
- ✅ WASM compilation gate in CI
- ✅ `cargo clippy -- -Dwarnings`, no `unsafe`, no `anyhow` in lib code
- ⏳ Not yet on crates.io (publishing is the next milestone)

## Building

```
just build       # cargo build --all-targets --all-features --workspace
just test        # cargo test --all-targets --all-features --workspace
just clippy      # cargo clippy ... -- -Dwarnings
just fmt-check
just wasm-check  # cargo check --target wasm32-unknown-unknown ...
just doc         # cargo doc with -D warnings
```

## Layout

```
crates/cow-rs/                # Library crate; everything re-exported from the root
crates/cow-rs/examples/       # get_quote.rs, post_order.rs
tools/vector-gen/             # Node.js golden-vector generator (ethers reference)
recon/                        # Internal recon docs (gitignored, not published)
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Briefly: Oxford English in
prose, no em dashes, Conventional Commits, AI-assistance disclosure
in the PR body (never in commits), PRs ≤ 1,500 LoC against `develop`.

## Licence

GPL-3.0-or-later; see [LICENSE](./LICENSE). Portions adapted from
[`cowprotocol/services`](https://github.com/cowprotocol/services)
under MIT / Apache-2.0 with attribution in each affected file.
