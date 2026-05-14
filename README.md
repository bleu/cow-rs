# cow-rs

A Rust SDK for the [CoW Protocol](https://cow.fi).

## Surface

- **Order primitives**: `OrderData` (12-field signed payload),
  `OrderUid` (56-byte identifier), `OrderKind`, `SellTokenSource` and
  `BuyTokenDestination`. EIP-712 struct hashing via
  `OrderData::hash_struct`, UID derivation via `OrderData::uid`.
- **Signing**: `Signature` covers all four schemes (`Eip712`,
  `EthSign`, `Eip1271`, `PreSign`); `EcdsaSignature` carries the raw
  `r/s/v` triple; recovery via `Signature::recover`.
- **Domain**: `DomainSeparator`, `hashed_eip712_message`,
  `hashed_ethsign_message`.
- **Chains**: `Chain` covers the eleven networks the CoW orderbook
  serves (Mainnet, BNB, Gnosis, Polygon, Base, Plasma, Arbitrum One,
  Avalanche, Ink, Linea, Sepolia) with their `api.cow.fi` slugs.
- **Orderbook**: `OrderBookApi` is the async HTTP client. Quote,
  submit, lookup, cancel; trade / native-price / account queries;
  app-data pinning.
- **App-data**: `AppDataDoc` builder with deterministic canonical
  JSON, `AppDataHash` keccak digest, `AppDataCid` IPFS CID
  derivation.
- **EthFlow**: native-ETH sell support via the periphery EthFlow
  contract addresses and `EthFlowOrder`.
- **Composable orders**: `ConditionalOrderParams`, `Proof`,
  `PollOutcome` for the
  [`ComposableCoW`](https://github.com/nullislabs/composable-cow)
  framework's core primitives plus deployment addresses.
- **Contract bindings**: typed ABI structs for `GPv2Settlement`
  (including the `Trade`, `Settlement`, `OrderInvalidated`,
  `Interaction`, `PreSignature` events and the `settle` calldata),
  `GPv2OrderData`, `ERC20`, `WETH9`.
- **Subgraph**: `SubgraphClient` typed read-only access to CoW's
  subgraph deployments.
- **WASM**: compiles cleanly to `wasm32-unknown-unknown`; the HTTP
  surface uses `reqwest`'s fetch backend in the browser.

## Status

Pre-1.0. Public API will evolve until 0.1.0; pin a specific commit
for stability today.

Parity targets: [`cowprotocol/cow-sdk`](https://github.com/cowprotocol/cow-sdk)
(TypeScript, canonical),
[`cowdao-grants/cow-py`](https://github.com/cowdao-grants/cow-py)
(Python). Internal lifts from
[`cowprotocol/services`](https://github.com/cowprotocol/services)
under MIT / Apache-2.0 with attribution.

## Quick start

```rust
use cow_rs::{Chain, OrderBookApi, QuoteRequest};
use alloy_primitives::{U256, address};

# async fn run() -> cow_rs::Result<()> {
let api = OrderBookApi::new(Chain::Mainnet);
let request = QuoteRequest::sell_amount_before_fee(
    address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), // USDC
    address!("6B175474E89094C44Da98b954EedeAC495271d0F"), // DAI
    address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    U256::from(100_000_000_u64),
);
let response = api.get_quote(&request).await?;
println!("buy amount: {}", response.quote.buy_amount);
# Ok(()) }
```

See `crates/cow-rs/examples/get_quote.rs` and
`crates/cow-rs/examples/post_order.rs` for a full sign-and-submit
flow on Sepolia.

## Layout

```
crates/cow-rs/        Library crate; everything re-exported from the root
crates/cow-rs/examples/
tools/vector-gen/     Node.js golden-vector generator (ethers reference)
recon/                Internal recon docs
```

## Building

```
just build       # cargo build --all-targets --all-features --workspace
just test        # cargo test --all-targets --all-features --workspace
just clippy      # cargo clippy ... -- -Dwarnings
just fmt-check
just wasm-check  # cargo check --target wasm32-unknown-unknown ...
just doc         # cargo doc with -D warnings
```

MSRV: 1.91. Edition 2024.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Briefly: Oxford English in
prose, no em dashes, conventional commits, AI assistance disclosed in
the PR description (never in commits), PRs ≤ 1,500 LoC against
`develop`.

## Licence

GPL-3.0-or-later. See [LICENSE](./LICENSE). Portions adapted from
[`cowprotocol/services`](https://github.com/cowprotocol/services)
under MIT / Apache-2.0 with attribution.
