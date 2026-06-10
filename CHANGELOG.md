# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed: one quote-to-order pipeline (breaking)

- **BUY orders now sign different amounts (the correct ones).** The old basic projection signed the bare quoted `sellAmount` for BUY orders; the unified `OrderQuoteResponse::try_to_order_data` routes through the parity-locked `quote_amounts::compute`, so the signed sell becomes `sellAmount + feeAmount`, matching the TS reference (`getQuoteAmountsAndCosts.ts`, pinned in `parity/source-lock.toml`). Any UID derived from a BUY quote with non-zero `feeAmount` changes. SELL projections at `OrderCosts::default()` are locked byte-equal to the old path by an equivalence test. Affects `cow-sdk-wasm`'s `to_signed_order_data` / `get_quote_simple` too.
- **Removed** `OrderQuoteResponse::try_into_signed_order_data` and `try_into_signed_order_data_with_costs`; the single replacement is `try_to_order_data(&request, app_data, &OrderCosts)`.
- **Removed** `TradingClient`, `SwapOrder`, `PostedSwapOrder`. `post_swap_order` maps 1:1 onto the pipeline (the pipeline module rustdoc carries the full recipe):

  ```rust
  api.quote_builder()
      .with_sell_token(sell)
      .with_buy_token(buy)
      .with_from(owner)
      .with_sell_amount(amount)
      .build()
      .await?
      .sign(&signer)?
      .submit()
      .await?;
  ```

- **Removed** `OrderBookQuoteBuilder` (and its `configure()` hatch), the request-only `QuoteRequestBuilder`, and `QuoteRequest::builder()`. The one replacement is the transport-generic `QuoteRequestBuilder<T, ...>`; `into_request()` replaces `build_request()`. `SignedOrderSubmission` is renamed `OrderSubmission`; `sign_with_scheme` / `sign_for_chain` collapse into `sign_with(chain, scheme, signer)`; the signer is taken by value (`&wallet` still works). The pipeline is no longer gated on `http-client` and works over any `HttpTransport + Clone`.
- **Added** `ProtocolFeeBps` (typed wire decimal; malformed strings now fail at quote-response deserialisation instead of at costs time), public `OrderCosts` with a neutral `Default`, and `DEFAULT_SLIPPAGE_BPS = 50` (seeded by `quote_builder()`).
- **Removed** `Error::QuoteAmountOverflow`, folded into `Error::QuoteFeeMathOverflow { stage }`.
- **Fail-closed behaviour**: degenerate quotes with `sellAmount = 0` now error (`QuoteSellAmountZero`); the pipeline's `build()` rejects `from == Address::ZERO` and oversized app-data documents before the quote round-trip, and binds the response to the request at quote time.
- `OrderSubmission::submit()` PUTs the canonical app-data JSON before POSTing, skipping the PUT for the empty document.
- **`OrderBookApi::post_order` owner-verifies every submission when the client carries a chain hint** (one extra ECDSA recovery); chainless clients skip the check. `cow-sdk-wasm`'s redundant pre-flight was dropped.
- **Removed** `QuoteAppData::hash` / `QuoteAppData::full` identity constructors; use the enum variants, `From<AppDataHash>`, or the new `From<&AppDataDoc>` (pins the canonical JSON).
- `SignerSync` is re-exported from `cowprotocol-signing` and the meta crate; `cowprotocol-orderbook` no longer depends on `alloy-signer`.

### Fixed

- **wasm `get_quote` no longer rejects quote requests that pin a non-empty `appData`.** The binding used to run eagerly with a hard-coded empty-document digest, so every pinned-appData quote failed with a spurious `appData mismatch`. The hostile-orderbook response binding now runs at the projection chokepoints (`to_signed_order_data`, `build_order_creation`) with the caller's real digest.
- `SubgraphClient::totals()` surfaces `SubgraphError::EmptyResponse` when the subgraph returns an empty `totals` array instead of fabricating an all-empty-strings `Totals` (its `Default` derive is gone).
- All stale cross-crate rustdoc links from the crate split are repaired; `cargo doc` is warning-free.

### Added

- `ProofLocation` (`repr(u8)`, mirrors cow-sdk's enum) with `From<ProofLocation> for U256` and `Proof::new(location, data)`, replacing hand-assembled `U256` location codes.
- `Chain` now implements `Serialize` (as the integer chain id), making the serde boundary symmetric; the `Deserialize` `expecting` message now admits slug strings, which were always accepted.
- `TryFrom<alloy_chains::NamedChain> for Chain`, so `OrderBookApi::with_chain(NamedChain::Gnosis.try_into()?)` works (new `alloy-chains` dependency, default features off).

### Changed

- **Breaking**: `UnsupportedChain` is now an enum (`Id(u64)` / `Slug(...)`) and no longer `Copy`. Parsing an unknown slug reports `unsupported chain slug "..."` instead of the misleading `unsupported chain id 0` sentinel.
- `Multiplexer` documentation now records the verified evidence chain for why its merkle layout differs from cow-sdk's `StandardMerkleTree`: upstream's own leaf encodings disagree with each other and with the on-chain `ComposableCoW` verifier (cow-sdk issue #155); this SDK's layout matches the contract. Documentation only, no behavioural change.
- App-data partner-fee validation has a single chokepoint (`AppDataPartnerFee::new`); the builders and the `Deserialize` impl route through it, and the free `validate_fee_policy` function is private.

### Removed

- **Breaking**: `PollOutcome` is deleted from `composable` and both crate roots. It had no producer, no revert-data decoder, and no consumer; it will return together with a real watch-tower polling feature.
- **Breaking**: `Signature::empty_for` and its all-zero ECDSA sentinel. It was a public constructor producing an invalid value of its own type, consumed only by tests; build placeholders explicitly in test code instead.
