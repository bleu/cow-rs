# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **wasm `get_quote` no longer rejects quote requests that pin a non-empty
  `appData`.** The binding used to run eagerly with a hard-coded
  empty-document digest, so every pinned-appData quote failed with a spurious
  `appData mismatch`. The hostile-orderbook response binding now runs at the
  projection chokepoints (`to_signed_order_data`, `build_order_creation`)
  with the caller's real digest.
- `SubgraphClient::totals()` surfaces `SubgraphError::EmptyResponse` when the
  subgraph returns an empty `totals` array instead of fabricating an
  all-empty-strings `Totals` (its `Default` derive is gone).
- All stale cross-crate rustdoc links from the crate split are repaired;
  `cargo doc` is warning-free.

### Added

- `ProofLocation` (`repr(u8)`, mirrors cow-sdk's enum) with
  `From<ProofLocation> for U256` and `Proof::new(location, data)`, replacing
  hand-assembled `U256` location codes.
- `Chain` now implements `Serialize` (as the integer chain id), making the
  serde boundary symmetric; the `Deserialize` `expecting` message now admits
  slug strings, which were always accepted.
- `TryFrom<alloy_chains::NamedChain> for Chain`, so
  `OrderBookApi::with_chain(NamedChain::Gnosis.try_into()?)` works (new
  `alloy-chains` dependency, default features off).

### Changed

- **Breaking**: `UnsupportedChain` is now an enum (`Id(u64)` / `Slug(...)`)
  and no longer `Copy`. Parsing an unknown slug reports
  `unsupported chain slug "..."` instead of the misleading
  `unsupported chain id 0` sentinel.
- `Multiplexer` documentation now records the verified evidence chain for why
  its merkle layout differs from cow-sdk's `StandardMerkleTree`: upstream's
  own leaf encodings disagree with each other and with the on-chain
  `ComposableCoW` verifier (cow-sdk issue #155); this SDK's layout matches
  the contract. Documentation only, no behavioural change.
- App-data partner-fee validation has a single chokepoint
  (`AppDataPartnerFee::new`); the builders and the `Deserialize` impl route
  through it, and the free `validate_fee_policy` function is private.

### Removed

- **Breaking**: `PollOutcome` is deleted from `composable` and both crate
  roots. It had no producer, no revert-data decoder, and no consumer; it will
  return together with a real watch-tower polling feature.
