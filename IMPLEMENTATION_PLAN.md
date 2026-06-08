## Stage 1: Add Domain Crate Shells
**Goal**: Add workspace crates for `cowprotocol-primitives`, `cowprotocol-appdata`, `cowprotocol-signing`, and `cowprotocol-orderbook` without changing the public `cowprotocol` facade yet.
**Success Criteria**: Workspace metadata includes the new crates, each crate compiles as an empty domain package, and the existing SDK continues to compile unchanged.
**Tests**: `cargo +1.91.1 check --workspace --all-targets`
**Status**: Complete

## Stage 2: Extract Primitive Types
**Goal**: Move chain, domain, contract ABI, composable-order, and multiplexer primitives behind `cowprotocol-primitives`, with `cowprotocol` re-exporting the existing public API.
**Success Criteria**: Existing `cowprotocol::{Chain, DomainSeparator, ComposableCoW, Multiplexer, ...}` imports keep working, and primitive-only consumers can depend on `cowprotocol-primitives`.
**Tests**: `cargo +1.91.1 test -p cowprotocol-primitives`; `cargo +1.91.1 test -p cowprotocol`
**Status**: Complete

## Stage 3: Extract App-Data And Signing
**Goal**: Move order data, app-data document/hash/CID logic, and signature/cancellation logic into `cowprotocol-appdata` and `cowprotocol-signing`, keeping meta-crate exports stable.
**Success Criteria**: App-data and signing tests live with their owning crates, while `cowprotocol` still exposes the same ergonomic types and prelude.
**Tests**: `cargo +1.91.1 test -p cowprotocol-appdata`; `cargo +1.91.1 test -p cowprotocol-signing`; `cargo +1.91.1 test -p cowprotocol`
**Status**: Complete

## Stage 4: Extract Orderbook Client
**Goal**: Move quote/order DTOs, orderbook HTTP client, quote amount math, and trading helpers into `cowprotocol-orderbook`.
**Success Criteria**: `cowprotocol-orderbook` owns the HTTP feature gates and quote-builder flow, while the `cowprotocol` crate remains the common meta entry point.
**Tests**: `NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1 cargo +1.91.1 test -p cowprotocol-orderbook`; `cargo +1.91.1 check -p cowprotocol --no-default-features`
**Status**: Not Started

## Stage 5: Final Facade And WASM Integration
**Goal**: Make `cowprotocol` a cfg-gated meta crate with a small prelude over the domain crates, and update WASM/tooling dependencies to consume the new boundaries.
**Success Criteria**: The workspace builds through the meta crate on native and wasm paths, public examples use the meta prelude, and temporary compatibility shims are removed.
**Tests**: `cargo fmt --all -- --check`; `cargo +1.91.1 check --workspace --all-targets`; `NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1 cargo +1.91.1 test -p cowprotocol`
**Status**: Not Started
