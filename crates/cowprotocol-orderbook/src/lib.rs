//! # cowprotocol-orderbook
//!
//! Orderbook HTTP client, trading facade, and subgraph queries for the
//! CoW Protocol Rust SDK. The `http-client` feature gates the
//! `reqwest`-backed client; the `subgraph` feature gates the GraphQL
//! totals/volume queries. Both default on.
//!
//! Re-exports the `cowprotocol::orderbook` namespace; use the umbrella
//! [`cowprotocol`](https://docs.rs/cowprotocol) crate for the full SDK
//! surface.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use cowprotocol::orderbook::*;

/// Smoke
///
/// ```
/// use cowprotocol_orderbook::OrderBookApi;
/// use cowprotocol_primitives::Chain;
///
/// let api = OrderBookApi::with_chain(Chain::Mainnet).build();
/// assert_eq!(api.chain(), Some(Chain::Mainnet));
/// ```
#[cfg(feature = "http-client")]
#[doc(hidden)]
pub mod _smoke {}
