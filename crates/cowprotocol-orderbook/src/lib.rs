//! # cowprotocol-orderbook
//!
//! Orderbook HTTP client, trading facade, and subgraph queries for the
//! CoW Protocol Rust SDK. Depends on
//! [`cowprotocol-primitives`](https://docs.rs/cowprotocol-primitives),
//! [`cowprotocol-signing`](https://docs.rs/cowprotocol-signing), and
//! [`cowprotocol-appdata`](https://docs.rs/cowprotocol-appdata).
//! The full SDK lives at
//! [`cowprotocol`](https://docs.rs/cowprotocol).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
