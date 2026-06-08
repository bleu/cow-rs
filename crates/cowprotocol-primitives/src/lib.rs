//! # cowprotocol-primitives
//!
//! Pure-compute primitives for the CoW Protocol Rust SDK. Carries no
//! HTTP dependency. The full SDK lives at
//! [`cowprotocol`](https://docs.rs/cowprotocol); use this crate
//! directly when you only need typed orders, EIP-712 domain
//! separators, contract bindings, EthFlow, cancellation,
//! ComposableCoW conditional orders, multiplexer merkle proofs, or the
//! quote-amounts arithmetic.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(target_arch = "wasm32")]
use getrandom as _;
