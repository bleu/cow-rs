//! # cowprotocol-primitives
//!
//! Pure-compute primitives for the CoW Protocol Rust SDK: chain
//! selectors, EIP-712 domain, 12-field [`OrderData`], `sol!`-generated
//! contract bindings, EthFlow, [`OrderCancellations`], ComposableCoW
//! conditional orders, multiplexer merkle proofs, and the
//! `quote_amounts` arithmetic. No HTTP, no signing.
//!
//! Re-exports the `cowprotocol::primitives` namespace; pair with
//! [`cowprotocol-signing`](https://docs.rs/cowprotocol-signing),
//! [`cowprotocol-appdata`](https://docs.rs/cowprotocol-appdata), and
//! [`cowprotocol-orderbook`](https://docs.rs/cowprotocol-orderbook) for
//! the full surface, or use the umbrella
//! [`cowprotocol`](https://docs.rs/cowprotocol) crate.
//!
//! ## Smoke
//!
//! ```
//! use cowprotocol_primitives::{Chain, SigningScheme, settlement_domain};
//!
//! let chain = Chain::Mainnet;
//! let domain = settlement_domain(chain as u64, chain.settlement());
//! assert_eq!(SigningScheme::default(), SigningScheme::Eip712);
//! # let _ = domain;
//! ```
//!
//! [`OrderData`]: cowprotocol::primitives::OrderData
//! [`OrderCancellations`]: cowprotocol::primitives::OrderCancellations

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use cowprotocol::primitives::*;
