//! # cowprotocol-signing
//!
//! Signing schemes for the CoW Protocol Rust SDK: EIP-712, EthSign,
//! EIP-1271, PreSign. Pairs with
//! [`cowprotocol-primitives`](https://docs.rs/cowprotocol-primitives)
//! for the EIP-712 domain types.
//!
//! Re-exports the `cowprotocol::signing` namespace; use the umbrella
//! [`cowprotocol`](https://docs.rs/cowprotocol) crate for the full SDK
//! surface.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use cowprotocol::signing::*;

/// Smoke
///
/// ```
/// use cowprotocol_primitives::SigningScheme;
/// use cowprotocol_signing::Signature;
///
/// let sig = Signature::empty_for(SigningScheme::PreSign);
/// assert_eq!(sig.scheme(), SigningScheme::PreSign);
/// ```
#[doc(hidden)]
pub mod _smoke {}
