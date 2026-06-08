//! # cowprotocol-appdata
//!
//! App-data document, keccak digest, IPFS CID encoding, and the
//! SDK-attribution metadata (`COW_RS_APP_CODE`, `COW_RS_WASM_APP_CODE`)
//! for the CoW Protocol Rust SDK.
//!
//! Re-exports the `cowprotocol::appdata` namespace; use the umbrella
//! [`cowprotocol`](https://docs.rs/cowprotocol) crate for the full SDK
//! surface.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use cowprotocol::appdata::*;

/// Smoke
///
/// ```
/// use cowprotocol_appdata::{AppDataDoc, COW_RS_APP_CODE};
///
/// let doc = AppDataDoc::sdk_attribution(COW_RS_APP_CODE);
/// let _ = doc.canonical_json();
/// ```
#[doc(hidden)]
pub mod _smoke {}
