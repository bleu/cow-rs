//! # cowprotocol-appdata
//!
//! App-data document, keccak digest, IPFS CID encoding, and the
//! SDK-attribution metadata (`COW_RS_APP_CODE`, `COW_RS_WASM_APP_CODE`)
//! for the CoW Protocol Rust SDK. Depends only on
//! [`cowprotocol-primitives`](https://docs.rs/cowprotocol-primitives).
//! The full SDK lives at
//! [`cowprotocol`](https://docs.rs/cowprotocol).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
