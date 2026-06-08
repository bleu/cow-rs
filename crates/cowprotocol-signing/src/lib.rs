//! # cowprotocol-signing
//!
//! Signing schemes for the CoW Protocol Rust SDK: EIP-712, EthSign,
//! EIP-1271, PreSign. Depends only on
//! [`cowprotocol-primitives`](https://docs.rs/cowprotocol-primitives)
//! for the EIP-712 domain and signing-scheme enums. The full SDK lives
//! at [`cowprotocol`](https://docs.rs/cowprotocol).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
