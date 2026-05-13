//! # cow-rs
//!
//! Rust SDK for the [CoW Protocol](https://cow.fi).
//!
//! This crate is in early development. The first public surface is the
//! canonical signed-order payload — [`OrderData`] — and the primitives
//! needed to hash and identify it: [`DomainSeparator`], [`OrderUid`], and
//! the on-chain `bytes32` encodings of [`OrderKind`], [`SellTokenSource`],
//! [`BuyTokenDestination`], along with [`AppDataHash`].
//!
//! Everything else (orderbook client, signing, contract bindings, app-data
//! schema, subgraph, composable orders) will land in subsequent commits so
//! each addition can be reviewed in isolation.
//!
//! ## Example
//!
//! ```
//! use cow_rs::{
//!     AppDataHash, BuyTokenDestination, DomainSeparator, OrderData, OrderKind, SellTokenSource,
//! };
//! use alloy_primitives::{Address, U256, address};
//!
//! // Sepolia GPv2Settlement deployment.
//! let domain = DomainSeparator::new(
//!     11_155_111,
//!     address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
//! );
//!
//! let order = OrderData {
//!     sell_token: Address::ZERO,
//!     buy_token: Address::ZERO,
//!     sell_amount: U256::from(1_000_000_u64),
//!     buy_amount: U256::from(1_000_000_u64),
//!     valid_to: 1_700_000_000,
//!     app_data: AppDataHash::default(),
//!     fee_amount: U256::ZERO,
//!     kind: OrderKind::Sell,
//!     partially_fillable: false,
//!     sell_token_balance: SellTokenSource::Erc20,
//!     buy_token_balance: BuyTokenDestination::Erc20,
//!     receiver: None,
//! };
//!
//! let uid = order.uid(&domain, Address::ZERO);
//! assert_eq!(uid.0.len(), 56);
//! ```
//!
//! ## Parity references
//!
//! - [`cowprotocol/cow-sdk`](https://github.com/cowprotocol/cow-sdk) (TypeScript, canonical)
//! - [`cowdao-grants/cow-py`](https://github.com/cowdao-grants/cow-py) (Python)
//! - [`cowprotocol/services`](https://github.com/cowprotocol/services) (Rust, server-side)
//!
//! ## Licence
//!
//! GPL-3.0-or-later, matching the upstream `cowdao-grants/cow-rs` repository.
//! Portions of the source are adapted from [`cowprotocol/services`] under its
//! MIT OR Apache-2.0 licence.
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services

pub mod app_data;
pub mod bytes_hex;
pub mod domain;
pub mod order;

pub use crate::{
    app_data::AppDataHash,
    domain::{DomainSeparator, hashed_eip712_message},
    order::{
        BUY_ETH_ADDRESS, BuyTokenDestination, OrderData, OrderKind, OrderUid, SellTokenSource,
    },
};
