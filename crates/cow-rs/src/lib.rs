//! # cow-rs
//!
//! Rust SDK for the [CoW Protocol](https://cow.fi).
//!
//! Public surface so far:
//!
//! - [`OrderData`] — the 12-field signed payload, with
//!   [`OrderData::hash_struct`] for EIP-712 hashing and
//!   [`OrderData::uid`] for the 56-byte order identifier.
//! - [`DomainSeparator`] and [`hashed_eip712_message`] for the typed-data
//!   envelope.
//! - [`Chain`] — the five chains the CoW orderbook supports, with their
//!   `api.cow.fi` URL slugs.
//! - [`OrderBookApi`] — async client for `POST /api/v1/quote`.
//!
//! Everything else (signing, order submission, contract bindings, app-data
//! schema, subgraph, composable orders) will land in subsequent commits so
//! each addition can be reviewed in isolation.
//!
//! ## Quote example
//!
//! ```no_run
//! use cow_rs::{Chain, OrderBookApi, QuoteRequest};
//! use alloy_primitives::{Address, U256, address};
//!
//! # async fn run() -> cow_rs::Result<()> {
//! let api = OrderBookApi::new(Chain::Mainnet);
//! let request = QuoteRequest::sell_amount_before_fee(
//!     address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), // USDC
//!     address!("6B175474E89094C44Da98b954EedeAC495271d0F"), // DAI
//!     address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
//!     U256::from(100_000_000_u64),
//! );
//! let response = api.get_quote(&request).await?;
//! println!("buy amount: {}", response.quote.buy_amount);
//! # Ok(()) }
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
pub mod cancellation;
pub mod chain;
pub mod domain;
pub mod error;
pub mod order;
pub mod order_book;
pub mod signature;
pub mod signing_scheme;

pub use crate::{
    app_data::{AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON},
    cancellation::{OrderCancellation, OrderCancellations, SignedOrderCancellations},
    chain::{Chain, UnsupportedChain},
    domain::{DomainSeparator, hashed_eip712_message, hashed_ethsign_message},
    error::{ApiError, Error, Result},
    order::{
        BUY_ETH_ADDRESS, BuyTokenDestination, Order, OrderClass, OrderData, OrderKind, OrderStatus,
        OrderUid, SellTokenSource,
    },
    order_book::{
        AuctionStatus, AuctionStatusType, OrderBookApi, OrderCreation, OrderQuote,
        OrderQuoteResponse, QuoteRequest,
    },
    signature::{EcdsaSignature, Recovered, Signature, SignatureError},
    signing_scheme::{EcdsaSigningScheme, SigningScheme},
};
