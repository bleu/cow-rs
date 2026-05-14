//! # cow-rs
//!
//! Rust SDK for the [CoW Protocol](https://cow.fi).
//!
//! ## Surface
//!
//! - [`OrderData`]: the 12-field signed payload, with
//!   [`OrderData::hash_struct`] for EIP-712 hashing,
//!   [`OrderData::uid`] for the 56-byte order identifier and
//!   [`OrderData::sign`] for ECDSA signing.
//! - [`DomainSeparator`], [`hashed_eip712_message`] and
//!   [`hashed_ethsign_message`] for the typed-data envelope.
//! - [`Signature`], [`EcdsaSignature`] and [`SignatureError`] covering
//!   EIP-712, EthSign, EIP-1271 and PreSign schemes.
//! - [`Chain`]: all eleven chains the orderbook supports
//!   (Mainnet, Bnb, Gnosis, Polygon, Base, Plasma, Arbitrum One, Avalanche,
//!   Ink, Linea, Sepolia), with their `api.cow.fi` URL slugs.
//! - [`OrderBookApi`]: async client for the orderbook HTTP API, with
//!   methods for quoting, posting, lookup, cancellation, trade and account
//!   queries, native-price lookups and app-data pinning.
//! - [`OrderCreation`], [`OrderCancellation`] and [`OrderCancellations`]
//!   for the submission and cancellation flows.
//! - [`AppDataHash`] and [`AppDataDoc`] for the canonical metadata
//!   document and its keccak digest.
//! - [`EthFlowOrder`] plus the [`ETH_FLOW_PRODUCTION`] /
//!   [`ETH_FLOW_STAGING`] addresses for native-ETH sells via the
//!   periphery EthFlow contract.
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
//! See `examples/post_order.rs` for the full sign-and-submit flow on
//! Sepolia.
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
pub mod contracts;
pub mod domain;
pub mod error;
pub mod eth_flow;
pub mod order;
pub mod order_book;
pub mod signature;
pub mod signing_scheme;

pub use crate::{
    app_data::{
        AppDataDoc, AppDataHash, AppDataMetadata, AppDataOrderClass, AppDataPartnerFee,
        AppDataQuote, AppDataReferrer, AppDataUtm, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON,
        LATEST_APP_DATA_VERSION,
    },
    cancellation::{OrderCancellation, OrderCancellations, SignedOrderCancellations},
    chain::{Chain, UnsupportedChain},
    contracts::{ERC20, GPV2_SETTLEMENT, GPV2_VAULT_RELAYER, GPv2OrderData, GPv2Settlement, WETH9},
    domain::{DomainSeparator, hashed_eip712_message, hashed_ethsign_message},
    error::{ApiError, Error, Result},
    eth_flow::{ETH_FLOW_PRODUCTION, ETH_FLOW_STAGING, EthFlowOrder},
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
