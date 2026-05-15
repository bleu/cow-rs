//! # cowprotocol
//!
//! Crate name on crates.io. Hosted at
//! [`cowdao-grants/cow-rs`](https://github.com/cowdao-grants/cow-rs).
//!
//! Rust SDK for the [CoW Protocol](https://cow.fi).
//!
//! ## What this crate exposes
//!
//! - [`OrderData`]: the 12-field signed payload, with
//!   [`OrderData::hash_struct`] for EIP-712 hashing,
//!   [`OrderData::uid`] for the 56-byte order identifier and
//!   [`OrderData::sign`] for ECDSA signing.
//! - [`DomainSeparator`] (a type alias for
//!   [`alloy_sol_types::Eip712Domain`]) and [`settlement_domain`] for the
//!   `GPv2Settlement` EIP-712 domain. The typed-data envelope is supplied
//!   by [`alloy_sol_types::SolStruct`] and the EIP-191 personal-sign wrap
//!   by [`alloy_primitives::eip191_hash_message`].
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
//! - [`GPv2Settlement`] and [`GPv2OrderData`] for typed contract bindings,
//!   plus [`GPV2_SETTLEMENT`], [`GPV2_VAULT_RELAYER`], [`WETH9`] and
//!   [`ERC20`] address constants.
//! - [`ConditionalOrderParams`], [`Proof`] and [`PollOutcome`] for the
//!   `ComposableCoW` conditional-order primitives, plus the
//!   [`COMPOSABLE_COW`], [`EXTENSIBLE_FALLBACK_HANDLER`] and
//!   [`CURRENT_BLOCK_TIMESTAMP_FACTORY`] address constants.
//! - [`TwapData`] / [`TwapStaticInput`] for the canonical TWAP handler
//!   `staticInput`, locked byte-conformant against cow-py's
//!   `test_twap.py` vector.
//! - [`Multiplexer`] plus [`conditional_order_leaf`] / [`verify_proof`]
//!   for batched conditional orders behind a single
//!   `ComposableCoW.setRoot`, matching the contract's OpenZeppelin
//!   sorted-pair merkle proof verifier exactly.
//!
//! ## Quote example
//!
//! ```no_run
//! use cowprotocol::{Chain, OrderBookApi, QuoteRequest};
//! use alloy_primitives::{Address, U256, address};
//!
//! # async fn run() -> cowprotocol::Result<()> {
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

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

// `getrandom` is a wasm-only build-time dep that wires alloy's PRNG
// into the browser's `crypto.getRandomValues` via its `js` feature.
// Nothing in this crate references the crate directly; this `as _`
// import keeps `unused_crate_dependencies` quiet on the wasm32 target.
#[cfg(target_arch = "wasm32")]
use getrandom as _;

pub mod app_data;
pub mod cancellation;
pub mod chain;
pub mod composable;
pub mod contracts;
pub mod domain;
pub mod error;
pub mod eth_flow;
pub mod multiplexer;
pub mod order;
pub mod order_book;
pub mod quote_amounts;
pub mod signature;
pub mod signing_scheme;
#[cfg(feature = "subgraph")]
pub mod subgraph;
pub mod trading;

pub use crate::{
    app_data::{
        AppDataCid, AppDataCidError, AppDataDoc, AppDataFlashloan, AppDataHash, AppDataMetadata,
        AppDataOrderClass, AppDataPartnerFee, AppDataQuote, AppDataReferrer, AppDataReplacedOrder,
        AppDataUtm, AppDataWrapperCall, COW_RS_APP_CODE, COW_RS_WASM_APP_CODE, EMPTY_APP_DATA_HASH,
        EMPTY_APP_DATA_JSON, FeePolicy, LATEST_APP_DATA_VERSION,
    },
    cancellation::{OrderCancellation, OrderCancellations, SignedOrderCancellations},
    chain::{Chain, UnsupportedChain},
    composable::{
        COMPOSABLE_COW, CURRENT_BLOCK_TIMESTAMP_FACTORY, ComposableCoW, ConditionalOrderParams,
        EXTENSIBLE_FALLBACK_HANDLER, PollOutcome, Proof, TWAP_HANDLER, TwapData, TwapDuration,
        TwapError, TwapStart, TwapStaticInput,
    },
    contracts::{
        CoWSwapOnchainOrders, ERC20, GPV2_SETTLEMENT, GPV2_VAULT_RELAYER, GPv2OrderData,
        GPv2Settlement, OnchainSignature, OnchainSigningScheme, WETH9,
    },
    domain::{DomainSeparator, settlement_domain},
    error::{ApiError, Error, Result},
    eth_flow::{ETH_FLOW_PRODUCTION, ETH_FLOW_STAGING, EthFlowOrder},
    multiplexer::{Multiplexer, MultiplexerError, conditional_order_leaf, verify_proof},
    order::{
        BUY_ETH_ADDRESS, BuyTokenDestination, Order, OrderBuilder, OrderClass, OrderData,
        OrderKind, OrderStatus, OrderUid, SellTokenSource,
    },
    order_book::{
        AppDataDocument, Auction, AuctionStatus, AuctionStatusType, NativePrice, OrderBookApi,
        OrderCreation, OrderQuote, OrderQuoteResponse, PriceQuality, QuoteRequest, TokenMetadata,
        TotalSurplus, Trade,
    },
    quote_amounts::{
        Amounts as QuoteAmounts, QuoteAmountsAndCosts, QuoteAmountsParams, QuoteCosts,
    },
    signature::{EcdsaSignature, Recovered, Signature, SignatureError},
    signing_scheme::{EcdsaSigningScheme, SigningScheme},
    trading::{PostedSwapOrder, SwapOrder, TradingClient},
};

#[cfg(feature = "subgraph")]
pub use crate::subgraph::{
    ChainSubgraphUnavailable, DailyTotal, GraphQlError, HourlyTotal, SubgraphClient, SubgraphError,
    Totals,
};
