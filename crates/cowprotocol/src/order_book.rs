//! Thin client for the CoW Protocol orderbook HTTP API.
//!
//! The first endpoint implemented here is [`OrderBookApi::quote`],
//! which mirrors the `getQuote` flow exposed by `@cowprotocol/cow-sdk`
//! and `cow-py`. The request and response shapes reflect the
//! production orderbook OpenAPI as of 2026-05.

use std::time::Duration;

/// Default per-request timeout. A stuck or hostile orderbook cannot
/// hold a caller's task open longer; override via
/// [`OrderBookApi::with_client`]. Exposed feature-independently so the
/// `cow-sdk-wasm` fetch transport can reuse it without pulling in the
/// `http-client` stack.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum HTTP response body. Larger payloads return
/// [`Error::ResponseTooLarge`] before allocating. Exposed
/// feature-independently so the `cow-sdk-wasm` fetch transport can reuse
/// it without pulling in the `http-client` stack.
///
/// [`Error::ResponseTooLarge`]: crate::Error::ResponseTooLarge
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

mod types;
pub use types::*;

mod quote;
pub use quote::*;

mod builder;
pub use builder::{Missing, QuoteRequestBuilder, Set};

mod orders;
pub use orders::OrderCreation;

#[cfg(feature = "http-client")]
mod client;
#[cfg(feature = "http-client")]
pub use client::OrderBookApi;

#[cfg(feature = "http-client")]
mod api_builder;
#[cfg(feature = "http-client")]
pub use api_builder::{NoTarget, OrderBookApiBuilder, WithTarget};

#[cfg(test)]
#[path = "order_book/tests.rs"]
mod tests;
