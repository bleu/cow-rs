//! Type-state builder for [`OrderBookApi`].
//!
//! Reaches a callable [`OrderBookApiBuilder::build`] only after a target
//! (a [`Chain`] or an explicit base URL) has been pinned. The optional
//! [`reqwest::Client`] override can be supplied in any state and, when
//! omitted, the default client honours [`DEFAULT_HTTP_TIMEOUT`] on
//! native and the browser fetch timeout on wasm.
//!
//! ```no_run
//! use cowprotocol::{Chain, OrderBookApi};
//!
//! let api = OrderBookApi::with_chain(Chain::Mainnet).build();
//! # let _ = api;
//! ```

use std::marker::PhantomData;

use crate::chain::Chain;

use super::DEFAULT_HTTP_TIMEOUT;
use super::client::OrderBookApi;

/// Marker: no target has been set yet, so [`OrderBookApiBuilder::build`]
/// is not in scope.
#[derive(Debug)]
pub struct NoTarget;

/// Marker: a target ([`Chain`] or base URL) has been pinned.
#[derive(Debug)]
pub struct WithTarget;

enum Target {
    Chain(Chain),
    Url(url::Url),
}

impl core::fmt::Debug for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Chain(c) => f.debug_tuple("Chain").field(c).finish(),
            Self::Url(u) => f.debug_tuple("Url").field(&u.as_str()).finish(),
        }
    }
}

/// Type-state builder for [`OrderBookApi`].
///
/// Start with [`OrderBookApi::builder`] (no target yet), or jump
/// straight to a `WithTarget` builder via [`OrderBookApi::with_chain`]
/// or [`OrderBookApi::with_base_url`].
#[must_use = "OrderBookApiBuilder does nothing until build() is called"]
#[derive(Debug)]
pub struct OrderBookApiBuilder<State> {
    target: Option<Target>,
    client: Option<reqwest::Client>,
    _state: PhantomData<State>,
}

impl Default for OrderBookApiBuilder<NoTarget> {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderBookApiBuilder<NoTarget> {
    /// Empty builder with no target and the default HTTP client.
    pub const fn new() -> Self {
        Self {
            target: None,
            client: None,
            _state: PhantomData,
        }
    }

    /// Pin the target [`Chain`]. The resulting [`OrderBookApi::chain`]
    /// is `Some`, so [`crate::TradingClient::from_orderbook`] can
    /// cross-check signing-domain agreement.
    pub fn chain(self, chain: Chain) -> OrderBookApiBuilder<WithTarget> {
        OrderBookApiBuilder {
            target: Some(Target::Chain(chain)),
            client: self.client,
            _state: PhantomData,
        }
    }

    /// Pin an arbitrary base URL (staging, recorded mock, …). The
    /// resulting [`OrderBookApi::chain`] is `None`.
    pub fn base_url(self, base_url: url::Url) -> OrderBookApiBuilder<WithTarget> {
        OrderBookApiBuilder {
            target: Some(Target::Url(base_url)),
            client: self.client,
            _state: PhantomData,
        }
    }
}

impl<State> OrderBookApiBuilder<State> {
    /// Override the underlying [`reqwest::Client`]. Defaults to a fresh
    /// client with [`DEFAULT_HTTP_TIMEOUT`] applied on native.
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }
}

impl OrderBookApiBuilder<WithTarget> {
    /// Materialise the [`OrderBookApi`]. Available only once a target
    /// has been pinned via [`chain`] or [`base_url`].
    ///
    /// [`chain`]: OrderBookApiBuilder::<NoTarget>::chain
    /// [`base_url`]: OrderBookApiBuilder::<NoTarget>::base_url
    pub fn build(self) -> OrderBookApi {
        let client = self.client.unwrap_or_else(default_client);
        match self.target.expect("WithTarget guarantees Some") {
            Target::Chain(chain) => {
                OrderBookApi::from_parts(chain.orderbook_base_url(), client, Some(chain))
            }
            Target::Url(url) => OrderBookApi::from_parts(url, client, None),
        }
    }
}

fn default_client() -> reqwest::Client {
    // `ClientBuilder::timeout` is non-wasm32 only; the wasm backend
    // defers to the browser's fetch timeout.
    let builder = reqwest::Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder.timeout(DEFAULT_HTTP_TIMEOUT);
    builder.build().expect("reqwest defaults cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_with_chain_matches_new() {
        let from_builder = OrderBookApi::with_chain(Chain::Mainnet).build();
        let from_new = OrderBookApi::new(Chain::Mainnet);
        assert_eq!(from_builder.base_url(), from_new.base_url());
        assert_eq!(from_builder.chain(), from_new.chain());
    }

    #[test]
    fn builder_with_base_url_matches_new_with_base_url() {
        let url: url::Url = "https://staging.cow.fi/".parse().unwrap();
        let from_builder = OrderBookApi::builder().base_url(url.clone()).build();
        let from_new = OrderBookApi::new_with_base_url(url);
        assert_eq!(from_builder.base_url(), from_new.base_url());
        assert_eq!(from_builder.chain(), None);
        assert_eq!(from_new.chain(), None);
    }

    #[test]
    fn builder_client_override_preserved() {
        let custom = reqwest::Client::builder().build().unwrap();
        let api = OrderBookApi::with_chain(Chain::Gnosis).client(custom).build();
        assert_eq!(api.chain(), Some(Chain::Gnosis));
    }
}
