//! Ergonomic [`OrderBookApi`] constructors and their type-state builder.
//!
//! This module is gated behind the `http-client` feature; the
//! transport-generic [`OrderBookApi`], its endpoint logic, and the
//! quote pipeline live in the feature-independent
//! [`api`](super::api) / [`flow`](super::flow) siblings. The reqwest
//! [`HttpTransport`](crate::transport::HttpTransport) backend lives in
//! [`crate::transport`].

use crate::chain::Chain;
use crate::transport::ReqwestTransport;

use super::api::OrderBookApi;
use super::builder_state;

/// Type-state builder for [`OrderBookApi`].
#[derive(Debug, Clone)]
pub struct OrderBookApiBuilder<Target = builder_state::Missing> {
    chain: Option<Chain>,
    base_url: Option<url::Url>,
    client: Option<reqwest::Client>,
    _state: core::marker::PhantomData<Target>,
}

impl OrderBookApiBuilder {
    const fn new() -> Self {
        Self {
            chain: None,
            base_url: None,
            client: None,
            _state: core::marker::PhantomData,
        }
    }
}

impl<Target> OrderBookApiBuilder<Target> {
    fn cast<NextTarget>(self) -> OrderBookApiBuilder<NextTarget> {
        OrderBookApiBuilder {
            chain: self.chain,
            base_url: self.base_url,
            client: self.client,
            _state: core::marker::PhantomData,
        }
    }

    /// Use a pre-configured [`reqwest::Client`] for the orderbook API.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Target the production orderbook for a supported chain.
    pub fn with_chain(self, chain: Chain) -> OrderBookApiBuilder<builder_state::Set> {
        let mut next = self.cast::<builder_state::Set>();
        next.chain = Some(chain);
        next.base_url = Some(chain.orderbook_base_url());
        next
    }

    /// Target an arbitrary orderbook base URL, such as barn or a mock.
    pub fn with_base_url(self, base_url: url::Url) -> OrderBookApiBuilder<builder_state::Set> {
        let mut next = self.cast::<builder_state::Set>();
        next.chain = None;
        next.base_url = Some(base_url);
        next
    }
}

impl OrderBookApiBuilder<builder_state::Set> {
    /// Build the [`OrderBookApi`].
    pub fn build(self) -> OrderBookApi {
        let base_url = self.base_url.expect("target typestate sets base_url");
        let transport = self
            .client
            .map_or_else(ReqwestTransport::default, ReqwestTransport::new);
        let api = OrderBookApi::new_with_transport(base_url, transport);
        match self.chain {
            Some(chain) => api.with_chain_hint(chain),
            None => api,
        }
    }
}

impl OrderBookApi<ReqwestTransport> {
    /// Start a type-state builder for an orderbook client.
    pub const fn builder() -> OrderBookApiBuilder {
        OrderBookApiBuilder::new()
    }

    /// Start a type-state builder targeting the production orderbook on `chain`.
    pub fn with_chain(chain: Chain) -> OrderBookApiBuilder<builder_state::Set> {
        Self::builder().with_chain(chain)
    }

    /// Client for the production orderbook on `chain`.
    /// [`Chain::orderbook_base_url`] already includes the trailing slash
    /// [`url::Url::join`] needs to append, not replace, path segments.
    pub fn new(chain: Chain) -> Self {
        Self::new_with_transport(chain.orderbook_base_url(), ReqwestTransport::default())
            .with_chain_hint(chain)
    }

    /// Client against an arbitrary base URL (staging, recorded mock,
    /// etc.). The default reqwest client enforces
    /// [`DEFAULT_HTTP_TIMEOUT`]. The chain is left unknown; prefer
    /// [`Self::new`] when targeting a production chain so the quote
    /// pipeline can infer the signing domain and cross-check it.
    ///
    /// [`DEFAULT_HTTP_TIMEOUT`]: super::DEFAULT_HTTP_TIMEOUT
    pub fn new_with_base_url(base_url: url::Url) -> Self {
        Self::new_with_transport(base_url, ReqwestTransport::default())
    }

    /// Client around a pre-configured [`reqwest::Client`]. Use for
    /// custom timeouts, proxies, TLS roots, or auth middleware.
    pub fn with_client(base_url: url::Url, client: reqwest::Client) -> Self {
        Self::new_with_transport(base_url, ReqwestTransport::new(client))
    }
}
