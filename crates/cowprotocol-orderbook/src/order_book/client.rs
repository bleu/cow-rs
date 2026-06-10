//! The reqwest [`HttpTransport`] backend and the ergonomic
//! [`OrderBookApi`] constructors.
//!
//! This module is gated behind the `http-client` feature; the
//! transport-generic [`OrderBookApi`], its endpoint logic, and the
//! quote pipeline live in the feature-independent
//! [`api`](super::api) / [`flow`](super::flow) siblings.

use crate::chain::Chain;
use crate::error::{Error, Result};
use crate::transport::{HttpMethod, HttpRequest, HttpResponse, HttpTransport};

use super::api::OrderBookApi;
use super::builder_state;
// Only consumed by the default reqwest client's `timeout`, gated out on wasm.
#[cfg(not(target_arch = "wasm32"))]
use super::DEFAULT_HTTP_TIMEOUT;

/// The reqwest-backed [`HttpTransport`]. Wraps a [`reqwest::Client`] and
/// applies the [`MAX_RESPONSE_BYTES`](super::MAX_RESPONSE_BYTES) body cap
/// as it reads each response.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Wrap a pre-configured [`reqwest::Client`]. Use for custom timeouts,
    /// proxies, TLS roots, or auth middleware.
    pub const fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// The default reqwest client, enforcing [`DEFAULT_HTTP_TIMEOUT`] on
    /// native targets (wasm defers to the browser's fetch timeout).
    fn default_client() -> reqwest::Client {
        // `ClientBuilder::timeout` is non-wasm32 only; the wasm backend
        // defers to the browser's fetch timeout.
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(DEFAULT_HTTP_TIMEOUT);
        builder.build().expect("reqwest defaults cannot fail")
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new(Self::default_client())
    }
}

impl HttpTransport for ReqwestTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(request.url),
            HttpMethod::Post => self.client.post(request.url),
            HttpMethod::Put => self.client.put(request.url),
            HttpMethod::Delete => self.client.delete(request.url),
        };
        if let Some(body) = request.json_body {
            builder = builder
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = builder.send().await?;
        let status = response.status().as_u16();
        let body = read_capped_text(response).await?;
        Ok(HttpResponse { status, body })
    }
}

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
    /// [`Self::new`] when targeting a production chain so
    /// [`crate::TradingClient::from_orderbook`] can cross-check it.
    pub fn new_with_base_url(base_url: url::Url) -> Self {
        Self::new_with_transport(base_url, ReqwestTransport::default())
    }

    /// Client around a pre-configured [`reqwest::Client`]. Use for
    /// custom timeouts, proxies, TLS roots, or auth middleware.
    pub fn with_client(base_url: url::Url, client: reqwest::Client) -> Self {
        Self::new_with_transport(base_url, ReqwestTransport::new(client))
    }
}

/// Read a response body as UTF-8 text, rejecting payloads above
/// [`MAX_RESPONSE_BYTES`]. Early-rejects on a declared `Content-Length`,
/// then bounds the body as it streams in (see [`read_capped_body`]) so a
/// chunked or length-less response cannot buffer past the cap before the
/// check fires.
///
/// [`MAX_RESPONSE_BYTES`]: super::MAX_RESPONSE_BYTES
async fn read_capped_text(response: reqwest::Response) -> Result<String> {
    if let Some(declared_len) = response.content_length()
        && declared_len > super::MAX_RESPONSE_BYTES as u64
    {
        return Err(Error::ResponseTooLarge {
            max: super::MAX_RESPONSE_BYTES,
        });
    }
    read_capped_body(response).await
}

/// Accumulate the body chunk-by-chunk, failing the moment the running
/// length would exceed [`MAX_RESPONSE_BYTES`]. This is the stream-bounded
/// guard the `Content-Length` early-reject cannot provide for chunked
/// transfers.
///
/// [`MAX_RESPONSE_BYTES`]: super::MAX_RESPONSE_BYTES
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn read_capped_body(mut response: reqwest::Response) -> Result<String> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > super::MAX_RESPONSE_BYTES {
            return Err(Error::ResponseTooLarge {
                max: super::MAX_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    // The orderbook always returns UTF-8 JSON; a non-UTF-8 body is
    // pathological and would fail the downstream `serde_json` parse
    // anyway, so a lossy decode is acceptable and avoids a panic.
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// wasm's `reqwest` backend has no streaming body API, so fall back to a
/// buffered read plus the post-read backstop. The `Content-Length`
/// early-reject in [`read_capped_text`] still applies.
///
/// [`MAX_RESPONSE_BYTES`]: super::MAX_RESPONSE_BYTES
#[cfg(target_arch = "wasm32")]
pub(crate) async fn read_capped_body(response: reqwest::Response) -> Result<String> {
    let text = response.text().await?;
    if text.len() > super::MAX_RESPONSE_BYTES {
        return Err(Error::ResponseTooLarge {
            max: super::MAX_RESPONSE_BYTES,
        });
    }
    Ok(text)
}
