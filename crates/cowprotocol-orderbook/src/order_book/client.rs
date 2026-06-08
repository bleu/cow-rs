//! The reqwest [`HttpTransport`] backend, the ergonomic [`OrderBookApi`]
//! constructors, and the typed quote builders.
//!
//! This module is gated behind the `http-client` feature; the
//! transport-generic [`OrderBookApi`] and its endpoint logic live in the
//! feature-independent [`api`](super::api) sibling.

use alloy_primitives::{Address, U256, keccak256};

use crate::app_data::{AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON};
use crate::chain::Chain;
use crate::error::{Error, Result};
use crate::order::OrderUid;
use crate::signing_scheme::EcdsaSigningScheme;
use crate::transport::{HttpMethod, HttpRequest, HttpResponse, HttpTransport};

use super::api::OrderBookApi;
use super::orders::OrderCreation;
use super::quote::{OrderQuoteResponse, QuoteRequest, QuoteRequestBuilder, builder_state};
use super::types::QuoteAppData;
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

    /// Start a type-state quote builder bound to this client.
    pub fn quote_builder(&self) -> OrderBookQuoteBuilder {
        OrderBookQuoteBuilder::new(self.clone(), QuoteRequest::builder(), CostParams::default())
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

/// Partner-fee, slippage, and protocol-fee inputs threaded from the quote
/// builder into [`QuotedOrder::sign`]. Defaults match
/// [`crate::SwapOrder::eip712`] (50 bps slippage, no partner fee), so the
/// fluent path applies the same protection [`crate::TradingClient`] does
/// rather than signing the raw quote.
#[derive(Debug, Clone)]
struct CostParams {
    partner_fee_bps: u32,
    slippage_bps: u32,
    protocol_fee_bps_override: Option<String>,
}

impl Default for CostParams {
    fn default() -> Self {
        Self {
            partner_fee_bps: 0,
            slippage_bps: 50,
            protocol_fee_bps_override: None,
        }
    }
}

/// Type-state quote builder bound to an [`OrderBookApi`].
#[derive(Debug, Clone)]
pub struct OrderBookQuoteBuilder<
    SellToken = builder_state::Missing,
    BuyToken = builder_state::Missing,
    From = builder_state::Missing,
    Amount = builder_state::Missing,
> {
    api: OrderBookApi,
    request: QuoteRequestBuilder<SellToken, BuyToken, From, Amount>,
    costs: CostParams,
}

impl<SellToken, BuyToken, From, Amount> OrderBookQuoteBuilder<SellToken, BuyToken, From, Amount> {
    const fn new(
        api: OrderBookApi,
        request: QuoteRequestBuilder<SellToken, BuyToken, From, Amount>,
        costs: CostParams,
    ) -> Self {
        Self {
            api,
            request,
            costs,
        }
    }

    /// Set the token the owner sells.
    pub fn with_sell_token(
        self,
        sell_token: Address,
    ) -> OrderBookQuoteBuilder<builder_state::Set, BuyToken, From, Amount> {
        OrderBookQuoteBuilder::new(
            self.api,
            self.request.with_sell_token(sell_token),
            self.costs,
        )
    }

    /// Set the token the owner buys.
    pub fn with_buy_token(
        self,
        buy_token: Address,
    ) -> OrderBookQuoteBuilder<SellToken, builder_state::Set, From, Amount> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_buy_token(buy_token), self.costs)
    }

    /// Set the order owner.
    pub fn with_from(
        self,
        from: Address,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, builder_state::Set, Amount> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_from(from), self.costs)
    }

    /// Set a sell-side quote amount before fee deduction.
    pub fn with_sell_amount(
        self,
        sell_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(
            self.api,
            self.request.with_sell_amount(sell_amount),
            self.costs,
        )
    }

    /// Set a sell-side quote amount before fee deduction.
    pub fn with_sell_amount_before_fee(
        self,
        sell_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(
            self.api,
            self.request.with_sell_amount_before_fee(sell_amount),
            self.costs,
        )
    }

    /// Set a sell-side quote amount after fee deduction.
    pub fn with_sell_amount_after_fee(
        self,
        sell_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(
            self.api,
            self.request.with_sell_amount_after_fee(sell_amount),
            self.costs,
        )
    }

    /// Set a buy-side quote amount after fee deduction.
    pub fn with_buy_amount_after_fee(
        self,
        buy_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(
            self.api,
            self.request.with_buy_amount_after_fee(buy_amount),
            self.costs,
        )
    }

    /// Apply optional request settings through the inner
    /// [`QuoteRequestBuilder`] without this api-bound builder having to
    /// re-declare every setter. The closure receives the request builder
    /// in its current type-state and must return it in the same state, so
    /// the required-field tracking that gates [`Self::build`] is preserved.
    /// Use it for receiver, expiry (`with_valid_to` / `with_valid_for`),
    /// app-data, balances, signing scheme, partial-fill, gas limit and
    /// price-quality hints, for example
    /// `.configure(|q| q.with_valid_for(1800).with_partially_fillable(true))`.
    pub fn configure(
        mut self,
        f: impl FnOnce(
            QuoteRequestBuilder<SellToken, BuyToken, From, Amount>,
        ) -> QuoteRequestBuilder<SellToken, BuyToken, From, Amount>,
    ) -> Self {
        self.request = f(self.request);
        self
    }

    /// Slippage tolerance in basis points, applied to the non-fixed side of
    /// the signed order (`buy_amount` for SELL, `sell_amount` for BUY).
    /// Defaults to 50 bps; pass `0` to sign the raw quote with no slippage.
    pub const fn with_slippage_bps(mut self, bps: u32) -> Self {
        self.costs.slippage_bps = bps;
        self
    }

    /// Partner-fee tier in basis points, charged on the surplus side.
    /// Defaults to `0` (no partner fee).
    pub const fn with_partner_fee_bps(mut self, bps: u32) -> Self {
        self.costs.partner_fee_bps = bps;
        self
    }

    /// Override the `protocolFeeBps` echoed by the quote response (decimal
    /// string, e.g. `"0.3"`). Defaults to the value the quote reports.
    pub fn with_protocol_fee_bps_override(mut self, value: impl Into<String>) -> Self {
        self.costs.protocol_fee_bps_override = Some(value.into());
        self
    }
}

impl
    OrderBookQuoteBuilder<
        builder_state::Set,
        builder_state::Set,
        builder_state::Set,
        builder_state::Set,
    >
{
    /// Build the request DTO without sending it.
    pub fn build_request(self) -> QuoteRequest {
        self.request.build_request()
    }

    /// Send the quote request and keep enough context to bind, sign, and submit it.
    pub async fn build(self) -> Result<QuotedOrder> {
        let request = self.request.build_request();
        let (app_data_hash, app_data_json) = app_data_for_submission(&request);
        let response = self.api.quote(&request).await?;
        Ok(QuotedOrder {
            api: self.api,
            request,
            response,
            app_data_hash,
            app_data_json,
            costs: self.costs,
        })
    }
}

/// Quote response plus the request context needed to sign and submit it safely.
#[derive(Debug, Clone)]
pub struct QuotedOrder {
    api: OrderBookApi,
    request: QuoteRequest,
    response: OrderQuoteResponse,
    app_data_hash: AppDataHash,
    app_data_json: Option<String>,
    costs: CostParams,
}

impl QuotedOrder {
    /// Request that produced this quote.
    pub const fn request(&self) -> &QuoteRequest {
        &self.request
    }

    /// Raw orderbook quote response.
    pub const fn response(&self) -> &OrderQuoteResponse {
        &self.response
    }

    /// Consume the context and return the raw orderbook quote response.
    pub fn into_response(self) -> OrderQuoteResponse {
        self.response
    }

    /// Sign with EIP-712 using the chain attached to the [`OrderBookApi`].
    ///
    /// The signed amounts apply the builder's partner-fee, protocol-fee and
    /// slippage composition (defaulting to 50 bps slippage, no partner fee,
    /// matching [`crate::TradingClient`]); set them via the quote builder's
    /// `with_slippage_bps` / `with_partner_fee_bps`.
    pub fn sign<S: alloy_signer::SignerSync>(&self, signer: &S) -> Result<SignedOrderSubmission> {
        self.sign_with_scheme(EcdsaSigningScheme::Eip712, signer)
    }

    /// Sign with an ECDSA scheme using the chain attached to the [`OrderBookApi`].
    pub fn sign_with_scheme<S: alloy_signer::SignerSync>(
        &self,
        scheme: EcdsaSigningScheme,
        signer: &S,
    ) -> Result<SignedOrderSubmission> {
        let chain = self.api.chain().ok_or(Error::OrderCreationInvalid {
            field: "chain",
            reason: "quote builder can only infer the signing domain when OrderBookApi was built with a chain; use sign_for_chain",
        })?;
        self.sign_for_chain(chain, scheme, signer)
    }

    /// Sign with an explicit chain, useful for clients built from custom URLs.
    pub fn sign_for_chain<S: alloy_signer::SignerSync>(
        &self,
        chain: Chain,
        scheme: EcdsaSigningScheme,
        signer: &S,
    ) -> Result<SignedOrderSubmission> {
        let order_data = self.response.try_into_signed_order_data_with_costs(
            &self.request,
            self.costs.partner_fee_bps,
            self.costs.slippage_bps,
            self.costs.protocol_fee_bps_override.as_deref(),
            self.app_data_hash,
        )?;
        let signature = order_data.sign(scheme, &chain.settlement_domain(), signer)?;
        let app_data_json = self.app_data_json.clone().ok_or(Error::OrderCreationInvalid {
            field: "app_data",
            reason: "full app-data JSON is required to submit a quote pinned by a non-empty hash",
        })?;
        let order = OrderCreation::from_signed_order_data(
            &order_data,
            signature,
            self.response.from,
            app_data_json,
            Some(self.response.id),
        )?;
        Ok(SignedOrderSubmission {
            api: self.api.clone(),
            order,
        })
    }
}

/// Signed order plus the orderbook client that should receive it.
#[derive(Debug, Clone)]
pub struct SignedOrderSubmission {
    api: OrderBookApi,
    order: OrderCreation,
}

impl SignedOrderSubmission {
    /// Wire body that will be posted.
    pub const fn order(&self) -> &OrderCreation {
        &self.order
    }

    /// Submit the signed order to `POST /api/v1/orders`.
    pub async fn submit(&self) -> Result<OrderUid> {
        self.api.post_order(&self.order).await
    }
}

fn app_data_for_submission(request: &QuoteRequest) -> (AppDataHash, Option<String>) {
    match request.app_data.as_ref() {
        Some(QuoteAppData::Hash(hash)) if *hash == EMPTY_APP_DATA_HASH => {
            (*hash, Some(EMPTY_APP_DATA_JSON.to_owned()))
        }
        Some(QuoteAppData::Hash(hash)) => (*hash, None),
        Some(QuoteAppData::Full(json)) => (keccak256(json.as_bytes()), Some(json.clone())),
        None => (EMPTY_APP_DATA_HASH, Some(EMPTY_APP_DATA_JSON.to_owned())),
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
