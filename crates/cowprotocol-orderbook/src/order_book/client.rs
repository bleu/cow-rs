//! [`OrderBookApi`]: the HTTP client for the CoW Protocol orderbook and
//! the request/response plumbing behind its endpoints.
//!
//! This module is gated behind the `http-client` feature; the DTO types
//! it returns live in the feature-independent sibling modules.

use alloy_primitives::{Address, B256, U256, keccak256};
use serde::{Deserialize, Serialize};

use crate::app_data::{AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON};
use crate::cancellation::{SignedOrderCancellation, SignedOrderCancellations};
use crate::chain::Chain;
use crate::error::{ApiError, Error, Result};
use crate::order::{Order, OrderUid};
use crate::signature::{EcdsaSignature, ecdsa_wire};
use crate::signing_scheme::EcdsaSigningScheme;

use super::MAX_RESPONSE_BYTES;
use super::orders::OrderCreation;
use super::quote::{OrderQuoteResponse, QuoteRequest, QuoteRequestBuilder, builder_state};
use super::types::{
    AppDataDocument, Auction, AuctionStatus, NativePrice, QuoteAppData, TokenMetadata,
    TotalSurplus, Trade,
};
// Only consumed by `ClientBuilder::timeout`, which is gated out on wasm.
#[cfg(not(target_arch = "wasm32"))]
use super::DEFAULT_HTTP_TIMEOUT;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrdersByUidsRequest<'a> {
    pub(crate) order_uids: &'a [OrderUid],
}

/// Wire body for `DELETE /api/v1/orders/{uid}`. The UID lives in the URL,
/// so the body is just the signature material; this mirrors the upstream
/// `CancellationPayload` shape in `cowprotocol/services/crates/model/
/// src/order.rs`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancellationPayload {
    #[serde(with = "ecdsa_wire")]
    signature: EcdsaSignature,
    signing_scheme: EcdsaSigningScheme,
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
        match self.client {
            Some(client) => OrderBookApi {
                base_url: ensure_trailing_slash(base_url),
                client,
                chain: self.chain,
            },
            None => {
                let mut api = OrderBookApi::new_with_base_url(base_url);
                api.chain = self.chain;
                api
            }
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
}

impl<SellToken, BuyToken, From, Amount> OrderBookQuoteBuilder<SellToken, BuyToken, From, Amount> {
    const fn new(
        api: OrderBookApi,
        request: QuoteRequestBuilder<SellToken, BuyToken, From, Amount>,
    ) -> Self {
        Self { api, request }
    }

    /// Set the token the owner sells.
    pub fn with_sell_token(
        self,
        sell_token: Address,
    ) -> OrderBookQuoteBuilder<builder_state::Set, BuyToken, From, Amount> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_sell_token(sell_token))
    }

    /// Set the token the owner buys.
    pub fn with_buy_token(
        self,
        buy_token: Address,
    ) -> OrderBookQuoteBuilder<SellToken, builder_state::Set, From, Amount> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_buy_token(buy_token))
    }

    /// Set the order owner.
    pub fn with_from(
        self,
        from: Address,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, builder_state::Set, Amount> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_from(from))
    }

    /// Set a sell-side quote amount before fee deduction.
    pub fn with_sell_amount(
        self,
        sell_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_sell_amount(sell_amount))
    }

    /// Set a sell-side quote amount before fee deduction.
    pub fn with_sell_amount_before_fee(
        self,
        sell_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(
            self.api,
            self.request.with_sell_amount_before_fee(sell_amount),
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
        )
    }

    /// Set a buy-side quote amount after fee deduction.
    pub fn with_buy_amount_after_fee(
        self,
        buy_amount: U256,
    ) -> OrderBookQuoteBuilder<SellToken, BuyToken, From, builder_state::Set> {
        OrderBookQuoteBuilder::new(self.api, self.request.with_buy_amount_after_fee(buy_amount))
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
    pub fn sign<S: alloy_signer::SignerSync>(&self, signer: &S) -> Result<SignedOrderSubmission> {
        self.sign_with_scheme(EcdsaSigningScheme::Eip712, signer)
    }

    /// Sign with an ECDSA scheme using the chain attached to the [`OrderBookApi`].
    pub fn sign_with_scheme<S: alloy_signer::SignerSync>(
        &self,
        scheme: EcdsaSigningScheme,
        signer: &S,
    ) -> Result<SignedOrderSubmission> {
        let chain = self.api.chain.ok_or(Error::OrderCreationInvalid {
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
        let order_data = self
            .response
            .try_into_signed_order_data(&self.request, self.app_data_hash)?;
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

/// Thin client for the CoW Protocol orderbook.
#[derive(Debug, Clone)]
pub struct OrderBookApi {
    base_url: url::Url,
    client: reqwest::Client,
    // `Some` when built from a [`Chain`] via [`Self::new`]; `None` when
    // built from an arbitrary URL (staging / mock), where the chain is
    // not known. [`crate::TradingClient::from_orderbook`] uses it to
    // refuse a chain that disagrees with the signing domain.
    chain: Option<Chain>,
}

impl OrderBookApi {
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
        OrderBookQuoteBuilder::new(self.clone(), QuoteRequest::builder())
    }

    /// Client for the production orderbook on `chain`.
    /// [`Chain::orderbook_base_url`] already includes the trailing slash
    /// [`url::Url::join`] needs to append, not replace, path segments.
    pub fn new(chain: Chain) -> Self {
        let mut api = Self::new_with_base_url(chain.orderbook_base_url());
        api.chain = Some(chain);
        api
    }

    /// Client against an arbitrary base URL (staging, recorded mock,
    /// etc.). The default reqwest client enforces
    /// [`DEFAULT_HTTP_TIMEOUT`]. The chain is left unknown; prefer
    /// [`Self::new`] when targeting a production chain so
    /// [`crate::TradingClient::from_orderbook`] can cross-check it.
    pub fn new_with_base_url(base_url: url::Url) -> Self {
        // `ClientBuilder::timeout` is non-wasm32 only; the wasm
        // backend defers to the browser's fetch timeout.
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(DEFAULT_HTTP_TIMEOUT);
        let client = builder.build().expect("reqwest defaults cannot fail");
        Self::with_client(base_url, client)
    }

    /// Client around a pre-configured [`reqwest::Client`]. Use for
    /// custom timeouts, proxies, TLS roots, or auth middleware.
    pub fn with_client(base_url: url::Url, client: reqwest::Client) -> Self {
        Self {
            base_url: ensure_trailing_slash(base_url),
            client,
            chain: None,
        }
    }

    /// Base URL with the trailing slash path joining relies on.
    pub const fn base_url(&self) -> &url::Url {
        &self.base_url
    }

    /// The [`Chain`] this client targets, when known. `Some` only when
    /// built via [`Self::new`]; arbitrary-URL constructors leave it
    /// `None`.
    pub const fn chain(&self) -> Option<Chain> {
        self.chain
    }

    /// `POST /api/v1/quote`. Rejects an inconsistent request via
    /// [`QuoteRequest::validate`] before issuing it.
    pub async fn quote(&self, request: &QuoteRequest) -> Result<OrderQuoteResponse> {
        request.validate()?;
        self.post_json("api/v1/quote", request).await
    }

    /// `POST /api/v1/orders`. Returns the assigned 56-byte UID.
    pub async fn post_order(&self, order: &OrderCreation) -> Result<OrderUid> {
        self.post_json("api/v1/orders", order).await
    }

    /// `GET /api/v1/orders/{uid}`.
    pub async fn order(&self, uid: &OrderUid) -> Result<Order> {
        self.get_json(&format!("api/v1/orders/{uid}")).await
    }

    /// `GET /api/v1/orders/{uid}/status`.
    pub async fn order_status(&self, uid: &OrderUid) -> Result<AuctionStatus> {
        self.get_json(&format!("api/v1/orders/{uid}/status")).await
    }

    /// Poll [`Self::order`] until `should_stop` returns `true`,
    /// sleeping via the caller-supplied closure. Runtime-agnostic;
    /// pass `tokio::time::sleep`, `gloo_timers::future::sleep`, or
    /// any `Future<Output = ()>` producer. Callers wanting a deadline
    /// bake it into `should_stop`.
    pub async fn poll_until<P, S, Fut>(
        &self,
        uid: &OrderUid,
        mut should_stop: P,
        mut sleep: S,
    ) -> Result<Order>
    where
        P: FnMut(&Order) -> bool,
        S: FnMut() -> Fut,
        Fut: core::future::Future<Output = ()>,
    {
        loop {
            let order = self.order(uid).await?;
            if should_stop(&order) {
                return Ok(order);
            }
            sleep().await;
        }
    }

    /// `GET /api/v1/account/{owner}/orders`. Most recent first. Pass
    /// `None` for both pagers to use the server defaults.
    pub async fn account_orders(
        &self,
        owner: Address,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<Order>> {
        self.get_json_with_query(
            &format!("api/v1/account/{owner:?}/orders"),
            &[],
            offset,
            limit,
        )
        .await
    }

    /// `POST /api/v1/orders/by_uids`. Returns orders in request
    /// order; unknown UIDs are omitted.
    pub async fn orders_by_uids(&self, uids: &[OrderUid]) -> Result<Vec<Order>> {
        self.post_json(
            "api/v1/orders/by_uids",
            &OrdersByUidsRequest { order_uids: uids },
        )
        .await
    }

    /// `GET /api/v2/trades?owner=...`. Newest first. Pass `None` for both
    /// pagers to use the server defaults (`offset` 0, `limit` 10); the
    /// server caps `limit` at 1000. v2 replaces the deprecated,
    /// unpaginated v1 endpoint.
    pub async fn trades_by_owner(
        &self,
        owner: Address,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<Trade>> {
        self.get_json_with_query(
            "api/v2/trades",
            &[("owner", format!("{owner:?}"))],
            offset,
            limit,
        )
        .await
    }

    /// `GET /api/v2/trades?orderUid=...`. Newest first; see
    /// [`OrderBookApi::trades_by_owner`] for the pagination semantics.
    pub async fn trades_by_order_uid(
        &self,
        uid: &OrderUid,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<Trade>> {
        self.get_json_with_query(
            "api/v2/trades",
            &[("orderUid", uid.to_string())],
            offset,
            limit,
        )
        .await
    }

    /// `GET /api/v1/token/{token}/native_price`. One atomic unit of
    /// `token` in the chain's native gas token; solvers use this to
    /// denominate gas uniformly across pairs.
    pub async fn native_price(&self, token: Address) -> Result<NativePrice> {
        self.get_json(&format!("api/v1/token/{token:?}/native_price"))
            .await
    }

    /// `GET /api/v1/token/{token}/metadata`.
    ///
    /// The handler ships in upstream `services`, so this works against
    /// production today, but the route is not documented in the bundled
    /// orderbook OpenAPI and `@cowprotocol/cow-sdk` does not expose it.
    /// Treat it as best-effort: it could be removed without an OpenAPI
    /// bump.
    pub async fn token_metadata(&self, token: Address) -> Result<TokenMetadata> {
        self.get_json(&format!("api/v1/token/{token:?}/metadata"))
            .await
    }

    /// `GET /api/v1/transactions/{hash}/orders`. Empty list for an
    /// unknown settlement.
    pub async fn orders_by_tx(&self, tx_hash: B256) -> Result<Vec<Order>> {
        self.get_json(&format!("api/v1/transactions/{tx_hash:?}/orders"))
            .await
    }

    /// `GET /api/v1/auction`. Permissioned (solver-only); the
    /// public-facing proxy returns 403. Shipped for parity with
    /// cow-py / cow-sdk; per-order array is opaque JSON because the
    /// auction shape drifts across CIPs.
    pub async fn auction(&self) -> Result<Auction> {
        self.get_json("api/v1/auction").await
    }

    /// `GET /api/v1/users/{user}/total_surplus`.
    pub async fn total_surplus(&self, user: Address) -> Result<TotalSurplus> {
        self.get_json(&format!("api/v1/users/{user:?}/total_surplus"))
            .await
    }

    /// `GET /api/v1/app_data/{hash}`. Re-hashes the returned body
    /// locally and rejects with [`Error::AppDataHashMismatch`] when
    /// the digest disagrees with `hash`; the signed order commits to
    /// the digest, so this closes the loop between what was signed
    /// and what downstream code displays.
    pub async fn app_data(&self, hash: &AppDataHash) -> Result<AppDataDocument> {
        let document: AppDataDocument = self.get_json(&format!("api/v1/app_data/{hash}")).await?;
        let computed = document.computed_hash();
        if computed != *hash {
            return Err(Error::AppDataHashMismatch {
                expected: hash.to_string(),
                computed: computed.to_string(),
            });
        }
        Ok(document)
    }

    /// `PUT /api/v1/app_data/{hash}`. Hashes `document.full_app_data`
    /// locally first and refuses with [`Error::AppDataHashMismatch`]
    /// on a digest disagreement.
    pub async fn put_app_data(&self, hash: &AppDataHash, document: &AppDataDocument) -> Result<()> {
        let computed = document.computed_hash();
        if computed != *hash {
            return Err(Error::AppDataHashMismatch {
                expected: hash.to_string(),
                computed: computed.to_string(),
            });
        }
        let url = self.base_url.join(&format!("api/v1/app_data/{hash}"))?;
        let response = self.client.put(url).json(document).send().await?;
        Self::decode_empty(response).await
    }

    /// `PUT /api/v1/app_data`. Lets the orderbook compute and return
    /// the digest, then verifies it against
    /// [`AppDataDocument::computed_hash`] locally and rejects with
    /// [`Error::AppDataHashMismatch`] on disagreement. The signed order
    /// commits only to the digest, so a server-supplied hash that does
    /// not match the document the caller uploaded would silently swap
    /// the metadata bound to the order.
    pub async fn upload_app_data(&self, document: &AppDataDocument) -> Result<AppDataHash> {
        let computed = document.computed_hash();
        let server_hash: AppDataHash = self.put_json("api/v1/app_data", document).await?;
        if server_hash != computed {
            return Err(Error::AppDataHashMismatch {
                expected: server_hash.to_string(),
                computed: computed.to_string(),
            });
        }
        Ok(server_hash)
    }

    /// `GET /api/v1/version`. Plain-text liveness probe.
    pub async fn version(&self) -> Result<String> {
        let response = self
            .client
            .get(self.base_url.join("api/v1/version")?)
            .send()
            .await?;
        let status = response.status();
        let text = read_capped_text(response).await?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(error_from_status(status, text))
        }
    }

    /// `DELETE /api/v1/orders`. UIDs travel in the body, not the URL.
    /// Soft-cancel: orders already in flight may still settle.
    pub async fn cancel_orders(&self, signed: &SignedOrderCancellations) -> Result<()> {
        let response = self
            .client
            .delete(self.base_url.join("api/v1/orders")?)
            .json(signed)
            .send()
            .await?;
        Self::decode_empty(response).await
    }

    /// `DELETE /api/v1/orders/{uid}`. Soft-cancel: an order already
    /// picked up by a solver may still settle. For pre-signed and
    /// EthFlow orders, invalidate on-chain instead.
    pub async fn cancel_order(&self, cancellation: &SignedOrderCancellation) -> Result<()> {
        let url = self
            .base_url
            .join(&format!("api/v1/orders/{}", cancellation.order_uid))?;
        let body = CancellationPayload {
            signature: cancellation.signature,
            signing_scheme: cancellation.signing_scheme,
        };
        let response = self.client.delete(url).json(&body).send().await?;
        Self::decode_empty(response).await
    }

    async fn post_json<TReq, TResp>(&self, path: &str, body: &TReq) -> Result<TResp>
    where
        TReq: Serialize + ?Sized,
        TResp: for<'de> Deserialize<'de>,
    {
        let response = self
            .client
            .post(self.base_url.join(path)?)
            .json(body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    async fn put_json<TReq, TResp>(&self, path: &str, body: &TReq) -> Result<TResp>
    where
        TReq: Serialize + ?Sized,
        TResp: for<'de> Deserialize<'de>,
    {
        let response = self
            .client
            .put(self.base_url.join(path)?)
            .json(body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self.client.get(self.base_url.join(path)?).send().await?;
        Self::decode_response(response).await
    }

    /// `GET path` with `pairs` plus the optional `offset` / `limit`
    /// pagination appended to the query string, then decoded as JSON.
    /// The pagination handling matches the other paginated GETs (see
    /// [`append_pagination`]); `pairs` carries the endpoint-specific
    /// filters (`owner`, `orderUid`).
    async fn get_json_with_query<T>(
        &self,
        path: &str,
        pairs: &[(&str, String)],
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut url = self.base_url.join(path)?;
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in pairs {
                query.append_pair(key, value);
            }
            append_pagination(&mut query, offset, limit);
        }
        let response = self.client.get(url).send().await?;
        Self::decode_response(response).await
    }

    async fn decode_response<T>(response: reqwest::Response) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = read_capped_text(response).await?;
        if status.is_success() {
            serde_json::from_str(&text).map_err(Error::from)
        } else {
            Err(error_from_status(status, text))
        }
    }

    /// Decode a response that carries no body on success (`PUT` /
    /// `DELETE` endpoints), mapping a non-2xx status through the same
    /// [`error_from_status`] path as [`Self::decode_response`].
    async fn decode_empty(response: reqwest::Response) -> Result<()> {
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = read_capped_text(response).await?;
        Err(error_from_status(status, text))
    }
}

/// Read a response body as UTF-8 text, rejecting payloads above
/// [`MAX_RESPONSE_BYTES`]. Early-rejects on a declared `Content-Length`,
/// then bounds the body as it streams in (see [`read_capped_body`]) so a
/// chunked or length-less response cannot buffer past the cap before the
/// check fires.
async fn read_capped_text(response: reqwest::Response) -> Result<String> {
    if let Some(declared_len) = response.content_length()
        && declared_len > MAX_RESPONSE_BYTES as u64
    {
        return Err(Error::ResponseTooLarge {
            max: MAX_RESPONSE_BYTES,
        });
    }
    read_capped_body(response).await
}

/// Accumulate the body chunk-by-chunk, failing the moment the running
/// length would exceed [`MAX_RESPONSE_BYTES`]. This is the stream-bounded
/// guard the `Content-Length` early-reject cannot provide for chunked
/// transfers.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn read_capped_body(mut response: reqwest::Response) -> Result<String> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(Error::ResponseTooLarge {
                max: MAX_RESPONSE_BYTES,
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
#[cfg(target_arch = "wasm32")]
pub(crate) async fn read_capped_body(response: reqwest::Response) -> Result<String> {
    let text = response.text().await?;
    if text.len() > MAX_RESPONSE_BYTES {
        return Err(Error::ResponseTooLarge {
            max: MAX_RESPONSE_BYTES,
        });
    }
    Ok(text)
}

/// Map a non-success `(status, body)` to an [`Error`]. Decodes the body
/// as an [`ApiError`] when it parses, falling back to
/// [`Error::UnexpectedStatus`] with the raw body otherwise. The single
/// error-mapping path shared by [`OrderBookApi::decode_response`],
/// [`OrderBookApi::decode_empty`] and [`OrderBookApi::version`].
pub(crate) fn error_from_status(status: reqwest::StatusCode, body: String) -> Error {
    serde_json::from_str::<ApiError>(&body).map_or_else(
        |_| Error::UnexpectedStatus { status, body },
        |api| Error::OrderbookApi { status, api },
    )
}

fn ensure_trailing_slash(mut url: url::Url) -> url::Url {
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    url
}

/// Append the optional `offset` / `limit` pagination pair to a query.
/// `None` leaves the parameter off so the server applies its default.
fn append_pagination(
    q: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    offset: Option<u32>,
    limit: Option<u32>,
) {
    if let Some(offset) = offset {
        q.append_pair("offset", &offset.to_string());
    }
    if let Some(limit) = limit {
        q.append_pair("limit", &limit.to_string());
    }
}
