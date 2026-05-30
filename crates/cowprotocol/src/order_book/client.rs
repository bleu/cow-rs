//! [`OrderBookApi`]: the HTTP client for the CoW Protocol orderbook and
//! the request/response plumbing behind its endpoints.
//!
//! This module is gated behind the `http-client` feature; the DTO types
//! it returns live in the feature-independent sibling modules.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::app_data::AppDataHash;
use crate::cancellation::{SignedOrderCancellation, SignedOrderCancellations};
use crate::chain::Chain;
use crate::error::{ApiError, Error, Result};
use crate::order::{Order, OrderUid};
use crate::signature::{EcdsaSignature, ecdsa_wire};
use crate::signing_scheme::EcdsaSigningScheme;

use super::MAX_RESPONSE_BYTES;
use super::orders::OrderCreation;
use super::quote::{OrderQuoteResponse, QuoteRequest};
use super::types::{
    AppDataDocument, Auction, AuctionStatus, NativePrice, TokenMetadata, TotalSurplus, Trade,
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
