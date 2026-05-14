//! Thin client for the CoW Protocol orderbook HTTP API.
//!
//! The first surface implemented here is the quote endpoint —
//! [`OrderBookApi::get_quote`] — which mirrors the `getQuote` flow exposed
//! by `@cowprotocol/cow-sdk` and `cow-py`. The request and response shapes
//! reflect the production orderbook OpenAPI as of 2026-05.

use {
    crate::{
        app_data::AppDataHash,
        cancellation::SignedOrderCancellations,
        chain::Chain,
        error::{ApiError, Error, Result},
        order::{BuyTokenDestination, Order, OrderData, OrderKind, OrderUid, SellTokenSource},
        signature::Signature,
        signing_scheme::SigningScheme,
    },
    alloy_primitives::{Address, U256},
    serde::{Deserialize, Serialize},
    serde_with::{DisplayFromStr, serde_as},
};

/// Auction lifecycle stage returned by `GET /api/v1/orders/{uid}/status`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuctionStatusType {
    /// Quoted but not yet in an auction.
    Open,
    /// Scheduled for inclusion in an upcoming auction.
    Scheduled,
    /// In the currently active auction.
    Active,
    /// Solved by one or more solvers; awaiting settlement.
    Solved,
    /// Solver transaction is being submitted on chain.
    Executing,
    /// Settlement transaction was mined.
    Traded,
    /// Cancelled before settlement.
    Cancelled,
}

/// Auction-status payload returned by `GET /api/v1/orders/{uid}/status`.
///
/// `value` carries solver execution proposals when relevant
/// (`solved`/`executing`), and is empty for `open`/`cancelled`. We surface
/// it as opaque JSON to stay forward-compatible with solver-side schema
/// additions.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuctionStatus {
    /// Stage of the auction lifecycle.
    #[serde(rename = "type")]
    pub status_type: AuctionStatusType,
    /// Solver execution proposals attached to the current stage.
    #[serde(default)]
    pub value: Vec<serde_json::Value>,
}

/// Quote request body for `POST /api/v1/quote`.
///
/// Exactly one of the three amount fields
/// (`sell_amount_before_fee`, `sell_amount_after_fee`, `buy_amount_after_fee`)
/// must be `Some` and it must agree with [`QuoteRequest::kind`].
/// Use the constructors below to build a well-formed request.
#[serde_as]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteRequest {
    /// Address of the token being sold.
    pub sell_token: Address,
    /// Address of the token being bought.
    pub buy_token: Address,
    /// Owner that will sign the resulting order.
    pub from: Address,
    /// Optional buy-token recipient; defaults to `from` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<Address>,
    /// Whether the user is fixing the sell side or the buy side.
    pub kind: OrderKind,
    /// Sell amount before the orderbook's fee is deducted.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sell_amount_before_fee: Option<U256>,
    /// Sell amount after the orderbook's fee is deducted.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sell_amount_after_fee: Option<U256>,
    /// Buy amount after the orderbook's fee is deducted.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buy_amount_after_fee: Option<U256>,
    /// Optional explicit expiry timestamp; orderbook picks a default when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<u32>,
    /// Optional pre-computed app-data digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_data: Option<AppDataHash>,
    /// Whether to allow partial fills.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partially_fillable: Option<bool>,
    /// Source from which the sell token is drawn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sell_token_balance: Option<SellTokenSource>,
    /// Destination to which the buy token is paid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buy_token_balance: Option<BuyTokenDestination>,
    /// Intended signing scheme; the orderbook returns this in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_scheme: Option<SigningScheme>,
}

impl QuoteRequest {
    /// Build a sell-side quote where the input amount has NOT yet had the
    /// orderbook fee subtracted. This mirrors the `getQuote` default in
    /// `@cowprotocol/cow-sdk`'s trading package.
    pub const fn sell_amount_before_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        sell_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Sell)
            .with_sell_amount_before_fee(sell_amount)
    }

    /// Build a sell-side quote where the input amount IS the post-fee amount.
    pub const fn sell_amount_after_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        sell_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Sell)
            .with_sell_amount_after_fee(sell_amount)
    }

    /// Build a buy-side quote.
    pub const fn buy_amount_after_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        buy_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Buy).with_buy_amount_after_fee(buy_amount)
    }

    const fn new(sell_token: Address, buy_token: Address, from: Address, kind: OrderKind) -> Self {
        Self {
            sell_token,
            buy_token,
            from,
            receiver: None,
            kind,
            sell_amount_before_fee: None,
            sell_amount_after_fee: None,
            buy_amount_after_fee: None,
            valid_to: None,
            app_data: None,
            partially_fillable: None,
            sell_token_balance: None,
            buy_token_balance: None,
            signing_scheme: None,
        }
    }

    const fn with_sell_amount_before_fee(mut self, amount: U256) -> Self {
        self.sell_amount_before_fee = Some(amount);
        self
    }

    const fn with_sell_amount_after_fee(mut self, amount: U256) -> Self {
        self.sell_amount_after_fee = Some(amount);
        self
    }

    const fn with_buy_amount_after_fee(mut self, amount: U256) -> Self {
        self.buy_amount_after_fee = Some(amount);
        self
    }

    /// Set a custom recipient for the buy token.
    pub const fn with_receiver(mut self, receiver: Address) -> Self {
        self.receiver = Some(receiver);
        self
    }

    /// Set the order's app-data digest.
    pub const fn with_app_data(mut self, app_data: AppDataHash) -> Self {
        self.app_data = Some(app_data);
        self
    }

    /// Pin the order's expiry timestamp.
    pub const fn with_valid_to(mut self, valid_to: u32) -> Self {
        self.valid_to = Some(valid_to);
        self
    }
}

/// The order returned by the quote endpoint.
///
/// This is the 12-field signed payload ([`OrderData`]) plus the signing
/// scheme the orderbook expects and the price metadata it surfaces back to
/// the caller. Use [`OrderQuote::to_order_data`] to extract the subset that
/// gets hashed and signed.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderQuote {
    /// Address of the sold token.
    pub sell_token: Address,
    /// Address of the bought token.
    pub buy_token: Address,
    /// Optional buy-token recipient.
    #[serde(default)]
    pub receiver: Option<Address>,
    /// Sell amount in atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Buy amount in atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Unix timestamp at which the quote stops being valid for signing.
    pub valid_to: u32,
    /// App-data digest.
    pub app_data: AppDataHash,
    /// Fee charged by the orderbook in `sell_token` atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub fee_amount: U256,
    /// Direction of the order.
    pub kind: OrderKind,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Source the sell amount is drawn from.
    #[serde(default)]
    pub sell_token_balance: SellTokenSource,
    /// Destination the buy amount is paid to.
    #[serde(default)]
    pub buy_token_balance: BuyTokenDestination,
    /// Signing scheme the orderbook expects.
    pub signing_scheme: SigningScheme,
}

impl OrderQuote {
    /// Project just the 12 signed fields into an [`OrderData`] suitable for
    /// [`OrderData::hash_struct`] and [`OrderData::uid`].
    pub const fn to_order_data(&self) -> OrderData {
        OrderData {
            sell_token: self.sell_token,
            buy_token: self.buy_token,
            receiver: self.receiver,
            sell_amount: self.sell_amount,
            buy_amount: self.buy_amount,
            valid_to: self.valid_to,
            app_data: self.app_data,
            fee_amount: self.fee_amount,
            kind: self.kind,
            partially_fillable: self.partially_fillable,
            sell_token_balance: self.sell_token_balance,
            buy_token_balance: self.buy_token_balance,
        }
    }
}

impl OrderQuoteResponse {
    /// Apply the submission adjustments documented at
    /// [`api.mdx §"Step 3"`][step3] and return the [`OrderData`] that must
    /// be hashed and signed by the order owner.
    ///
    /// - For sell orders, `sell_amount` is the quoted `sellAmount +
    ///   feeAmount`. For buy orders, the quote values pass through.
    /// - `fee_amount` is always `0` at submission — solvers price gas at
    ///   settlement time.
    /// - `app_data` is the 32-byte digest of the canonical metadata JSON
    ///   the caller will submit (use [`EMPTY_APP_DATA_HASH`] for the empty
    ///   document `"{}"`).
    ///
    /// [step3]: https://docs.cow.fi/cow-protocol/howto/integrate/api#step-3-compute-the-amounts-to-sign
    pub const fn to_signed_order_data(&self, app_data: AppDataHash) -> OrderData {
        let q = &self.quote;
        let (sell_amount, buy_amount) = match q.kind {
            OrderKind::Sell => (q.sell_amount.saturating_add(q.fee_amount), q.buy_amount),
            OrderKind::Buy => (q.sell_amount, q.buy_amount),
        };
        OrderData {
            sell_token: q.sell_token,
            buy_token: q.buy_token,
            receiver: q.receiver,
            sell_amount,
            buy_amount,
            valid_to: q.valid_to,
            app_data,
            fee_amount: U256::ZERO,
            kind: q.kind,
            partially_fillable: q.partially_fillable,
            sell_token_balance: q.sell_token_balance,
            buy_token_balance: q.buy_token_balance,
        }
    }
}

/// Full response body of `POST /api/v1/quote`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderQuoteResponse {
    /// The order the orderbook is willing to settle.
    pub quote: OrderQuote,
    /// Owner address echoed back.
    pub from: Address,
    /// ISO-8601 timestamp at which the quote stops being honoured.
    pub expiration: String,
    /// Server-assigned quote identifier; pass back when posting the order
    /// so the orderbook can reconcile fee/price.
    pub id: i64,
    /// Whether the orderbook simulated the order against on-chain balances.
    pub verified: bool,
    /// Protocol fee in basis points (decimal string).
    #[serde(default)]
    pub protocol_fee_bps: Option<String>,
}

/// Body of `POST /api/v1/orders`.
///
/// Differs from a raw [`OrderData`] in three load-bearing ways
/// (`cow-protocol/howto/integrate/api.mdx`):
///
/// - `fee_amount` here is what the user signed (which must be `0`); the
///   protocol fee is taken from surplus at settlement.
/// - `app_data` is the canonical JSON string of the metadata document;
///   `app_data_hash` is the `keccak256` digest of those exact bytes. The
///   signed [`OrderData::app_data`] field equals `app_data_hash`.
/// - `signing_scheme`, `signature` and `from` carry the owner's signature
///   along with the order.
///
/// Use [`OrderCreation::from_signed_order_data`] to assemble the body once
/// the owner has signed [`OrderQuoteResponse::to_signed_order_data`].
#[serde_as]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderCreation {
    /// Token the owner is selling.
    pub sell_token: Address,
    /// Token the owner is buying.
    pub buy_token: Address,
    /// Optional buy-token recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<Address>,
    /// Sell amount in atomic units (must agree with the signed payload).
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Buy amount in atomic units (must agree with the signed payload).
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Order expiry in Unix seconds.
    pub valid_to: u32,
    /// Canonical JSON of the app-data document.
    pub app_data: String,
    /// `keccak256(app_data)`. Mirrors the signed payload's `app_data` field.
    pub app_data_hash: AppDataHash,
    /// User-signed fee amount. Must be `"0"` at submission.
    #[serde_as(as = "DisplayFromStr")]
    pub fee_amount: U256,
    /// Direction of the order.
    pub kind: OrderKind,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Source the sell amount is drawn from.
    pub sell_token_balance: SellTokenSource,
    /// Destination the buy amount is paid to.
    pub buy_token_balance: BuyTokenDestination,
    /// Off-chain signing scheme used to authenticate the order.
    pub signing_scheme: SigningScheme,
    /// Signature bytes. Empty for [`SigningScheme::PreSign`].
    #[serde(serialize_with = "serialise_signature_bytes")]
    pub signature: Signature,
    /// Order owner. Required for `presign` / `eip1271`; recommended for
    /// ECDSA schemes so the server can reject malformed signatures early.
    pub from: Address,
    /// Identifier returned by `POST /api/v1/quote`. Optional but improves
    /// solver fee accounting when the order is matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<i64>,
}

fn serialise_signature_bytes<S>(
    signature: &Signature,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    crate::bytes_hex::serialize(signature.to_bytes(), serializer)
}

impl OrderCreation {
    /// Assemble a submission body from a signed [`OrderData`] plus the
    /// metadata required by the orderbook (`from`, signature, app-data
    /// document, optional quote id).
    pub const fn from_signed_order_data(
        order_data: OrderData,
        signature: Signature,
        from: Address,
        app_data_json: String,
        quote_id: Option<i64>,
    ) -> Self {
        Self {
            sell_token: order_data.sell_token,
            buy_token: order_data.buy_token,
            receiver: order_data.receiver,
            sell_amount: order_data.sell_amount,
            buy_amount: order_data.buy_amount,
            valid_to: order_data.valid_to,
            app_data: app_data_json,
            app_data_hash: order_data.app_data,
            fee_amount: order_data.fee_amount,
            kind: order_data.kind,
            partially_fillable: order_data.partially_fillable,
            sell_token_balance: order_data.sell_token_balance,
            buy_token_balance: order_data.buy_token_balance,
            signing_scheme: signature.scheme(),
            signature,
            from,
            quote_id,
        }
    }
}

/// Thin client for the CoW Protocol orderbook.
#[derive(Debug, Clone)]
pub struct OrderBookApi {
    base_url: url::Url,
    client: reqwest::Client,
}

impl OrderBookApi {
    /// Build a client targeting the production orderbook for the given chain.
    pub fn new(chain: Chain) -> Self {
        Self::new_with_base_url(ensure_trailing_slash(chain.orderbook_base_url()))
    }

    /// Build a client against a custom base URL — useful for tests against
    /// a recorded server or a staging deployment.
    pub fn new_with_base_url(base_url: url::Url) -> Self {
        Self {
            base_url: ensure_trailing_slash(base_url),
            client: reqwest::Client::new(),
        }
    }

    /// The base URL the client points at, with the trailing slash that path
    /// joining relies on.
    pub const fn base_url(&self) -> &url::Url {
        &self.base_url
    }

    /// `POST /api/v1/quote` — ask the orderbook for a quote that the
    /// requester can sign and submit.
    pub async fn get_quote(&self, request: &QuoteRequest) -> Result<OrderQuoteResponse> {
        self.post_json("api/v1/quote", request).await
    }

    /// `POST /api/v1/orders` — submit a signed order. Returns the
    /// 56-byte UID assigned by the orderbook.
    pub async fn post_order(&self, order: &OrderCreation) -> Result<OrderUid> {
        self.post_json("api/v1/orders", order).await
    }

    /// `GET /api/v1/orders/{uid}` — fetch the full order record, including
    /// execution counters and lifecycle status.
    pub async fn get_order(&self, uid: &OrderUid) -> Result<Order> {
        self.get_json(&format!("api/v1/orders/{uid}")).await
    }

    /// `GET /api/v1/orders/{uid}/status` — fetch the auction lifecycle
    /// stage and any attached solver proposals.
    pub async fn get_order_status(&self, uid: &OrderUid) -> Result<AuctionStatus> {
        self.get_json(&format!("api/v1/orders/{uid}/status")).await
    }

    /// `DELETE /api/v1/orders` — submit a signed cancellation collection.
    ///
    /// Note that the endpoint is `/api/v1/orders` (collection), not
    /// `/api/v1/orders/{uid}`; the orders to cancel are identified by the
    /// `orderUids` array in the body. The cancellation is "soft" — orders
    /// already in flight may still settle.
    pub async fn cancel_orders(&self, signed: &SignedOrderCancellations) -> Result<()> {
        let response = self
            .client
            .delete(self.base_url.join("api/v1/orders")?)
            .json(signed)
            .send()
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response.text().await?;
        serde_json::from_str::<ApiError>(&text).map_or_else(
            |_| Err(Error::UnexpectedStatus { status, body: text }),
            |api| Err(Error::OrderbookApi { status, api }),
        )
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

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self.client.get(self.base_url.join(path)?).send().await?;
        Self::decode_response(response).await
    }

    async fn decode_response<T>(response: reqwest::Response) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = response.text().await?;
        if status.is_success() {
            serde_json::from_str(&text).map_err(Error::from)
        } else if let Ok(api) = serde_json::from_str::<ApiError>(&text) {
            Err(Error::OrderbookApi { status, api })
        } else {
            Err(Error::UnexpectedStatus { status, body: text })
        }
    }
}

fn ensure_trailing_slash(mut url: url::Url) -> url::Url {
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    url
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::app_data::{EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON},
    };

    /// Token addresses used by [`fixture_quote_request`]: USDC and DAI on
    /// Ethereum mainnet.
    const USDC: Address = Address::new(hex_literal::hex!(
        "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    ));
    const DAI: Address = Address::new(hex_literal::hex!(
        "6B175474E89094C44Da98b954EedeAC495271d0F"
    ));
    const OWNER: Address = Address::new(hex_literal::hex!(
        "70997970C51812dc3A010C7d01b50e0d17dc79C8"
    ));

    fn fixture_quote_request() -> QuoteRequest {
        QuoteRequest::sell_amount_before_fee(USDC, DAI, OWNER, U256::from(100_000_000_u64))
    }

    #[test]
    fn quote_request_serialises_to_expected_wire_shape() {
        let body = serde_json::to_value(fixture_quote_request()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "sellToken": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "buyToken": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "from": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
                "kind": "sell",
                "sellAmountBeforeFee": "100000000",
            })
        );
    }

    #[test]
    fn quote_request_includes_buy_kind_when_built_with_buy_amount() {
        let request = QuoteRequest::buy_amount_after_fee(USDC, DAI, OWNER, U256::from(1_000_u64));
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(body["kind"], serde_json::Value::String("buy".into()));
        assert_eq!(
            body["buyAmountAfterFee"],
            serde_json::Value::String("1000".into())
        );
        assert!(body.get("sellAmountBeforeFee").is_none());
    }

    #[test]
    fn base_url_gets_trailing_slash_added() {
        let api = OrderBookApi::new_with_base_url(
            url::Url::parse("https://example.test/orderbook").unwrap(),
        );
        assert!(api.base_url().path().ends_with('/'));
        let endpoint = api.base_url().join("api/v1/quote").unwrap();
        assert_eq!(endpoint.path(), "/orderbook/api/v1/quote");
    }

    #[test]
    fn chain_base_url_composes_correctly() {
        let api = OrderBookApi::new(Chain::Mainnet);
        let endpoint = api.base_url().join("api/v1/quote").unwrap();
        assert_eq!(endpoint.as_str(), "https://api.cow.fi/mainnet/api/v1/quote");
    }

    /// Locks the deserialisation of an `OrderQuoteResponse` against a real
    /// body captured from the production mainnet orderbook
    /// (`tools/vector-gen` is not involved; the fixture is the raw HTTP
    /// response). Catches any drift in the wire schema.
    #[test]
    fn deserialise_mainnet_quote_fixture() {
        let body = include_str!("../tests/fixtures/quote-mainnet.json");
        let response: OrderQuoteResponse = serde_json::from_str(body).unwrap();
        assert_eq!(response.from, OWNER);
        assert!(response.verified);
        assert_eq!(response.quote.sell_token, USDC);
        assert_eq!(response.quote.buy_token, DAI);
        assert_eq!(response.quote.kind, OrderKind::Sell);
        assert_eq!(response.quote.signing_scheme, SigningScheme::Eip712);
        assert_eq!(response.quote.app_data, AppDataHash([0u8; 32]));

        // The order data extracted from the quote round-trips into the
        // signed-payload type and hashes deterministically.
        let order_data = response.quote.to_order_data();
        let _ = order_data.hash_struct();
    }

    fn load_mainnet_quote() -> OrderQuoteResponse {
        serde_json::from_str(include_str!("../tests/fixtures/quote-mainnet.json")).unwrap()
    }

    /// `to_signed_order_data` for a sell-side quote adds `feeAmount` back
    /// into `sellAmount` and zeroes the fee — the documented submission
    /// adjustment.
    #[test]
    fn to_signed_order_data_adjusts_sell_amount_and_zeroes_fee() {
        let quote = load_mainnet_quote();
        assert_eq!(quote.quote.kind, OrderKind::Sell);
        let original_sell = quote.quote.sell_amount;
        let original_fee = quote.quote.fee_amount;

        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH);

        assert_eq!(signed.sell_amount, original_sell + original_fee);
        assert_eq!(signed.buy_amount, quote.quote.buy_amount);
        assert_eq!(signed.fee_amount, U256::ZERO);
        assert_eq!(signed.app_data, EMPTY_APP_DATA_HASH);
        assert_eq!(signed.kind, OrderKind::Sell);
    }

    /// Buy-side quote keeps `sellAmount` as-is; only `feeAmount` gets zeroed.
    #[test]
    fn to_signed_order_data_buy_side_passes_through_amounts() {
        let mut quote = load_mainnet_quote();
        quote.quote.kind = OrderKind::Buy;
        let original_sell = quote.quote.sell_amount;
        let original_buy = quote.quote.buy_amount;

        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH);

        assert_eq!(signed.sell_amount, original_sell);
        assert_eq!(signed.buy_amount, original_buy);
        assert_eq!(signed.fee_amount, U256::ZERO);
    }

    /// `OrderCreation` serialises to the wire shape documented by the
    /// orderbook OpenAPI: 12 signed fields, plus `appData` (JSON string),
    /// `appDataHash` (bytes32), `signingScheme`, `signature`, `from` and
    /// optional `quoteId`. Verifies the field-name overrides that make
    /// `OrderCreation` distinct from a flattened `OrderData`.
    #[test]
    fn order_creation_serialises_to_expected_wire_shape() {
        let quote = load_mainnet_quote();
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH);
        let signature = Signature::default();
        let creation = OrderCreation::from_signed_order_data(
            signed,
            signature,
            quote.from,
            EMPTY_APP_DATA_JSON.to_owned(),
            Some(quote.id),
        );

        let body = serde_json::to_value(&creation).unwrap();
        assert_eq!(body["feeAmount"], "0");
        assert_eq!(body["appData"], "{}");
        assert_eq!(
            body["appDataHash"],
            "0xb48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d"
        );
        assert_eq!(body["signingScheme"], "eip712");
        assert!(body["signature"].as_str().unwrap().starts_with("0x"));
        assert_eq!(body["from"], format!("{:?}", quote.from).to_lowercase());
        assert_eq!(body["quoteId"], 1_176_992_200_i64);
        assert!(body["sellAmount"].is_string());
        // Sell-side adjustment is visible in the serialised body.
        let expected_sell = quote.quote.sell_amount + quote.quote.fee_amount;
        assert_eq!(body["sellAmount"], expected_sell.to_string());
    }

    /// `quoteId` is omitted when not provided rather than emitted as `null`.
    #[test]
    fn order_creation_skips_optional_quote_id() {
        let quote = load_mainnet_quote();
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH);
        let creation = OrderCreation::from_signed_order_data(
            signed,
            Signature::default(),
            quote.from,
            EMPTY_APP_DATA_JSON.to_owned(),
            None,
        );
        let body = serde_json::to_value(&creation).unwrap();
        assert!(body.get("quoteId").is_none());
    }
}
