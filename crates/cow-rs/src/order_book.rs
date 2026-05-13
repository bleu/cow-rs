//! Thin client for the CoW Protocol orderbook HTTP API.
//!
//! The first surface implemented here is the quote endpoint —
//! [`OrderBookApi::get_quote`] — which mirrors the `getQuote` flow exposed
//! by `@cowprotocol/cow-sdk` and `cow-py`. The request and response shapes
//! reflect the production orderbook OpenAPI as of 2026-05.

use {
    crate::{
        app_data::AppDataHash,
        chain::Chain,
        error::{ApiError, Error, Result},
        order::{BuyTokenDestination, OrderData, OrderKind, SellTokenSource},
        signing_scheme::SigningScheme,
    },
    alloy_primitives::{Address, U256},
    serde::{Deserialize, Serialize},
    serde_with::{DisplayFromStr, serde_as},
};

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
        let url = self.base_url.join("api/v1/quote")?;
        let response = self.client.post(url).json(request).send().await?;
        let status = response.status();
        let body = response.text().await?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(Error::from)
        } else if let Ok(api) = serde_json::from_str::<ApiError>(&body) {
            Err(Error::OrderbookApi { status, api })
        } else {
            Err(Error::UnexpectedStatus { status, body })
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
    use super::*;

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
}
