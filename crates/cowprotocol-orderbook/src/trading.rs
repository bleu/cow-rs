//! Quote → sign → submit in one call.
//!
//! [`TradingClient`] wraps [`OrderBookApi`] with the same ergonomics
//! `@cowprotocol/cow-sdk`'s `TradingSdk.postSwapOrder` exposes: callers
//! describe the swap they want, supply a signer, and receive the
//! resulting [`OrderUid`] without having to wire the intermediate
//! quote/sign/cross-check steps themselves. Partner-fee + slippage
//! composition routes through [`crate::quote_amounts`], so a caller
//! that attaches a partner fee on top of a quote carrying a protocol
//! fee gets the byte-correct `buyAmount` the orderbook expects.
//!
//! For raw orderbook access (account orders, trade lookups, version,
//! native price, app-data pinning, cancellation), keep using
//! [`OrderBookApi`] directly: this module is intentionally narrow.

use alloy_primitives::Address;
use cowprotocol_signing::SignerSync;

use crate::{
    AppDataDoc, Chain, Error, OrderBookApi, OrderCreation, OrderData, OrderQuoteResponse, OrderUid,
    QuoteRequest, Result,
    quote_amounts::{OrderCosts, ProtocolFeeBps},
    signing_scheme::EcdsaSigningScheme,
};

/// Inputs to [`TradingClient::post_swap_order`]. Every field except
/// `signer` has a sensible default.
#[derive(Debug, Clone)]
pub struct SwapOrder<'a> {
    /// The quote request to send to the orderbook before signing.
    pub request: QuoteRequest,
    /// The app-data document to bind to the order. The orderbook is
    /// `PUT`-uploaded with the canonical JSON before the order is
    /// posted so callers always end up with a hash the server agrees
    /// with.
    pub app_data: &'a AppDataDoc,
    /// EIP-712 or EthSign. Defaults to EIP-712 via
    /// [`SwapOrder::eip712`].
    pub scheme: EcdsaSigningScheme,
    /// Partner-fee tier in basis points. `0` skips the partner-fee leg.
    pub partner_fee_bps: u32,
    /// Slippage tolerance in basis points, applied to the non-fixed
    /// side of the order (`buy_amount` for SELL, `sell_amount` for
    /// BUY). Default 50 bps.
    pub slippage_bps: u32,
    /// Optional override for the `protocolFeeBps` echoed by the quote
    /// response. `None` falls back to `OrderQuoteResponse::protocol_fee_bps`.
    pub protocol_fee_bps_override: Option<ProtocolFeeBps>,
}

impl<'a> SwapOrder<'a> {
    /// EIP-712, 50 bps slippage, no partner fee. The closest analogue
    /// to `TradingSdk.postSwapOrder({...defaults})` in the TS SDK.
    pub const fn eip712(request: QuoteRequest, app_data: &'a AppDataDoc) -> Self {
        Self {
            request,
            app_data,
            scheme: EcdsaSigningScheme::Eip712,
            partner_fee_bps: 0,
            slippage_bps: 50,
            protocol_fee_bps_override: None,
        }
    }

    /// Pin a partner-fee tier (bps of swap value).
    pub const fn with_partner_fee_bps(mut self, bps: u32) -> Self {
        self.partner_fee_bps = bps;
        self
    }

    /// Pin a custom slippage tolerance (bps).
    pub const fn with_slippage_bps(mut self, bps: u32) -> Self {
        self.slippage_bps = bps;
        self
    }

    /// Pin the signing scheme to EthSign (legacy `personal_sign`);
    /// EIP-712 is the default.
    pub const fn with_ethsign(mut self) -> Self {
        self.scheme = EcdsaSigningScheme::EthSign;
        self
    }
}

/// Result of [`TradingClient::post_swap_order`].
#[derive(Debug, Clone)]
pub struct PostedSwapOrder {
    /// The 56-byte order identifier the orderbook accepted.
    pub uid: OrderUid,
    /// The exact [`OrderData`] that was signed. Pin this for receipts,
    /// recovery flows, or cancellation envelopes built later.
    pub order_data: OrderData,
    /// The quote response the orderbook returned. Useful for
    /// surfacing the projected fees / amounts back to the user.
    pub quote: OrderQuoteResponse,
}

/// One-call quote → sign → submit. Mirrors `TradingSdk.postSwapOrder`
/// in `@cowprotocol/cow-sdk`.
#[derive(Debug, Clone)]
pub struct TradingClient {
    api: OrderBookApi,
    chain: Chain,
}

impl TradingClient {
    /// Build a [`TradingClient`] targeting the production orderbook
    /// for the given chain.
    pub fn new(chain: Chain) -> Self {
        Self {
            api: OrderBookApi::new(chain),
            chain,
        }
    }

    /// Build a [`TradingClient`] around a pre-configured
    /// [`OrderBookApi`]. Use this when the caller wants to share a
    /// `reqwest::Client` across endpoints or point the SDK at the
    /// barn / staging orderbook.
    ///
    /// `chain` drives the EIP-712 signing domain; the `api` drives the
    /// HTTP endpoint. If `api` was built from a known chain (via
    /// [`OrderBookApi::new`]) that disagrees with `chain`, this returns
    /// [`Error::ChainMismatch`] rather than letting the caller sign for
    /// one chain and post to another. An arbitrary-URL `api` (staging /
    /// mock) carries no chain, so the caller's `chain` is trusted.
    pub fn from_orderbook(chain: Chain, api: OrderBookApi) -> Result<Self> {
        if let Some(api_chain) = api.chain()
            && api_chain != chain
        {
            return Err(Error::ChainMismatch {
                client: chain,
                api: api_chain,
            });
        }
        Ok(Self { api, chain })
    }

    /// The chain this client is bound to.
    pub const fn chain(&self) -> Chain {
        self.chain
    }

    /// Borrow the underlying [`OrderBookApi`].
    pub const fn orderbook(&self) -> &OrderBookApi {
        &self.api
    }

    /// One-call quote → sign → submit. The flow:
    ///
    /// 1. `POST /api/v1/quote` with the caller's [`QuoteRequest`].
    /// 2. Apply partner-fee + protocol-fee + slippage composition via
    ///    [`crate::quote_amounts::compute`], producing the
    ///    [`OrderData`] to sign.
    /// 3. Cross-check the response against the request to guard
    ///    against a hostile orderbook flipping `sell_token` /
    ///    `buy_token` / `receiver`.
    /// 4. Sign with the caller's [`SignerSync`].
    /// 5. `PUT /api/v1/app_data/{hash}` so the canonical JSON for the
    ///    bound `appData` digest is available before the order lands.
    /// 6. `POST /api/v1/orders` with the assembled [`OrderCreation`].
    ///
    /// Returns the orderbook's [`OrderUid`] together with the
    /// [`OrderData`] that was signed and the [`OrderQuoteResponse`]
    /// that drove the amount projection.
    pub async fn post_swap_order<S>(
        &self,
        params: SwapOrder<'_>,
        signer: &S,
    ) -> Result<PostedSwapOrder>
    where
        S: SignerSync,
    {
        // `try_hash` rather than `hash`: the document is caller-supplied
        // (a partner can hand in oversized hooks), so surface an oversize
        // doc as an error instead of panicking the task.
        let app_data_hash = params.app_data.try_hash()?;
        let app_data_json = params.app_data.canonical_json();

        // Cheap precondition on the caller's params: fail fast before the
        // quote round-trip, consistent with the oversize-app-data guard.
        if params.request.from == Address::ZERO {
            return Err(Error::OrderCreationInvalid {
                field: "from",
                reason: "QuoteRequest.from must be the order owner; \
                         TradingClient does not infer it from the signer",
            });
        }
        let from = params.request.from;

        let quote = self.api.quote(&params.request).await?;

        let order_data = quote.try_to_order_data(
            &params.request,
            app_data_hash,
            &OrderCosts {
                partner_fee_bps: params.partner_fee_bps,
                slippage_bps: params.slippage_bps,
                protocol_fee_bps_override: params.protocol_fee_bps_override,
            },
        )?;

        let domain = crate::domain::settlement_domain(self.chain.id(), self.chain.settlement());
        let signature = order_data
            .sign(params.scheme, &domain, signer)
            .map_err(Error::Signature)?;

        let body = OrderCreation::from_signed_order_data(
            &order_data,
            signature,
            from,
            app_data_json.clone(),
            Some(quote.id),
        )?;

        // Fail closed if `request.from` does not match the signer:
        // matches the wasm `build_order_creation` shim and avoids a
        // round-trip to the orderbook just to surface a 4xx.
        body.verify_owner(&domain).map_err(Error::Signature)?;

        // Pin the canonical JSON document before posting. The
        // orderbook accepts either order — but posting first risks a
        // window where the index has the hash but not the body.
        self.api
            .put_app_data(
                &app_data_hash,
                &crate::AppDataDocument {
                    full_app_data: app_data_json,
                },
            )
            .await?;

        let uid = self.api.post_order(&body).await?;
        Ok(PostedSwapOrder {
            uid,
            order_data,
            quote,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! Native-only tests for [`TradingClient::post_swap_order`]. The
    //! wiremock fixture is gated off wasm because `wiremock` (and the
    //! `tokio::net` stack it relies on) does not build for that target.
    use super::*;
    use crate::{AppDataDoc, OrderBookApi, SwapOrder};
    use alloy_primitives::{U256, address};
    use alloy_signer_local::PrivateKeySigner;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const DAI: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

    /// Same shape as `tests/trading_mock.rs::quote_body`: a minimal,
    /// deserialisable `OrderQuoteResponse` echoing the caller's `from`.
    fn quote_body(from: Address) -> Value {
        json!({
            "quote": {
                "sellToken": format!("{:#x}", USDC),
                "buyToken": format!("{:#x}", DAI),
                "receiver": null,
                "sellAmount": "1000000000000000000",
                "buyAmount": "2000000000000000000",
                "validTo": 1_900_000_000_u32,
                "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "feeAmount": "0",
                "kind": "sell",
                "partiallyFillable": false,
                "sellTokenBalance": "erc20",
                "buyTokenBalance": "erc20",
                "signingScheme": "eip712",
            },
            "from": format!("{from:#x}"),
            "expiration": "2099-12-31T23:59:59Z",
            "id": 42,
            "verified": true,
        })
    }

    /// R24: `post_swap_order` must fail closed before any
    /// `POST /api/v1/orders` hits the orderbook when `request.from`
    /// disagrees with the signer's address. Mirrors the WASM
    /// `build_order_creation` guard so native callers get the same
    /// fail-fast on a typo or a wallet switch.
    #[tokio::test]
    async fn post_swap_order_rejects_signer_mismatch_before_posting() {
        let signer = PrivateKeySigner::random();
        let signer_addr = signer.address();
        // `request.from` is a wallet the caller doesn't control; the
        // orderbook would 4xx this, but the client must catch it first.
        let declared_from = address!("dead0000dead0000dead0000dead0000dead0000");
        assert_ne!(signer_addr, declared_from);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/quote"))
            .respond_with(ResponseTemplate::new(200).set_body_json(quote_body(declared_from)))
            .mount(&server)
            .await;

        // Track POST /api/v1/orders calls. The assertion below pins
        // that the guard fires before this endpoint is reached: zero
        // calls is the load-bearing observation, not the response.
        let post_calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let post_calls_handle = post_calls.clone();
        Mock::given(method("POST"))
            .and(path("/api/v1/orders"))
            .respond_with(move |req: &wiremock::Request| {
                let body: Value =
                    serde_json::from_slice(&req.body).expect("orderbook body is JSON");
                post_calls_handle.lock().unwrap().push(body);
                ResponseTemplate::new(201).set_body_json(Value::String("0x".repeat(56)))
            })
            .mount(&server)
            .await;

        let api = OrderBookApi::new_with_base_url(server.uri().parse().unwrap());
        let client = TradingClient::from_orderbook(Chain::Mainnet, api).unwrap();
        let app_data = AppDataDoc::sdk_attribution("cow-rs");
        // Match the mocked quote's `sellAmount + feeAmount` so the
        // fixed-leg amount binding passes and execution reaches the
        // `verify_owner` guard this test exercises.
        let request = QuoteRequest::sell_before_fee(
            USDC,
            DAI,
            declared_from,
            U256::from(1_000_000_000_000_000_000_u64),
        );
        let params = SwapOrder::eip712(request, &app_data);

        let err = client
            .post_swap_order(params, &signer)
            .await
            .expect_err("client must reject signer/from mismatch before posting");

        assert!(
            matches!(
                err,
                Error::Signature(crate::signature::SignatureError::SignerMismatch { .. })
            ),
            "expected SignerMismatch, got: {err:?}",
        );

        assert!(
            post_calls.lock().unwrap().is_empty(),
            "POST /api/v1/orders must not be reached when verify_owner fails",
        );
    }

    /// `from_orderbook` refuses a `chain` that disagrees with a
    /// chain-bound `OrderBookApi`, so a caller cannot sign for one chain
    /// and post to another's orderbook.
    #[test]
    fn from_orderbook_rejects_chain_mismatch() {
        let api = OrderBookApi::new(Chain::Gnosis);
        let err = TradingClient::from_orderbook(Chain::Mainnet, api).unwrap_err();
        assert!(
            matches!(
                err,
                Error::ChainMismatch {
                    client: Chain::Mainnet,
                    api: Chain::Gnosis
                }
            ),
            "got: {err:?}"
        );
    }

    /// Matching chains (and arbitrary-URL apis, whose chain is unknown)
    /// are accepted.
    #[test]
    fn from_orderbook_accepts_matching_and_unknown_chain() {
        assert!(
            TradingClient::from_orderbook(Chain::Mainnet, OrderBookApi::new(Chain::Mainnet))
                .is_ok()
        );
        let mock = OrderBookApi::new_with_base_url("https://example.test/".parse().unwrap());
        assert!(TradingClient::from_orderbook(Chain::Gnosis, mock).is_ok());
    }

    /// `post_swap_order` surfaces an oversized caller-supplied app-data
    /// document as an error rather than panicking through `hash()`. The
    /// guard fires before any network call.
    #[tokio::test]
    async fn post_swap_order_surfaces_oversize_app_data_without_panicking() {
        let app_data = AppDataDoc {
            app_code: Some("x".repeat(crate::app_data::APP_DATA_SIZE_LIMIT + 1)),
            ..AppDataDoc::default()
        };
        let owner = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let client = TradingClient::new(Chain::Mainnet);
        let request = QuoteRequest::sell_before_fee(USDC, DAI, owner, U256::from(1u64));
        let params = SwapOrder::eip712(request, &app_data);
        let signer = PrivateKeySigner::random();
        let err = client
            .post_swap_order(params, &signer)
            .await
            .expect_err("oversize app-data must error, not panic");
        assert!(matches!(err, Error::AppData(_)), "got: {err:?}");
    }
}
