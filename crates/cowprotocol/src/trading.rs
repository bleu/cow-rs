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
use alloy_signer::SignerSync;

use crate::{
    AppDataDoc, Chain, Error, OrderBookApi, OrderCreation, OrderData, OrderQuoteResponse, OrderUid,
    QuoteRequest, Result, signing_scheme::EcdsaSigningScheme,
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
    pub protocol_fee_bps_override: Option<String>,
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
    pub const fn from_orderbook(chain: Chain, api: OrderBookApi) -> Self {
        Self { api, chain }
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
        let app_data_hash = params.app_data.hash();
        let app_data_json = params.app_data.canonical_json();

        let quote = self.api.get_quote(&params.request).await?;

        let order_data = quote.to_signed_order_data_with_costs(
            &params.request,
            params.partner_fee_bps,
            params.slippage_bps,
            params.protocol_fee_bps_override.as_deref(),
            app_data_hash,
        )?;

        let domain = crate::domain::settlement_domain(self.chain.id(), self.chain.settlement());
        let signature = order_data
            .sign(params.scheme, &domain, signer)
            .map_err(Error::Signature)?;

        if params.request.from == Address::ZERO {
            return Err(Error::OrderCreationInvalid {
                field: "from",
                reason: "QuoteRequest.from must be the order owner; \
                         TradingClient does not infer it from the signer",
            });
        }
        let from = params.request.from;

        let body = OrderCreation::from_signed_order_data(
            order_data,
            signature,
            from,
            app_data_json.clone(),
            Some(quote.id),
        )?;

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
