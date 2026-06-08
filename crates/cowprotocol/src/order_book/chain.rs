//! Fluent quote → sign → submit chain.
//!
//! [`OrderBookApi::quote_builder`] returns a [`ChainedQuoteBuilder`]
//! that borrows the api and forwards the standard [`QuoteRequest`]
//! type-state setters. Once the four required slots are pinned, the
//! terminal [`ChainedQuoteBuilder::build`] is async: it issues
//! `POST /api/v1/quote`, binds the response to the request, and yields
//! a [`PendingQuote`]. From there, [`PendingQuote::sign`] projects the
//! response into a signed [`OrderData`] under the api's chain domain
//! and [`SignedOrder::submit`] dispatches `POST /api/v1/orders`.
//!
//! ```no_run
//! use alloy_primitives::{U256, address};
//! use alloy_signer_local::PrivateKeySigner;
//! use cowprotocol::{Chain, OrderBookApi};
//!
//! # async fn run() -> cowprotocol::Result<()> {
//! let wallet: PrivateKeySigner = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse().unwrap();
//! let uid = OrderBookApi::with_chain(Chain::Mainnet)
//!     .build()
//!     .quote_builder()
//!     .sell_token(address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
//!     .buy_token(address!("6B175474E89094C44Da98b954EedeAC495271d0F"))
//!     .from(wallet.address())
//!     .sell_amount_before_fee(U256::from(100_000_000_u64))
//!     .build()
//!     .await?
//!     .sign(&wallet)?
//!     .submit()
//!     .await?;
//! # let _ = uid;
//! # Ok(()) }
//! ```

use alloy_primitives::{Address, U256};
use alloy_signer::SignerSync;

use crate::app_data::{AppDataDoc, AppDataError, COW_RS_APP_CODE};
use crate::error::{Error, Result};
use crate::order::{BuyTokenDestination, OrderData, OrderUid, SellTokenSource};
use crate::signing_scheme::SigningScheme;

use super::builder::{Missing, QuoteRequestBuilder, Set};
use super::client::OrderBookApi;
use super::orders::OrderCreation;
use super::quote::{OrderQuoteResponse, QuoteRequest};
use super::types::{PriceQuality, QuoteAppData};

/// Fluent quote → sign → submit chain. Borrows an [`OrderBookApi`] and
/// forwards [`QuoteRequest`] setters; once the type-state reaches
/// `<Set, Set, Set, Set>` the terminal [`build`] dispatches the HTTP
/// quote.
///
/// [`build`]: ChainedQuoteBuilder::<Set, Set, Set, Set>::build
#[must_use = "ChainedQuoteBuilder does nothing until build() is called"]
#[derive(Debug)]
pub struct ChainedQuoteBuilder<'a, Sell, Buy, From, Amount> {
    api: &'a OrderBookApi,
    inner: QuoteRequestBuilder<Sell, Buy, From, Amount>,
}

impl OrderBookApi {
    /// Begin a quote-sign-submit chain. The returned builder borrows
    /// this api; pin sell token, buy token, owner, and an amount, then
    /// call [`ChainedQuoteBuilder::build`] to issue the HTTP quote.
    pub const fn quote_builder(
        &self,
    ) -> ChainedQuoteBuilder<'_, Missing, Missing, Missing, Missing> {
        ChainedQuoteBuilder {
            api: self,
            inner: QuoteRequest::builder(),
        }
    }
}

impl<'a, B, F, A> ChainedQuoteBuilder<'a, Missing, B, F, A> {
    /// Pin the sell token. Required.
    pub fn sell_token(self, sell_token: Address) -> ChainedQuoteBuilder<'a, Set, B, F, A> {
        ChainedQuoteBuilder {
            api: self.api,
            inner: self.inner.sell_token(sell_token),
        }
    }
}

impl<'a, S, F, A> ChainedQuoteBuilder<'a, S, Missing, F, A> {
    /// Pin the buy token. Required.
    pub fn buy_token(self, buy_token: Address) -> ChainedQuoteBuilder<'a, S, Set, F, A> {
        ChainedQuoteBuilder {
            api: self.api,
            inner: self.inner.buy_token(buy_token),
        }
    }
}

impl<'a, S, B, A> ChainedQuoteBuilder<'a, S, B, Missing, A> {
    /// Pin the order owner (`from`). Required.
    pub fn from(self, from: Address) -> ChainedQuoteBuilder<'a, S, B, Set, A> {
        ChainedQuoteBuilder {
            api: self.api,
            inner: self.inner.from(from),
        }
    }
}

impl<'a, S, B, F> ChainedQuoteBuilder<'a, S, B, F, Missing> {
    /// Pin the pre-fee sell amount (sell-side quote). Matches `cow-sdk`'s
    /// default. Mutually exclusive with the two other amount setters at
    /// the type level.
    pub fn sell_amount_before_fee(
        self,
        amount: U256,
    ) -> ChainedQuoteBuilder<'a, S, B, F, Set> {
        ChainedQuoteBuilder {
            api: self.api,
            inner: self.inner.sell_amount_before_fee(amount),
        }
    }

    /// Pin the post-fee sell amount.
    pub fn sell_amount_after_fee(
        self,
        amount: U256,
    ) -> ChainedQuoteBuilder<'a, S, B, F, Set> {
        ChainedQuoteBuilder {
            api: self.api,
            inner: self.inner.sell_amount_after_fee(amount),
        }
    }

    /// Pin the post-fee buy amount (buy-side quote).
    pub fn buy_amount_after_fee(
        self,
        amount: U256,
    ) -> ChainedQuoteBuilder<'a, S, B, F, Set> {
        ChainedQuoteBuilder {
            api: self.api,
            inner: self.inner.buy_amount_after_fee(amount),
        }
    }
}

impl<'a, S, B, F, A> ChainedQuoteBuilder<'a, S, B, F, A> {
    /// Override the receiver of the buy-token. Defaults to `from` when
    /// unset.
    pub fn receiver(self, receiver: Address) -> Self {
        Self {
            api: self.api,
            inner: self.inner.receiver(receiver),
        }
    }

    /// Pin an absolute expiry (Unix seconds).
    pub fn valid_to(self, valid_to: u32) -> Self {
        Self {
            api: self.api,
            inner: self.inner.valid_to(valid_to),
        }
    }

    /// Pin a relative expiry (seconds from the server clock).
    pub fn valid_for(self, valid_for: u32) -> Self {
        Self {
            api: self.api,
            inner: self.inner.valid_for(valid_for),
        }
    }

    /// Pin the app-data digest or a canonical-JSON document.
    pub fn app_data(self, app_data: impl Into<QuoteAppData>) -> Self {
        Self {
            api: self.api,
            inner: self.inner.app_data(app_data),
        }
    }

    /// Pin the partial-fill flag.
    pub fn partially_fillable(self, partially_fillable: bool) -> Self {
        Self {
            api: self.api,
            inner: self.inner.partially_fillable(partially_fillable),
        }
    }

    /// Pin where the sell token is drawn from.
    pub fn sell_token_balance(self, source: SellTokenSource) -> Self {
        Self {
            api: self.api,
            inner: self.inner.sell_token_balance(source),
        }
    }

    /// Pin where the buy token is paid to.
    pub fn buy_token_balance(self, destination: BuyTokenDestination) -> Self {
        Self {
            api: self.api,
            inner: self.inner.buy_token_balance(destination),
        }
    }

    /// Pin the signing scheme the orderbook should expect.
    pub fn signing_scheme(self, scheme: SigningScheme) -> Self {
        Self {
            api: self.api,
            inner: self.inner.signing_scheme(scheme),
        }
    }

    /// Pin the EIP-1271 verification gas budget.
    pub fn verification_gas_limit(self, gas: u64) -> Self {
        Self {
            api: self.api,
            inner: self.inner.verification_gas_limit(gas),
        }
    }

    /// Mark the request as an on-chain order (EIP-1271 / PreSign).
    pub fn onchain_order(self, onchain: bool) -> Self {
        Self {
            api: self.api,
            inner: self.inner.onchain_order(onchain),
        }
    }

    /// Hint at the requested price quality.
    pub fn price_quality(self, quality: PriceQuality) -> Self {
        Self {
            api: self.api,
            inner: self.inner.price_quality(quality),
        }
    }
}

impl<'a> ChainedQuoteBuilder<'a, Set, Set, Set, Set> {
    /// Dispatch `POST /api/v1/quote` against the borrowed api, bind the
    /// response to the request, and yield a [`PendingQuote`] ready for
    /// signing.
    pub async fn build(self) -> Result<PendingQuote<'a>> {
        let request = self.inner.build();
        let response = self.api.quote(&request).await?;
        Ok(PendingQuote {
            api: self.api,
            request,
            response,
        })
    }
}

/// A quote that has been issued by the orderbook and bound to its
/// originating [`QuoteRequest`]; the next step is [`Self::sign`].
#[must_use = "PendingQuote does nothing until signed and submitted"]
#[derive(Debug)]
pub struct PendingQuote<'a> {
    api: &'a OrderBookApi,
    request: QuoteRequest,
    response: OrderQuoteResponse,
}

impl<'a> PendingQuote<'a> {
    /// The originating [`QuoteRequest`].
    pub const fn request(&self) -> &QuoteRequest {
        &self.request
    }

    /// The orderbook's [`OrderQuoteResponse`].
    pub const fn response(&self) -> &OrderQuoteResponse {
        &self.response
    }

    /// Sign the response with the SDK-attribution app-data document
    /// (`appCode: "cow-rs"`). Use [`Self::sign_with`] to override the
    /// document.
    pub fn sign<W: SignerSync>(self, wallet: &W) -> Result<SignedOrder<'a>> {
        let doc = AppDataDoc::sdk_attribution(COW_RS_APP_CODE);
        self.sign_with(wallet, &doc)
    }

    /// Sign the response with a caller-supplied app-data document. The
    /// digest of the canonical JSON is what the orderbook pins; the
    /// document must hash to ≤ `APP_DATA_SIZE_LIMIT`.
    pub fn sign_with<W: SignerSync>(
        self,
        wallet: &W,
        app_data: &AppDataDoc,
    ) -> Result<SignedOrder<'a>> {
        let app_data_hash = app_data.try_hash().map_err(Error::AppData)?;
        let app_data_json = app_data.canonical_json();
        let order_data = self
            .response
            .try_into_signed_order_data(&self.request, app_data_hash)?;

        let chain = self.api.chain().ok_or(Error::OrderCreationInvalid {
            field: "chain",
            reason: "fluent sign requires a known chain; build the api with OrderBookApi::with_chain",
        })?;
        let domain = chain.settlement_domain();

        let scheme = self
            .response
            .quote
            .signing_scheme
            .try_to_ecdsa_scheme()
            .ok_or(Error::OrderCreationInvalid {
                field: "signing_scheme",
                reason: "fluent sign supports only ECDSA schemes (Eip712, EthSign); use OrderCreation::from_signed_order_data manually for Eip1271 or PreSign",
            })?;

        let signature = order_data
            .sign(scheme, &domain, wallet)
            .map_err(Error::Signature)?;

        Ok(SignedOrder {
            api: self.api,
            order_data,
            signature,
            from: self.request.from,
            app_data_json,
            quote_id: self.response.id,
        })
    }
}

/// A signed order ready for submission via [`SignedOrder::submit`].
#[must_use = "SignedOrder does nothing until submit() is called"]
#[derive(Debug)]
pub struct SignedOrder<'a> {
    api: &'a OrderBookApi,
    order_data: OrderData,
    signature: crate::signature::Signature,
    from: Address,
    app_data_json: String,
    quote_id: i64,
}

impl<'a> SignedOrder<'a> {
    /// The signed [`OrderData`].
    pub const fn order_data(&self) -> &OrderData {
        &self.order_data
    }

    /// The signature (carries scheme + bytes).
    pub const fn signature(&self) -> &crate::signature::Signature {
        &self.signature
    }

    /// Order owner.
    pub const fn from(&self) -> Address {
        self.from
    }

    /// The orderbook quote id this submission is bound to.
    pub const fn quote_id(&self) -> i64 {
        self.quote_id
    }

    /// `POST /api/v1/orders`. Assembles the wire body via
    /// [`OrderCreation::from_signed_order_data`] and dispatches.
    pub async fn submit(self) -> Result<OrderUid> {
        let body = OrderCreation::from_signed_order_data(
            &self.order_data,
            self.signature,
            self.from,
            self.app_data_json,
            Some(self.quote_id),
        )?;
        self.api.post_order(&body).await
    }
}

// Silence the unused-deps lint when AppDataError is referenced through
// `Error::AppData` only; explicit imports are nicer for readability.
const _: fn() -> AppDataError = || unreachable!();
