//! Quote request and response types plus the projection that turns a
//! quote into the signable [`OrderData`].
//!
//! [`QuoteRequest`] is the `POST /api/v1/quote` body; [`OrderQuote`] and
//! [`OrderQuoteResponse`] model the reply. The request-binding guards
//! ([`OrderQuoteResponse::check_response_matches_request`]) are shared by
//! the orderbook client and by `trading.rs`, so this module is ungated.

use alloy_primitives::{Address, U256, keccak256};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

use crate::app_data::AppDataHash;
use crate::error::{Error, Result};
use crate::order::{BuyTokenDestination, OrderData, OrderKind, SellTokenSource};
use crate::signing_scheme::SigningScheme;

use super::types::{PriceQuality, QuoteAppData};

/// `POST /api/v1/quote` request. Exactly one of `sell_amount_before_fee`,
/// `sell_amount_after_fee`, `buy_amount_after_fee` must be `Some`, and
/// must agree with [`Self::kind`]. Those four fields are private so the
/// invariant cannot be broken; build via the constructors below and read
/// the side via [`Self::kind`]. [`Self::validate`] enforces the invariant
/// for deserialised requests.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteRequest {
    /// Token the owner is selling.
    pub sell_token: Address,
    /// Token the owner is buying.
    pub buy_token: Address,
    /// Order owner.
    pub from: Address,
    /// Defaults to `from` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<Address>,
    /// Sell-side vs buy-side fix. Crate-private so it cannot drift out of
    /// step with the set amount through the public API; read via
    /// [`Self::kind`], set via the constructors.
    pub(crate) kind: OrderKind,
    /// Sell amount before fee (sell-side quote). Crate-private so public
    /// callers cannot set more than one amount or one that disagrees with
    /// `kind`; use the constructors.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sell_amount_before_fee: Option<U256>,
    /// Sell amount after fee (sell-side quote, fee already folded in).
    /// Crate-private; see [`Self::sell_amount_before_fee`].
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sell_amount_after_fee: Option<U256>,
    /// Buy amount after fee (buy-side quote). Crate-private; see
    /// [`Self::sell_amount_before_fee`].
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) buy_amount_after_fee: Option<U256>,
    /// Absolute expiry; orderbook applies a default when absent. This is
    /// the authoritative expiry: when pinned it is bound against the
    /// quote response, so a hostile orderbook cannot lengthen it. Prefer
    /// it over `valid_for` whenever the expiry is security-relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<u32>,
    /// Relative expiry (seconds from the *server* clock; wire `validFor`).
    /// Mutually exclusive with `valid_to` (setting both is rejected at the
    /// signing chokepoint). Advisory only: being server-relative it
    /// cannot be bound client-side, so the SDK signs whatever absolute
    /// `validTo` the orderbook derives from it. Use `valid_to` for a
    /// client-enforced expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_for: Option<u32>,
    /// Optional pin on the app-data digest or document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_data: Option<QuoteAppData>,
    /// Optional pin on partial-fill semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partially_fillable: Option<bool>,
    /// Optional pin on the sell-token source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sell_token_balance: Option<SellTokenSource>,
    /// Optional pin on the buy-token destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buy_token_balance: Option<BuyTokenDestination>,
    /// Optional pin on the signing scheme.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_scheme: Option<SigningScheme>,
    /// Gas budget for the on-chain `isValidSignature` callback on
    /// EIP-1271 quotes. Server default: 27_000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_gas_limit: Option<u64>,
    /// `true` for orders placed on chain (EIP-1271 / PreSign).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onchain_order: Option<bool>,
    /// Price-quality hint. Omitted from the wire when `None`, in which
    /// case the server applies its default ([`PriceQuality::Verified`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_quality: Option<PriceQuality>,
}

/// Marker types used by [`QuoteRequestBuilder`] to track required fields.
pub mod builder_state {
    /// Required field has not been supplied yet.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Missing;

    /// Required field has been supplied.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Set;
}

use builder_state::{Missing, Set};
use core::marker::PhantomData;

/// Type-state builder for [`QuoteRequest`].
///
/// The builder only exposes [`build_request`](Self::build_request) after
/// `sell_token`, `buy_token`, `from`, and exactly one amount have been set.
/// This keeps the common construction path aligned with
/// [`QuoteRequest::validate`] while preserving serde support for wire DTOs.
#[derive(Clone, Debug)]
pub struct QuoteRequestBuilder<
    SellToken = Missing,
    BuyToken = Missing,
    From = Missing,
    Amount = Missing,
> {
    sell_token: Option<Address>,
    buy_token: Option<Address>,
    from: Option<Address>,
    receiver: Option<Address>,
    kind: Option<OrderKind>,
    sell_amount_before_fee: Option<U256>,
    sell_amount_after_fee: Option<U256>,
    buy_amount_after_fee: Option<U256>,
    valid_to: Option<u32>,
    valid_for: Option<u32>,
    app_data: Option<QuoteAppData>,
    partially_fillable: Option<bool>,
    sell_token_balance: Option<SellTokenSource>,
    buy_token_balance: Option<BuyTokenDestination>,
    signing_scheme: Option<SigningScheme>,
    verification_gas_limit: Option<u64>,
    onchain_order: Option<bool>,
    price_quality: Option<PriceQuality>,
    _state: PhantomData<(SellToken, BuyToken, From, Amount)>,
}

impl QuoteRequestBuilder {
    const fn new() -> Self {
        Self {
            sell_token: None,
            buy_token: None,
            from: None,
            receiver: None,
            kind: None,
            sell_amount_before_fee: None,
            sell_amount_after_fee: None,
            buy_amount_after_fee: None,
            valid_to: None,
            valid_for: None,
            app_data: None,
            partially_fillable: None,
            sell_token_balance: None,
            buy_token_balance: None,
            signing_scheme: None,
            verification_gas_limit: None,
            onchain_order: None,
            price_quality: None,
            _state: PhantomData,
        }
    }
}

impl<SellToken, BuyToken, From, Amount> QuoteRequestBuilder<SellToken, BuyToken, From, Amount> {
    fn cast<NextSellToken, NextBuyToken, NextFrom, NextAmount>(
        self,
    ) -> QuoteRequestBuilder<NextSellToken, NextBuyToken, NextFrom, NextAmount> {
        QuoteRequestBuilder {
            sell_token: self.sell_token,
            buy_token: self.buy_token,
            from: self.from,
            receiver: self.receiver,
            kind: self.kind,
            sell_amount_before_fee: self.sell_amount_before_fee,
            sell_amount_after_fee: self.sell_amount_after_fee,
            buy_amount_after_fee: self.buy_amount_after_fee,
            valid_to: self.valid_to,
            valid_for: self.valid_for,
            app_data: self.app_data,
            partially_fillable: self.partially_fillable,
            sell_token_balance: self.sell_token_balance,
            buy_token_balance: self.buy_token_balance,
            signing_scheme: self.signing_scheme,
            verification_gas_limit: self.verification_gas_limit,
            onchain_order: self.onchain_order,
            price_quality: self.price_quality,
            _state: PhantomData,
        }
    }

    /// Set the token the owner sells.
    pub fn with_sell_token(
        self,
        sell_token: Address,
    ) -> QuoteRequestBuilder<Set, BuyToken, From, Amount> {
        let mut next = self.cast::<Set, BuyToken, From, Amount>();
        next.sell_token = Some(sell_token);
        next
    }

    /// Set the token the owner buys.
    pub fn with_buy_token(
        self,
        buy_token: Address,
    ) -> QuoteRequestBuilder<SellToken, Set, From, Amount> {
        let mut next = self.cast::<SellToken, Set, From, Amount>();
        next.buy_token = Some(buy_token);
        next
    }

    /// Set the order owner.
    pub fn with_from(self, from: Address) -> QuoteRequestBuilder<SellToken, BuyToken, Set, Amount> {
        let mut next = self.cast::<SellToken, BuyToken, Set, Amount>();
        next.from = Some(from);
        next
    }

    /// Set a sell-side quote amount before fee deduction.
    pub fn with_sell_amount(
        self,
        sell_amount: U256,
    ) -> QuoteRequestBuilder<SellToken, BuyToken, From, Set> {
        self.with_sell_amount_before_fee(sell_amount)
    }

    /// Set a sell-side quote amount before fee deduction.
    pub fn with_sell_amount_before_fee(
        self,
        sell_amount: U256,
    ) -> QuoteRequestBuilder<SellToken, BuyToken, From, Set> {
        let mut next = self.cast::<SellToken, BuyToken, From, Set>();
        next.kind = Some(OrderKind::Sell);
        next.sell_amount_before_fee = Some(sell_amount);
        next.sell_amount_after_fee = None;
        next.buy_amount_after_fee = None;
        next
    }

    /// Set a sell-side quote amount after fee deduction.
    pub fn with_sell_amount_after_fee(
        self,
        sell_amount: U256,
    ) -> QuoteRequestBuilder<SellToken, BuyToken, From, Set> {
        let mut next = self.cast::<SellToken, BuyToken, From, Set>();
        next.kind = Some(OrderKind::Sell);
        next.sell_amount_before_fee = None;
        next.sell_amount_after_fee = Some(sell_amount);
        next.buy_amount_after_fee = None;
        next
    }

    /// Set a buy-side quote amount after fee deduction.
    pub fn with_buy_amount_after_fee(
        self,
        buy_amount: U256,
    ) -> QuoteRequestBuilder<SellToken, BuyToken, From, Set> {
        let mut next = self.cast::<SellToken, BuyToken, From, Set>();
        next.kind = Some(OrderKind::Buy);
        next.sell_amount_before_fee = None;
        next.sell_amount_after_fee = None;
        next.buy_amount_after_fee = Some(buy_amount);
        next
    }

    /// Set an explicit receiver. Omit it to use the owner.
    pub const fn with_receiver(mut self, receiver: Address) -> Self {
        self.receiver = Some(receiver);
        self
    }

    /// Pin the absolute order expiry returned by the orderbook.
    pub const fn with_valid_to(mut self, valid_to: u32) -> Self {
        self.valid_to = Some(valid_to);
        self.valid_for = None;
        self
    }

    /// Ask the orderbook for a server-relative expiry.
    pub const fn with_valid_for(mut self, valid_for: u32) -> Self {
        self.valid_for = Some(valid_for);
        self.valid_to = None;
        self
    }

    /// Pin app-data by hash or by full canonical JSON.
    pub fn with_app_data(mut self, app_data: impl Into<QuoteAppData>) -> Self {
        self.app_data = Some(app_data.into());
        self
    }

    /// Pin the partial-fill setting.
    pub const fn with_partially_fillable(mut self, partially_fillable: bool) -> Self {
        self.partially_fillable = Some(partially_fillable);
        self
    }

    /// Pin the sell-token source.
    pub const fn with_sell_token_balance(mut self, balance: SellTokenSource) -> Self {
        self.sell_token_balance = Some(balance);
        self
    }

    /// Pin the buy-token destination.
    pub const fn with_buy_token_balance(mut self, balance: BuyTokenDestination) -> Self {
        self.buy_token_balance = Some(balance);
        self
    }

    /// Pin the signing scheme expected in the quote response.
    pub const fn with_signing_scheme(mut self, signing_scheme: SigningScheme) -> Self {
        self.signing_scheme = Some(signing_scheme);
        self
    }

    /// Set the EIP-1271 verification gas limit hint.
    pub const fn with_verification_gas_limit(mut self, gas_limit: u64) -> Self {
        self.verification_gas_limit = Some(gas_limit);
        self
    }

    /// Mark whether the order is placed on chain.
    pub const fn with_onchain_order(mut self, onchain_order: bool) -> Self {
        self.onchain_order = Some(onchain_order);
        self
    }

    /// Set the price-quality hint.
    pub const fn with_price_quality(mut self, price_quality: PriceQuality) -> Self {
        self.price_quality = Some(price_quality);
        self
    }
}

impl QuoteRequestBuilder<Set, Set, Set, Set> {
    /// Build the wire [`QuoteRequest`].
    pub fn build_request(self) -> QuoteRequest {
        QuoteRequest {
            sell_token: self.sell_token.expect("sell token typestate is set"),
            buy_token: self.buy_token.expect("buy token typestate is set"),
            from: self.from.expect("from typestate is set"),
            receiver: self.receiver,
            kind: self.kind.expect("amount typestate sets kind"),
            sell_amount_before_fee: self.sell_amount_before_fee,
            sell_amount_after_fee: self.sell_amount_after_fee,
            buy_amount_after_fee: self.buy_amount_after_fee,
            valid_to: self.valid_to,
            valid_for: self.valid_for,
            app_data: self.app_data,
            partially_fillable: self.partially_fillable,
            sell_token_balance: self.sell_token_balance,
            buy_token_balance: self.buy_token_balance,
            signing_scheme: self.signing_scheme,
            verification_gas_limit: self.verification_gas_limit,
            onchain_order: self.onchain_order,
            price_quality: self.price_quality,
        }
    }
}

impl QuoteRequest {
    /// Start a type-state builder for quote requests.
    pub const fn builder() -> QuoteRequestBuilder {
        QuoteRequestBuilder::new()
    }

    /// Sell-side quote with pre-fee input amount. Matches
    /// `cow-sdk`'s `getQuote` default.
    pub const fn sell_before_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        sell_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Sell)
            .with_sell_amount_before_fee(sell_amount)
    }

    /// Sell-side quote with post-fee input amount.
    pub const fn sell_after_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        sell_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Sell)
            .with_sell_amount_after_fee(sell_amount)
    }

    /// Buy-side quote.
    pub const fn buy_after_fee(
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
            valid_for: None,
            app_data: None,
            partially_fillable: None,
            sell_token_balance: None,
            buy_token_balance: None,
            signing_scheme: None,
            verification_gas_limit: None,
            onchain_order: None,
            price_quality: None,
        }
    }

    const fn with_sell_amount_before_fee(mut self, a: U256) -> Self {
        self.sell_amount_before_fee = Some(a);
        self
    }
    const fn with_sell_amount_after_fee(mut self, a: U256) -> Self {
        self.sell_amount_after_fee = Some(a);
        self
    }
    const fn with_buy_amount_after_fee(mut self, a: U256) -> Self {
        self.buy_amount_after_fee = Some(a);
        self
    }

    /// Order side the request was built for. The amount fields are kept
    /// private and in step with this; read it here rather than off the
    /// (now private) field.
    pub const fn kind(&self) -> OrderKind {
        self.kind
    }

    /// Enforce the request-shape invariants the constructors already
    /// uphold, but which a deserialised or mutated request could break:
    /// exactly one amount is set, the set amount agrees with `kind`, and
    /// `valid_to` / `valid_for` are not both set. Called at the top of
    /// [`OrderBookApi::quote`] so an inconsistent request never reaches
    /// the orderbook or a signature.
    ///
    /// [`OrderBookApi::quote`]: super::OrderBookApi::quote
    pub fn validate(&self) -> Result<()> {
        // `valid_to` (absolute) and `valid_for` (server-relative) are
        // mutually exclusive: sending both is ambiguous, and only
        // `valid_to` can be bound client-side.
        if self.valid_to.is_some() && self.valid_for.is_some() {
            return Err(Error::QuoteRequestInvalid {
                field: "validTo/validFor",
                reason: "are mutually exclusive; set at most one",
            });
        }
        let count = u8::from(self.sell_amount_before_fee.is_some())
            + u8::from(self.sell_amount_after_fee.is_some())
            + u8::from(self.buy_amount_after_fee.is_some());
        if count != 1 {
            return Err(Error::QuoteRequestInvalid {
                field: "amount",
                reason: "exactly one of sellAmountBeforeFee, sellAmountAfterFee, \
                         buyAmountAfterFee must be set",
            });
        }
        // The set amount must agree with the side: a sell amount implies a
        // Sell order, a buy amount a Buy order. A disagreement would have
        // the orderbook price the wrong leg.
        let kind_for_amount = if self.buy_amount_after_fee.is_some() {
            OrderKind::Buy
        } else {
            OrderKind::Sell
        };
        if self.kind != kind_for_amount {
            return Err(Error::QuoteRequestInvalid {
                field: "kind",
                reason: "does not agree with the set amount; sell amounts \
                         require Sell, the buy amount requires Buy",
            });
        }
        Ok(())
    }
}

/// Quote response payload. The 12-field signed shape plus the
/// orderbook's expected signing scheme and price metadata. Use
/// [`OrderQuoteResponse::try_into_signed_order_data`] to project into a
/// signable [`OrderData`] after binding the response to the
/// originating [`QuoteRequest`].
///
/// The openapi schema also carries `gasAmount` / `gasPrice` /
/// `sellTokenPrice`; those are not modelled here (cow-sdk drops them
/// too). Serde tolerates the extras, so callers needing the gas
/// breakdown can decode the raw JSON body themselves.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderQuote {
    /// Sold token, echoed from the request.
    pub sell_token: Address,
    /// Bought token, echoed from the request.
    pub buy_token: Address,
    /// Receiver, normalised from the request.
    #[serde(default)]
    pub receiver: Option<Address>,
    /// Sell amount the orderbook expects in the signed order.
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Buy amount the orderbook expects in the signed order.
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Quoted expiry, Unix seconds.
    pub valid_to: u32,
    /// 32-byte digest of the app-data document.
    pub app_data: AppDataHash,
    /// Orderbook fee in `sell_token` atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub fee_amount: U256,
    /// Sell-side vs buy-side fix.
    pub kind: OrderKind,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Source the sell token is drawn from.
    #[serde(default)]
    pub sell_token_balance: SellTokenSource,
    /// Destination the buy token is paid to.
    #[serde(default)]
    pub buy_token_balance: BuyTokenDestination,
    /// Signing scheme the orderbook expects.
    pub signing_scheme: SigningScheme,
}

impl OrderQuoteResponse {
    /// Project the response into the [`OrderData`] the owner signs,
    /// applying the [step-3][step3] amount adjustments. Cross-checks
    /// `sellToken`, `buyToken`, normalised `receiver`, `kind`, `from`,
    /// plus any caller-pinned `validTo` / `partiallyFillable` /
    /// balance / scheme / `appData`, against `request`; mismatches
    /// fail closed with [`Error::QuoteFieldMismatch`]. Sell orders
    /// fold `feeAmount` into `sellAmount`; `fee_amount` ships as `0`
    /// (solvers price gas at settlement).
    ///
    /// [step3]: https://docs.cow.fi/cow-protocol/howto/integrate/api#step-3-compute-the-amounts-to-sign
    pub fn try_into_signed_order_data(
        &self,
        request: &QuoteRequest,
        app_data: AppDataHash,
    ) -> Result<OrderData> {
        self.check_response_matches_request(request, app_data)?;
        let q = &self.quote;
        let (sell_amount, buy_amount) = match q.kind {
            OrderKind::Sell => {
                let total =
                    q.sell_amount
                        .checked_add(q.fee_amount)
                        .ok_or(Error::QuoteAmountOverflow {
                            sell: q.sell_amount,
                            fee: q.fee_amount,
                        })?;
                (total, q.buy_amount)
            }
            OrderKind::Buy => (q.sell_amount, q.buy_amount),
        };
        Ok(self.project_into_order_data(sell_amount, buy_amount, app_data))
    }

    /// Project the response into [`OrderData`] with caller-supplied
    /// amounts and `app_data`; `fee_amount` is always `0` at signing
    /// time. Private because every public path must first run
    /// [`Self::check_response_matches_request`].
    const fn project_into_order_data(
        &self,
        sell_amount: U256,
        buy_amount: U256,
        app_data: AppDataHash,
    ) -> OrderData {
        let q = &self.quote;
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

    /// Project the quote through `getQuoteAmountsAndCosts`-equivalent
    /// arithmetic ([`crate::quote_amounts::compute`]). Required when
    /// combining a partner fee with a quote that carries a protocol
    /// fee: otherwise the partner-fee base is computed against the
    /// wrong spot price (see [cow-sdk #867]). Pass
    /// `protocol_fee_bps_override` to pin the value; `None` falls
    /// back to [`Self::protocol_fee_bps`].
    ///
    /// [cow-sdk #867]: https://github.com/cowprotocol/cow-sdk/pull/867
    pub fn amounts_with_costs(
        &self,
        partner_fee_bps: u32,
        slippage_bps: u32,
        protocol_fee_bps_override: Option<&str>,
    ) -> Result<crate::quote_amounts::QuoteAmountsAndCosts> {
        let q = &self.quote;
        let protocol_fee_bps = protocol_fee_bps_override.or(self.protocol_fee_bps.as_deref());
        crate::quote_amounts::compute(crate::quote_amounts::QuoteAmountsParams {
            kind: q.kind,
            sell_amount: q.sell_amount,
            buy_amount: q.buy_amount,
            fee_amount: q.fee_amount,
            partner_fee_bps,
            slippage_bps,
            protocol_fee_bps,
        })
    }

    /// Like [`Self::try_into_signed_order_data`] but runs the full
    /// partner-fee + protocol-fee + slippage composition through
    /// [`Self::amounts_with_costs`] first. Use when the order carries
    /// an `AppDataPartnerFee` or the quote echoes a non-zero
    /// `protocolFeeBps`. Same request-binding guard.
    pub fn try_into_signed_order_data_with_costs(
        &self,
        request: &QuoteRequest,
        partner_fee_bps: u32,
        slippage_bps: u32,
        protocol_fee_bps_override: Option<&str>,
        app_data: AppDataHash,
    ) -> Result<OrderData> {
        self.check_response_matches_request(request, app_data)?;
        let amounts =
            self.amounts_with_costs(partner_fee_bps, slippage_bps, protocol_fee_bps_override)?;
        Ok(self.project_into_order_data(
            amounts.amounts_to_sign.sell_amount,
            amounts.amounts_to_sign.buy_amount,
            app_data,
        ))
    }

    pub(crate) fn check_response_matches_request(
        &self,
        request: &QuoteRequest,
        app_data: AppDataHash,
    ) -> Result<()> {
        let q = &self.quote;
        ensure_eq("sellToken", request.sell_token, q.sell_token)?;
        ensure_eq("buyToken", request.buy_token, q.buy_token)?;
        // `from` lives on the response envelope, not OrderQuote. The
        // orderbook indexes the order under this address and the SDK
        // computes the UID from it; a mismatch silently swaps the
        // owner the order would settle for.
        ensure_eq("from", request.from, self.from)?;
        // `kind` is the most damaging swap: flipping Sell <-> Buy
        // reinterprets which side of the order is the fixed leg, so a
        // user-confirmed sell amount can come back as a quoted buy.
        ensure_eq("kind", request.kind, q.kind)?;
        // Treat `None`, `Some(ZERO)` and `Some(owner)` as "owner
        // receives" on both sides; the orderbook normalises the same
        // way. Comparing only when `request.receiver` is `Some` would
        // skip validation for the common default-receiver case and let
        // a hostile orderbook redirect proceeds to an attacker.
        let normalise = |owner: Address, receiver: Option<Address>| match receiver {
            Some(addr) if addr == Address::ZERO || addr == owner => None,
            other => other,
        };
        ensure_eq(
            "receiver",
            normalise(request.from, request.receiver),
            normalise(request.from, q.receiver),
        )?;
        // Conditional fields: only enforce when the request pinned
        // them, otherwise the orderbook is free to fill in defaults.
        if let Some(valid_to) = request.valid_to {
            ensure_eq("validTo", valid_to, q.valid_to)?;
        }
        if let Some(partially_fillable) = request.partially_fillable {
            ensure_eq(
                "partiallyFillable",
                partially_fillable,
                q.partially_fillable,
            )?;
        }
        if let Some(src) = request.sell_token_balance {
            ensure_eq("sellTokenBalance", src, q.sell_token_balance)?;
        }
        if let Some(dst) = request.buy_token_balance {
            ensure_eq("buyTokenBalance", dst, q.buy_token_balance)?;
        }
        if let Some(scheme) = request.signing_scheme {
            ensure_eq("signingScheme", scheme, q.signing_scheme)?;
        }
        if let Some(QuoteAppData::Hash(requested_hash)) = request.app_data.as_ref() {
            ensure_eq("appData", *requested_hash, app_data)?;
        }
        // `Full(json)` pins the document, not the digest: the orderbook
        // is expected to hash the bytes verbatim (matching
        // [`AppDataDocument::computed_hash`]) and return that digest on
        // the response. A mismatch means the server is signing the
        // caller against a different `app_data` than they handed in, so
        // refuse before the signature commits.
        //
        // [`AppDataDocument::computed_hash`]: super::AppDataDocument::computed_hash
        if let Some(QuoteAppData::Full(json)) = request.app_data.as_ref() {
            let expected = keccak256(json.as_bytes());
            if expected != app_data {
                return Err(Error::QuoteFieldMismatch {
                    field: "appData",
                    requested: expected.to_string(),
                    returned: app_data.to_string(),
                });
            }
        }
        // Bind the fixed leg the caller specified. Without this a hostile
        // orderbook can echo the right token pair and `kind` but inflate
        // the fixed amount, so the caller signs an order moving more (or
        // accepting less) than they requested. The variable leg (buy for
        // SELL, sell for BUY) is the quote itself and is deliberately not
        // bound: it is what the orderbook is being asked to price, and
        // slippage / fee composition adjust it downstream.
        if let Some(requested) = request.sell_amount_before_fee {
            // The signed `sellAmount` folds the fee back in, so the
            // pre-fee request equals `sellAmount + feeAmount`.
            let signed_sell =
                q.sell_amount
                    .checked_add(q.fee_amount)
                    .ok_or(Error::QuoteAmountOverflow {
                        sell: q.sell_amount,
                        fee: q.fee_amount,
                    })?;
            ensure_eq("sellAmountBeforeFee", requested, signed_sell)?;
        }
        if let Some(requested) = request.sell_amount_after_fee {
            ensure_eq("sellAmountAfterFee", requested, q.sell_amount)?;
        }
        if let Some(requested) = request.buy_amount_after_fee {
            ensure_eq("buyAmountAfterFee", requested, q.buy_amount)?;
        }
        Ok(())
    }
}

/// Fail closed with a uniform [`Error::QuoteFieldMismatch`] when a
/// response field does not equal the value the request pinned. `field` is
/// the camelCase wire name; `requested` and `returned` are rendered with
/// `Debug` so addresses, amounts, enums and `Option`s all format
/// consistently in the error.
pub(crate) fn ensure_eq<T>(field: &'static str, requested: T, returned: T) -> Result<()>
where
    T: core::fmt::Debug + PartialEq,
{
    if requested == returned {
        return Ok(());
    }
    Err(Error::QuoteFieldMismatch {
        field,
        requested: format!("{requested:?}"),
        returned: format!("{returned:?}"),
    })
}

/// `POST /api/v1/quote` response body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderQuoteResponse {
    /// Quoted [`OrderQuote`]; project via [`Self::try_into_signed_order_data`].
    pub quote: OrderQuote,
    /// Order owner; echoed from the request.
    pub from: Address,
    /// ISO-8601 expiry of the quote, as the orderbook reports it.
    /// Informational only: the authoritative expiry the SDK signs into
    /// the EIP-712 hash is [`OrderQuote::valid_to`], not this string.
    /// Callers that need a typed timestamp for display should parse
    /// this field in their own layer; cow-rs deliberately does not pull
    /// in a date-time dependency for it.
    pub expiration: String,
    /// Server-assigned quote id; pass back when posting so the
    /// orderbook can reconcile fee/price.
    pub id: i64,
    /// `true` if the orderbook simulated against on-chain balances.
    pub verified: bool,
    /// Protocol fee in bps, decimal string.
    #[serde(default)]
    pub protocol_fee_bps: Option<String>,
}
