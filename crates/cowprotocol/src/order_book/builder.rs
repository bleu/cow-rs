//! Type-state builder for [`QuoteRequest`].
//!
//! The four required fields — sell token, buy token, order owner
//! (`from`), and exactly one of three amount variants — are tracked at
//! the type level: [`QuoteRequestBuilder::build`] is only callable once
//! every required slot has transitioned from [`Missing`] to [`Set`].
//! Optional fields (receiver, expiry, app-data pin, balance source,
//! signing scheme, …) can be set in any order at any state.
//!
//! ```
//! use alloy_primitives::{U256, address};
//! use cowprotocol::QuoteRequest;
//!
//! let request = QuoteRequest::builder()
//!     .sell_token(address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
//!     .buy_token(address!("6B175474E89094C44Da98b954EedeAC495271d0F"))
//!     .from(address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"))
//!     .sell_amount_before_fee(U256::from(100_000_000_u64))
//!     .valid_for(60 * 30)
//!     .build();
//! ```

use alloy_primitives::{Address, U256};
use std::marker::PhantomData;

use crate::order::{BuyTokenDestination, OrderKind, SellTokenSource};
use crate::signing_scheme::SigningScheme;

use super::quote::QuoteRequest;
use super::types::{PriceQuality, QuoteAppData};

/// Marker for a required builder field that has not been provided. The
/// terminal [`QuoteRequestBuilder::build`] is not in scope while any
/// required state is `Missing`.
#[derive(Debug)]
pub struct Missing;

/// Marker for a required builder field that has been provided.
#[derive(Debug)]
pub struct Set;

/// Type-state builder for [`QuoteRequest`].
///
/// Construct via [`QuoteRequest::builder`]. The four type parameters
/// track which required fields have been set; only the
/// `<Set, Set, Set, Set>` specialisation exposes
/// [`QuoteRequestBuilder::build`].
#[must_use = "QuoteRequestBuilder does nothing until build() is called"]
#[derive(Debug)]
pub struct QuoteRequestBuilder<Sell, Buy, From, Amount> {
    sell_token: Option<Address>,
    buy_token: Option<Address>,
    from: Option<Address>,
    kind: Option<OrderKind>,
    sell_amount_before_fee: Option<U256>,
    sell_amount_after_fee: Option<U256>,
    buy_amount_after_fee: Option<U256>,
    receiver: Option<Address>,
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
    _state: PhantomData<(Sell, Buy, From, Amount)>,
}

impl QuoteRequest {
    /// Start a type-state builder. Set the sell token, buy token, owner
    /// (`from`), and exactly one of [`sell_amount_before_fee`],
    /// [`sell_amount_after_fee`], or [`buy_amount_after_fee`] to reach a
    /// callable [`build`].
    ///
    /// [`sell_amount_before_fee`]: QuoteRequestBuilder::sell_amount_before_fee
    /// [`sell_amount_after_fee`]: QuoteRequestBuilder::sell_amount_after_fee
    /// [`buy_amount_after_fee`]: QuoteRequestBuilder::buy_amount_after_fee
    /// [`build`]: QuoteRequestBuilder::build
    pub const fn builder() -> QuoteRequestBuilder<Missing, Missing, Missing, Missing> {
        QuoteRequestBuilder {
            sell_token: None,
            buy_token: None,
            from: None,
            kind: None,
            sell_amount_before_fee: None,
            sell_amount_after_fee: None,
            buy_amount_after_fee: None,
            receiver: None,
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

impl<S, B, F, A> QuoteRequestBuilder<S, B, F, A> {
    /// Re-tag the type-state markers without touching the payload.
    /// Private — callers transition state through the typed setters.
    fn retag<S2, B2, F2, A2>(self) -> QuoteRequestBuilder<S2, B2, F2, A2> {
        QuoteRequestBuilder {
            sell_token: self.sell_token,
            buy_token: self.buy_token,
            from: self.from,
            kind: self.kind,
            sell_amount_before_fee: self.sell_amount_before_fee,
            sell_amount_after_fee: self.sell_amount_after_fee,
            buy_amount_after_fee: self.buy_amount_after_fee,
            receiver: self.receiver,
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

    /// Override the receiver of the buy-token. Defaults to `from` on the
    /// orderbook when unset.
    pub fn receiver(mut self, receiver: Address) -> Self {
        self.receiver = Some(receiver);
        self
    }

    /// Pin an absolute expiry (Unix seconds). Mutually exclusive with
    /// [`Self::valid_for`]; setting both fails at the signing chokepoint
    /// rather than on the builder so the request is still constructible
    /// from deserialised input.
    pub fn valid_to(mut self, valid_to: u32) -> Self {
        self.valid_to = Some(valid_to);
        self
    }

    /// Pin a relative expiry (seconds from the server clock). See
    /// [`Self::valid_to`] for the mutual-exclusion rule.
    pub fn valid_for(mut self, valid_for: u32) -> Self {
        self.valid_for = Some(valid_for);
        self
    }

    /// Pin the app-data digest or a canonical-JSON document. See
    /// [`QuoteAppData`].
    pub fn app_data(mut self, app_data: impl Into<QuoteAppData>) -> Self {
        self.app_data = Some(app_data.into());
        self
    }

    /// Pin the partial-fill flag.
    pub fn partially_fillable(mut self, partially_fillable: bool) -> Self {
        self.partially_fillable = Some(partially_fillable);
        self
    }

    /// Pin where the sell token is drawn from (ERC-20 / external / Vault
    /// internal). Defaults server-side to [`SellTokenSource::Erc20`].
    pub fn sell_token_balance(mut self, source: SellTokenSource) -> Self {
        self.sell_token_balance = Some(source);
        self
    }

    /// Pin where the buy token is paid to. Defaults server-side to
    /// [`BuyTokenDestination::Erc20`].
    pub fn buy_token_balance(mut self, destination: BuyTokenDestination) -> Self {
        self.buy_token_balance = Some(destination);
        self
    }

    /// Pin the signing scheme the orderbook should expect.
    pub fn signing_scheme(mut self, scheme: SigningScheme) -> Self {
        self.signing_scheme = Some(scheme);
        self
    }

    /// Gas budget for the on-chain `isValidSignature` callback on
    /// EIP-1271 quotes. Server default is 27_000.
    pub fn verification_gas_limit(mut self, gas: u64) -> Self {
        self.verification_gas_limit = Some(gas);
        self
    }

    /// Mark the request as an on-chain order (EIP-1271 / PreSign).
    pub fn onchain_order(mut self, onchain: bool) -> Self {
        self.onchain_order = Some(onchain);
        self
    }

    /// Hint at the requested price quality.
    pub fn price_quality(mut self, quality: PriceQuality) -> Self {
        self.price_quality = Some(quality);
        self
    }
}

impl<B, F, A> QuoteRequestBuilder<Missing, B, F, A> {
    /// Pin the sell token. Required.
    pub fn sell_token(mut self, sell_token: Address) -> QuoteRequestBuilder<Set, B, F, A> {
        self.sell_token = Some(sell_token);
        self.retag()
    }
}

impl<S, F, A> QuoteRequestBuilder<S, Missing, F, A> {
    /// Pin the buy token. Required.
    pub fn buy_token(mut self, buy_token: Address) -> QuoteRequestBuilder<S, Set, F, A> {
        self.buy_token = Some(buy_token);
        self.retag()
    }
}

impl<S, B, A> QuoteRequestBuilder<S, B, Missing, A> {
    /// Pin the order owner (`from`). Required.
    pub fn from(mut self, from: Address) -> QuoteRequestBuilder<S, B, Set, A> {
        self.from = Some(from);
        self.retag()
    }
}

impl<S, B, F> QuoteRequestBuilder<S, B, F, Missing> {
    /// Pin the pre-fee sell amount for a sell-side quote. Matches
    /// `cow-sdk`'s default. Mutually exclusive with the two other amount
    /// methods — the type-state prevents calling more than one.
    pub fn sell_amount_before_fee(
        mut self,
        amount: U256,
    ) -> QuoteRequestBuilder<S, B, F, Set> {
        self.kind = Some(OrderKind::Sell);
        self.sell_amount_before_fee = Some(amount);
        self.retag()
    }

    /// Pin the post-fee sell amount for a sell-side quote.
    pub fn sell_amount_after_fee(
        mut self,
        amount: U256,
    ) -> QuoteRequestBuilder<S, B, F, Set> {
        self.kind = Some(OrderKind::Sell);
        self.sell_amount_after_fee = Some(amount);
        self.retag()
    }

    /// Pin the post-fee buy amount for a buy-side quote.
    pub fn buy_amount_after_fee(
        mut self,
        amount: U256,
    ) -> QuoteRequestBuilder<S, B, F, Set> {
        self.kind = Some(OrderKind::Buy);
        self.buy_amount_after_fee = Some(amount);
        self.retag()
    }
}

impl QuoteRequestBuilder<Set, Set, Set, Set> {
    /// Project the builder into a [`QuoteRequest`]. Available only once
    /// the four required fields have been provided through the typed
    /// setters above. Construction is infallible at this point: each
    /// [`Set`] marker corresponds to an `Option` the builder has already
    /// filled.
    pub fn build(self) -> QuoteRequest {
        QuoteRequest::from_builder_parts(BuiltParts {
            sell_token: self.sell_token.expect("Set marker guarantees Some"),
            buy_token: self.buy_token.expect("Set marker guarantees Some"),
            from: self.from.expect("Set marker guarantees Some"),
            kind: self.kind.expect("Set marker guarantees Some"),
            sell_amount_before_fee: self.sell_amount_before_fee,
            sell_amount_after_fee: self.sell_amount_after_fee,
            buy_amount_after_fee: self.buy_amount_after_fee,
            receiver: self.receiver,
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
        })
    }
}

/// Internal carrier the builder hands to [`QuoteRequest::from_builder_parts`].
/// Lives behind the same module barrier as `QuoteRequest`'s private
/// amount fields so the kind/amount invariant cannot be broken from
/// outside the crate.
pub(super) struct BuiltParts {
    pub sell_token: Address,
    pub buy_token: Address,
    pub from: Address,
    pub kind: OrderKind,
    pub sell_amount_before_fee: Option<U256>,
    pub sell_amount_after_fee: Option<U256>,
    pub buy_amount_after_fee: Option<U256>,
    pub receiver: Option<Address>,
    pub valid_to: Option<u32>,
    pub valid_for: Option<u32>,
    pub app_data: Option<QuoteAppData>,
    pub partially_fillable: Option<bool>,
    pub sell_token_balance: Option<SellTokenSource>,
    pub buy_token_balance: Option<BuyTokenDestination>,
    pub signing_scheme: Option<SigningScheme>,
    pub verification_gas_limit: Option<u64>,
    pub onchain_order: Option<bool>,
    pub price_quality: Option<PriceQuality>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const SELL: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const BUY: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");
    const FROM: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

    #[test]
    fn builder_matches_sell_before_fee_constructor() {
        let amount = U256::from(100_000_000_u64);
        let built = QuoteRequest::builder()
            .sell_token(SELL)
            .buy_token(BUY)
            .from(FROM)
            .sell_amount_before_fee(amount)
            .build();
        let direct = QuoteRequest::sell_before_fee(SELL, BUY, FROM, amount);
        assert_eq!(built.sell_token, direct.sell_token);
        assert_eq!(built.buy_token, direct.buy_token);
        assert_eq!(built.from, direct.from);
        assert_eq!(built.kind(), direct.kind());
        assert_eq!(
            serde_json::to_value(&built).unwrap(),
            serde_json::to_value(&direct).unwrap(),
        );
        // Round-trips the orderbook's wire-shape invariant.
        built.validate().unwrap();
    }

    #[test]
    fn builder_buy_side_routes_to_buy_amount() {
        let amount = U256::from(5_000_u64);
        let built = QuoteRequest::builder()
            .sell_token(SELL)
            .buy_token(BUY)
            .from(FROM)
            .buy_amount_after_fee(amount)
            .build();
        assert_eq!(built.kind(), OrderKind::Buy);
        built.validate().unwrap();
    }

    #[test]
    fn builder_carries_optional_fields() {
        let request = QuoteRequest::builder()
            .sell_token(SELL)
            .buy_token(BUY)
            .from(FROM)
            .sell_amount_after_fee(U256::from(42_u64))
            .receiver(FROM)
            .valid_for(900)
            .partially_fillable(true)
            .sell_token_balance(SellTokenSource::External)
            .buy_token_balance(BuyTokenDestination::Internal)
            .signing_scheme(SigningScheme::Eip712)
            .onchain_order(false)
            .verification_gas_limit(50_000)
            .price_quality(PriceQuality::Optimal)
            .build();
        assert_eq!(request.receiver, Some(FROM));
        assert_eq!(request.valid_for, Some(900));
        assert_eq!(request.partially_fillable, Some(true));
        assert_eq!(request.sell_token_balance, Some(SellTokenSource::External));
        assert_eq!(request.buy_token_balance, Some(BuyTokenDestination::Internal));
        assert_eq!(request.signing_scheme, Some(SigningScheme::Eip712));
        assert_eq!(request.onchain_order, Some(false));
        assert_eq!(request.verification_gas_limit, Some(50_000));
        assert_eq!(request.price_quality, Some(PriceQuality::Optimal));
    }
}
