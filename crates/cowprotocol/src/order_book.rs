//! Thin client for the CoW Protocol orderbook HTTP API.
//!
//! The first endpoint implemented here is [`OrderBookApi::get_quote`],
//! which mirrors the `getQuote` flow exposed by `@cowprotocol/cow-sdk`
//! and `cow-py`. The request and response shapes reflect the
//! production orderbook OpenAPI as of 2026-05.

use alloy_primitives::{Address, B256, U256, keccak256};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::collections::BTreeMap;
use std::time::Duration;

use crate::app_data::AppDataHash;
use crate::cancellation::{OrderCancellation, SignedOrderCancellations};
use crate::chain::Chain;
use crate::error::{ApiError, Error, Result};
use crate::order::{BuyTokenDestination, Order, OrderData, OrderKind, OrderUid, SellTokenSource};
use crate::signature::EcdsaSignature;
#[cfg(test)]
use crate::signature::Signature;
use crate::signing_scheme::{EcdsaSigningScheme, SigningScheme};

mod orders;
pub use orders::OrderCreation;

/// Default per-request timeout. A stuck or hostile orderbook cannot
/// hold a caller's task open longer; override via
/// [`OrderBookApi::with_client`].
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum HTTP response body. Larger payloads return
/// [`Error::ResponseTooLarge`] before allocating.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// `appData` field on a quote request: 32-byte digest or canonical
/// JSON document. Mirrors `OrderCreationAppData` in
/// `cowprotocol/services::model::quote`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum QuoteAppData {
    /// Pre-computed digest; serialises as `0x`-prefixed hex.
    Hash(AppDataHash),
    /// Canonical JSON; orderbook computes and pins the digest.
    Full(String),
}

impl QuoteAppData {
    /// Construct from a pre-computed digest.
    pub const fn hash(digest: AppDataHash) -> Self {
        Self::Hash(digest)
    }
    /// Construct from a canonical-JSON document.
    pub const fn full(full: String) -> Self {
        Self::Full(full)
    }
}

impl From<AppDataHash> for QuoteAppData {
    fn from(digest: AppDataHash) -> Self {
        Self::Hash(digest)
    }
}

/// Quote price-quality hint. Trades off solver latency against depth.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PriceQuality {
    /// Fastest available answer; solvers may skip simulation.
    Fast,
    /// Default: best solver answer within the quoting window.
    #[default]
    Optimal,
    /// `Optimal` plus on-chain simulation against balances/allowances.
    Verified,
}

/// `GET /api/v1/trades` row: one per `GPv2Settlement.Trade` log.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trade {
    /// Block the settlement transaction was mined in.
    pub block_number: u64,
    /// Log index within the settlement transaction.
    pub log_index: u32,
    /// UID of the filled order.
    pub order_uid: OrderUid,
    /// Owner that signed the order.
    pub owner: Address,
    /// Sold token.
    pub sell_token: Address,
    /// Bought token.
    pub buy_token: Address,
    /// Sell amount net of fee.
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Sell amount before fee deduction.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub sell_amount_before_fees: Option<U256>,
    /// Bought amount.
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Settlement transaction hash, when indexed.
    #[serde(default)]
    pub tx_hash: Option<String>,
}

/// Native-token-denominated price from
/// `GET /api/v1/token/{token}/native_price`. JSON number, not string.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct NativePrice {
    /// Native-token price of one atomic unit of the token.
    pub price: f64,
}

/// Cumulative user surplus from
/// `GET /api/v1/users/{user}/total_surplus`. Decimal string for
/// precision.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotalSurplus {
    /// Cumulative surplus, decimal string in atomic native units.
    pub total_surplus: String,
}

/// `GET /api/v1/auction` snapshot. Permissioned (solver-only); the
/// per-order array is left opaque because `AuctionOrder` drifts
/// across CIPs.
#[serde_as]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Auction {
    /// Monotonically increasing auction id.
    #[serde(default)]
    pub id: Option<u64>,
    /// Anchor block; orders, prices and settlements apply here.
    #[serde(default)]
    pub block: Option<u64>,
    /// Per-order array; left as JSON because the row shape drifts per CIP.
    #[serde(default)]
    pub orders: Option<serde_json::Value>,
    /// External prices, atomic native units per token.
    #[serde_as(as = "Option<BTreeMap<_, DisplayFromStr>>")]
    #[serde(default)]
    pub prices: Option<BTreeMap<Address, U256>>,
    /// JIT owners whose surplus counts toward solver objective.
    #[serde(default)]
    pub surplus_capturing_jit_order_owners: Option<Vec<Address>>,
}

/// `GET /api/v1/token/{token}/metadata`. Both fields are absent for
/// tokens the orderbook has not indexed.
#[serde_as]
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMetadata {
    /// Block of the first trade the orderbook has indexed for the token.
    #[serde(default)]
    pub first_trade_block: Option<u32>,
    /// Last-known native-token price, atomic units per token.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub native_price: Option<U256>,
}

/// `GET /api/v1/app_data/{hash}` body and `put_app_data` input. The
/// orderbook indexes the document under
/// `keccak256(full_app_data.as_bytes())` byte-for-byte.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataDocument {
    /// Raw JSON document; orderbook hashes the bytes verbatim.
    pub full_app_data: String,
}

impl AppDataDocument {
    /// `keccak256(full_app_data.as_bytes())`. Canonicalise via
    /// [`crate::app_data::AppDataDoc::canonical_json`] first if
    /// deterministic key order matters.
    pub fn computed_hash(&self) -> AppDataHash {
        AppDataHash(keccak256(self.full_app_data.as_bytes()))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OrdersByUidsRequest<'a> {
    order_uids: &'a [OrderUid],
}

/// Wire body for `DELETE /api/v1/orders/{uid}`. The UID lives in the URL,
/// so the body is just the signature material; this mirrors the upstream
/// `CancellationPayload` shape in `cowprotocol/services/crates/model/
/// src/order.rs`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancellationPayload<'a> {
    signature: &'a EcdsaSignature,
    signing_scheme: EcdsaSigningScheme,
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    out.push_str(&const_hex::encode(bytes));
    out
}

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

/// `GET /api/v1/orders/{uid}/status` payload. `value` carries solver
/// proposals when relevant (`solved`/`executing`); opaque to stay
/// forward-compatible across CIPs.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuctionStatus {
    /// Stage discriminant.
    #[serde(rename = "type")]
    pub status_type: AuctionStatusType,
    /// Stage-specific payload (e.g., solver proposals), left as JSON.
    #[serde(default)]
    pub value: Vec<serde_json::Value>,
}

/// `POST /api/v1/quote` request. Exactly one of `sell_amount_before_fee`,
/// `sell_amount_after_fee`, `buy_amount_after_fee` must be `Some`, and
/// must agree with [`Self::kind`]. Use the constructors below.
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
    /// Sell-side vs buy-side fix.
    pub kind: OrderKind,
    /// Sell amount before fee (sell-side quote).
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sell_amount_before_fee: Option<U256>,
    /// Sell amount after fee (sell-side quote, fee already folded in).
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sell_amount_after_fee: Option<U256>,
    /// Buy amount after fee (buy-side quote).
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buy_amount_after_fee: Option<U256>,
    /// Absolute expiry; orderbook applies a default when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<u32>,
    /// Relative expiry (seconds from server clock; wire `validFor`).
    /// Mutually exclusive with `valid_to`; default 30 min.
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
    /// Defaults to [`PriceQuality::Optimal`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_quality: Option<PriceQuality>,
}

impl QuoteRequest {
    /// Sell-side quote with pre-fee input amount. Matches
    /// `cow-sdk`'s `getQuote` default.
    pub const fn sell_amount_before_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        sell_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Sell)
            .with_sell_amount_before_fee(sell_amount)
    }

    /// Sell-side quote with post-fee input amount.
    pub const fn sell_amount_after_fee(
        sell_token: Address,
        buy_token: Address,
        from: Address,
        sell_amount: U256,
    ) -> Self {
        Self::new(sell_token, buy_token, from, OrderKind::Sell)
            .with_sell_amount_after_fee(sell_amount)
    }

    /// Buy-side quote.
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

    /// Set a custom recipient for the buy token.
    pub const fn with_receiver(mut self, receiver: Address) -> Self {
        self.receiver = Some(receiver);
        self
    }

    /// Set the order's app-data digest, wrapping it as
    /// [`QuoteAppData::Hash`]. Not `const fn` because the sibling
    /// `Full` variant holds a `String`.
    pub fn with_app_data(mut self, app_data: AppDataHash) -> Self {
        self.app_data = Some(QuoteAppData::Hash(app_data));
        self
    }

    /// Hand the orderbook the canonical JSON document; it computes and
    /// pins the digest.
    pub fn with_app_data_full(mut self, full_app_data: impl Into<String>) -> Self {
        self.app_data = Some(QuoteAppData::Full(full_app_data.into()));
        self
    }

    /// Pin the order's absolute expiry timestamp.
    pub const fn with_valid_to(mut self, valid_to: u32) -> Self {
        self.valid_to = Some(valid_to);
        self
    }

    /// Pin the expiry as seconds from the orderbook's clock. Mutually
    /// exclusive with [`Self::with_valid_to`]; 30-min default when
    /// both are absent.
    pub const fn with_valid_for(mut self, valid_for: u32) -> Self {
        self.valid_for = Some(valid_for);
        self
    }

    /// Gas budget for the on-chain `isValidSignature` callback on
    /// [`SigningScheme::Eip1271`] quotes.
    pub const fn with_verification_gas_limit(mut self, gas: u64) -> Self {
        self.verification_gas_limit = Some(gas);
        self
    }

    /// Mark the resulting order as on-chain-placed (EIP-1271 / PreSign
    /// flows). Lets the orderbook reserve the right simulation budget.
    pub const fn with_onchain_order(mut self, onchain: bool) -> Self {
        self.onchain_order = Some(onchain);
        self
    }

    /// Pin the price-quality regime; defaults to
    /// [`PriceQuality::Optimal`] when absent.
    pub const fn with_price_quality(mut self, quality: PriceQuality) -> Self {
        self.price_quality = Some(quality);
        self
    }

    /// Pin the signing scheme so the orderbook rejects incompatible
    /// quote / order combinations before signing.
    pub const fn with_signing_scheme(mut self, scheme: SigningScheme) -> Self {
        self.signing_scheme = Some(scheme);
        self
    }

    /// Mark the resulting order as partially fillable.
    pub const fn with_partially_fillable(mut self, partially_fillable: bool) -> Self {
        self.partially_fillable = Some(partially_fillable);
        self
    }

    /// Source the sell-side token balance is drawn from.
    pub const fn with_sell_token_balance(mut self, balance: SellTokenSource) -> Self {
        self.sell_token_balance = Some(balance);
        self
    }

    /// Destination the buy-side token balance is paid to.
    pub const fn with_buy_token_balance(mut self, balance: BuyTokenDestination) -> Self {
        self.buy_token_balance = Some(balance);
        self
    }
}

/// Quote response payload. The 12-field signed shape plus the
/// orderbook's expected signing scheme and price metadata. Use
/// [`OrderQuoteResponse::to_signed_order_data`] to project into a
/// signable [`OrderData`] after binding the response to the
/// originating [`QuoteRequest`].
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
    /// `sellToken`, `buyToken`, normalised `receiver`, `kind`, `from`
    /// — plus any caller-pinned `validTo` / `partiallyFillable` /
    /// balance / scheme / `appData` — against `request`; mismatches
    /// fail closed with [`Error::QuoteFieldMismatch`]. Sell orders
    /// fold `feeAmount` into `sellAmount`; `fee_amount` ships as `0`
    /// (solvers price gas at settlement).
    ///
    /// [step3]: https://docs.cow.fi/cow-protocol/howto/integrate/api#step-3-compute-the-amounts-to-sign
    pub fn to_signed_order_data(
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
    /// fee — otherwise the partner-fee base is computed against the
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

    /// Like [`Self::to_signed_order_data`] but runs the full
    /// partner-fee + protocol-fee + slippage composition through
    /// [`Self::amounts_with_costs`] first. Use when the order carries
    /// an `AppDataPartnerFee` or the quote echoes a non-zero
    /// `protocolFeeBps`. Same request-binding guard.
    pub fn to_signed_order_data_with_costs(
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

    fn check_response_matches_request(
        &self,
        request: &QuoteRequest,
        app_data: AppDataHash,
    ) -> Result<()> {
        let q = &self.quote;
        if q.sell_token != request.sell_token {
            return Err(Error::QuoteFieldMismatch {
                field: "sellToken",
                requested: format!("{:#x}", request.sell_token),
                returned: format!("{:#x}", q.sell_token),
            });
        }
        if q.buy_token != request.buy_token {
            return Err(Error::QuoteFieldMismatch {
                field: "buyToken",
                requested: format!("{:#x}", request.buy_token),
                returned: format!("{:#x}", q.buy_token),
            });
        }
        // `from` lives on the response envelope, not OrderQuote. The
        // orderbook indexes the order under this address and the SDK
        // computes the UID from it; a mismatch silently swaps the
        // owner the order would settle for.
        if self.from != request.from {
            return Err(Error::QuoteFieldMismatch {
                field: "from",
                requested: format!("{:#x}", request.from),
                returned: format!("{:#x}", self.from),
            });
        }
        // `kind` is the most damaging swap: flipping Sell <-> Buy
        // reinterprets which side of the order is the fixed leg, so a
        // user-confirmed sell amount can come back as a quoted buy.
        if q.kind != request.kind {
            return Err(Error::QuoteFieldMismatch {
                field: "kind",
                requested: format!("{:?}", request.kind),
                returned: format!("{:?}", q.kind),
            });
        }
        // Treat `None`, `Some(ZERO)` and `Some(owner)` as "owner
        // receives" on both sides; the orderbook normalises the same
        // way. Comparing only when `request.receiver` is `Some` would
        // skip validation for the common default-receiver case and let
        // a hostile orderbook redirect proceeds to an attacker.
        let normalise = |owner: Address, receiver: Option<Address>| match receiver {
            Some(addr) if addr == Address::ZERO || addr == owner => None,
            other => other,
        };
        let req = normalise(request.from, request.receiver);
        let got = normalise(request.from, q.receiver);
        if req != got {
            return Err(Error::QuoteFieldMismatch {
                field: "receiver",
                requested: format!("{req:?}"),
                returned: format!("{got:?}"),
            });
        }
        // Conditional fields: only enforce when the request pinned
        // them, otherwise the orderbook is free to fill in defaults.
        if let Some(valid_to) = request.valid_to
            && q.valid_to != valid_to
        {
            return Err(Error::QuoteFieldMismatch {
                field: "validTo",
                requested: valid_to.to_string(),
                returned: q.valid_to.to_string(),
            });
        }
        if let Some(partially_fillable) = request.partially_fillable
            && q.partially_fillable != partially_fillable
        {
            return Err(Error::QuoteFieldMismatch {
                field: "partiallyFillable",
                requested: partially_fillable.to_string(),
                returned: q.partially_fillable.to_string(),
            });
        }
        if let Some(src) = request.sell_token_balance
            && q.sell_token_balance != src
        {
            return Err(Error::QuoteFieldMismatch {
                field: "sellTokenBalance",
                requested: format!("{src:?}"),
                returned: format!("{:?}", q.sell_token_balance),
            });
        }
        if let Some(dst) = request.buy_token_balance
            && q.buy_token_balance != dst
        {
            return Err(Error::QuoteFieldMismatch {
                field: "buyTokenBalance",
                requested: format!("{dst:?}"),
                returned: format!("{:?}", q.buy_token_balance),
            });
        }
        if let Some(scheme) = request.signing_scheme
            && q.signing_scheme != scheme
        {
            return Err(Error::QuoteFieldMismatch {
                field: "signingScheme",
                requested: format!("{scheme:?}"),
                returned: format!("{:?}", q.signing_scheme),
            });
        }
        if let Some(QuoteAppData::Hash(requested_hash)) = request.app_data.as_ref()
            && *requested_hash != app_data
        {
            return Err(Error::QuoteFieldMismatch {
                field: "appData",
                requested: requested_hash.to_string(),
                returned: app_data.to_string(),
            });
        }
        Ok(())
    }
}

/// `POST /api/v1/quote` response body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderQuoteResponse {
    /// Quoted [`OrderQuote`]; project via [`Self::to_signed_order_data`].
    pub quote: OrderQuote,
    /// Order owner; echoed from the request.
    pub from: Address,
    /// ISO-8601 expiry of the quote.
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

/// Thin client for the CoW Protocol orderbook.
#[derive(Debug, Clone)]
pub struct OrderBookApi {
    base_url: url::Url,
    client: reqwest::Client,
}

impl OrderBookApi {
    /// Client for the production orderbook on `chain`.
    pub fn new(chain: Chain) -> Self {
        Self::new_with_base_url(ensure_trailing_slash(chain.orderbook_base_url()))
    }

    /// Client against an arbitrary base URL (staging, recorded mock,
    /// etc.). The default reqwest client enforces
    /// [`DEFAULT_HTTP_TIMEOUT`].
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
        }
    }

    /// Base URL with the trailing slash path joining relies on.
    pub const fn base_url(&self) -> &url::Url {
        &self.base_url
    }

    /// `POST /api/v1/quote`.
    pub async fn get_quote(&self, request: &QuoteRequest) -> Result<OrderQuoteResponse> {
        self.post_json("api/v1/quote", request).await
    }

    /// `POST /api/v1/orders`. Returns the assigned 56-byte UID.
    pub async fn post_order(&self, order: &OrderCreation) -> Result<OrderUid> {
        self.post_json("api/v1/orders", order).await
    }

    /// `GET /api/v1/orders/{uid}`.
    pub async fn get_order(&self, uid: &OrderUid) -> Result<Order> {
        self.get_json(&format!("api/v1/orders/{uid}")).await
    }

    /// `GET /api/v1/orders/{uid}/status`.
    pub async fn get_order_status(&self, uid: &OrderUid) -> Result<AuctionStatus> {
        self.get_json(&format!("api/v1/orders/{uid}/status")).await
    }

    /// Poll [`Self::get_order`] until `should_stop` returns `true`,
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
            let order = self.get_order(uid).await?;
            if should_stop(&order) {
                return Ok(order);
            }
            sleep().await;
        }
    }

    /// `tokio::time::sleep`-backed [`Self::poll_until`] that stops on
    /// a terminal status or when `deadline` elapses. Non-wasm only;
    /// wasm callers compose `poll_until` with their own sleep.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn wait_for_order_fulfilled(
        &self,
        uid: &OrderUid,
        poll_interval: std::time::Duration,
        deadline: Option<std::time::Duration>,
    ) -> Result<Order> {
        let start = std::time::Instant::now();
        let interval = poll_interval;
        self.poll_until(
            uid,
            |order| {
                matches!(
                    order.status,
                    crate::OrderStatus::Fulfilled
                        | crate::OrderStatus::Cancelled
                        | crate::OrderStatus::Expired
                ) || deadline.is_some_and(|d| start.elapsed() >= d)
            },
            move || tokio::time::sleep(interval),
        )
        .await
    }

    /// `GET /api/v1/account/{owner}/orders`. Most recent first. Pass
    /// `None` for both pagers to use the server defaults.
    pub async fn account_orders(
        &self,
        owner: Address,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<Order>> {
        let mut url = self
            .base_url
            .join(&format!("api/v1/account/{owner:?}/orders"))?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(offset) = offset {
                q.append_pair("offset", &offset.to_string());
            }
            if let Some(limit) = limit {
                q.append_pair("limit", &limit.to_string());
            }
        }
        let response = self.client.get(url).send().await?;
        Self::decode_response(response).await
    }

    /// `POST /api/v1/orders/by_uids`. Returns orders in request
    /// order; unknown UIDs are omitted.
    pub async fn get_orders_by_uids(&self, uids: &[OrderUid]) -> Result<Vec<Order>> {
        self.post_json(
            "api/v1/orders/by_uids",
            &OrdersByUidsRequest { order_uids: uids },
        )
        .await
    }

    /// `GET /api/v1/trades?owner=...`.
    pub async fn trades_by_owner(&self, owner: Address) -> Result<Vec<Trade>> {
        let mut url = self.base_url.join("api/v1/trades")?;
        url.query_pairs_mut()
            .append_pair("owner", &format!("{owner:?}"));
        let response = self.client.get(url).send().await?;
        Self::decode_response(response).await
    }

    /// `GET /api/v1/trades?orderUid=...`.
    pub async fn trades_by_order_uid(&self, uid: &OrderUid) -> Result<Vec<Trade>> {
        let mut url = self.base_url.join("api/v1/trades")?;
        url.query_pairs_mut()
            .append_pair("orderUid", &uid.to_string());
        let response = self.client.get(url).send().await?;
        Self::decode_response(response).await
    }

    /// `GET /api/v1/token/{token}/native_price`. One atomic unit of
    /// `token` in the chain's native gas token; solvers use this to
    /// denominate gas uniformly across pairs.
    pub async fn native_price(&self, token: Address) -> Result<NativePrice> {
        self.get_json(&format!("api/v1/token/{token:?}/native_price"))
            .await
    }

    /// `GET /api/v1/token/{token}/metadata`.
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
    pub async fn get_auction(&self) -> Result<Auction> {
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
    pub async fn get_app_data(&self, hash: &AppDataHash) -> Result<AppDataDocument> {
        let document: AppDataDocument = self
            .get_json(&format!("api/v1/app_data/{}", hex_string(hash.as_ref())))
            .await?;
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
        let url = self
            .base_url
            .join(&format!("api/v1/app_data/{}", hex_string(hash.as_ref())))?;
        let response = self.client.put(url).json(document).send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = read_capped_text(response).await?;
        serde_json::from_str::<ApiError>(&text).map_or_else(
            |_| Err(Error::UnexpectedStatus { status, body: text }),
            |api| Err(Error::OrderbookApi { status, api }),
        )
    }

    /// `PUT /api/v1/app_data`. Lets the orderbook compute and return
    /// the digest. Prefer [`Self::put_app_data`] when the caller has
    /// already pinned an [`AppDataHash`] in a signed order.
    pub async fn upload_app_data(&self, document: &AppDataDocument) -> Result<AppDataHash> {
        self.put_json("api/v1/app_data", document).await
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
        } else if let Ok(api) = serde_json::from_str::<ApiError>(&text) {
            Err(Error::OrderbookApi { status, api })
        } else {
            Err(Error::UnexpectedStatus { status, body: text })
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
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = read_capped_text(response).await?;
        serde_json::from_str::<ApiError>(&text).map_or_else(
            |_| Err(Error::UnexpectedStatus { status, body: text }),
            |api| Err(Error::OrderbookApi { status, api }),
        )
    }

    /// `DELETE /api/v1/orders/{uid}`. Soft-cancel: an order already
    /// picked up by a solver may still settle. For pre-signed and
    /// EthFlow orders, invalidate on-chain instead.
    pub async fn cancel_order(&self, cancellation: &OrderCancellation) -> Result<()> {
        let url = self
            .base_url
            .join(&format!("api/v1/orders/{}", cancellation.order_uid))?;
        let body = CancellationPayload {
            signature: &cancellation.signature,
            signing_scheme: cancellation.signing_scheme,
        };
        let response = self.client.delete(url).json(&body).send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = read_capped_text(response).await?;
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

    async fn decode_response<T>(response: reqwest::Response) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = read_capped_text(response).await?;
        if status.is_success() {
            serde_json::from_str(&text).map_err(Error::from)
        } else if let Ok(api) = serde_json::from_str::<ApiError>(&text) {
            Err(Error::OrderbookApi { status, api })
        } else {
            Err(Error::UnexpectedStatus { status, body: text })
        }
    }
}

/// Read a response body as UTF-8 text, rejecting payloads above
/// [`MAX_RESPONSE_BYTES`]. Early-rejects on `Content-Length` and
/// re-checks the materialised body as a backstop.
async fn read_capped_text(response: reqwest::Response) -> Result<String> {
    if let Some(declared_len) = response.content_length()
        && declared_len > MAX_RESPONSE_BYTES as u64
    {
        return Err(Error::ResponseTooLarge {
            max: MAX_RESPONSE_BYTES,
        });
    }
    let text = response.text().await?;
    if text.len() > MAX_RESPONSE_BYTES {
        return Err(Error::ResponseTooLarge {
            max: MAX_RESPONSE_BYTES,
        });
    }
    Ok(text)
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
    use crate::app_data::{EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON};

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
    fn quote_request_emits_app_data_hash_form() {
        let request = fixture_quote_request().with_app_data(crate::EMPTY_APP_DATA_HASH);
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(
            body["appData"],
            serde_json::Value::String(
                "0xb48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d".to_owned()
            )
        );
        // QuoteRequest's `appData` field is overloaded by content; there
        // is no separate `appDataHash` key on the quote wire shape.
        assert!(body.get("appDataHash").is_none());
    }

    #[test]
    fn quote_request_emits_app_data_full_form() {
        let request = fixture_quote_request().with_app_data_full(crate::EMPTY_APP_DATA_JSON);
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(body["appData"], serde_json::Value::String("{}".to_owned()));
        assert!(body.get("appDataHash").is_none());
    }

    #[test]
    fn quote_request_round_trips_price_quality_field() {
        let request = QuoteRequest::sell_amount_before_fee(USDC, DAI, OWNER, U256::from(1_u64))
            .with_price_quality(PriceQuality::Verified);
        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(body["priceQuality"], "verified");
    }

    #[test]
    fn price_quality_serialises_lowercase() {
        for (variant, wire) in [
            (PriceQuality::Fast, "\"fast\""),
            (PriceQuality::Optimal, "\"optimal\""),
            (PriceQuality::Verified, "\"verified\""),
        ] {
            let serialised = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialised, wire);
            let parsed: PriceQuality = serde_json::from_str(wire).unwrap();
            assert_eq!(parsed, variant);
        }
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
    fn quote_request_emits_valid_for_and_eip1271_extras() {
        let request = fixture_quote_request()
            .with_valid_for(1_800)
            .with_signing_scheme(SigningScheme::Eip1271)
            .with_verification_gas_limit(50_000)
            .with_onchain_order(true);
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(body["validFor"], serde_json::Value::from(1_800));
        assert_eq!(
            body["signingScheme"],
            serde_json::Value::String("eip1271".into())
        );
        assert_eq!(
            body["verificationGasLimit"],
            serde_json::Value::from(50_000)
        );
        assert_eq!(body["onchainOrder"], serde_json::Value::from(true));
        // validTo stays absent when only validFor is set.
        assert!(body.get("validTo").is_none());
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
    fn hex_string_lowercases_with_prefix() {
        assert_eq!(hex_string(&[0xab, 0xcd]), "0xabcd");
        assert_eq!(hex_string(&[]), "0x");
    }

    #[test]
    fn native_price_deserialises_float_number() {
        let body = serde_json::json!({ "price": 1.23e9 });
        let parsed: NativePrice = serde_json::from_value(body).unwrap();
        assert!((parsed.price - 1.23e9).abs() < 1.0);
    }

    #[test]
    fn app_data_document_round_trips() {
        let doc = AppDataDocument {
            full_app_data: "{}".into(),
        };
        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json, serde_json::json!({ "fullAppData": "{}" }));
        let parsed: AppDataDocument = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.full_app_data, "{}");
    }

    #[test]
    fn total_surplus_keeps_decimal_string() {
        let body = serde_json::json!({ "totalSurplus": "1234567.89" });
        let parsed: TotalSurplus = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.total_surplus, "1234567.89");
    }

    #[test]
    fn orders_by_uids_request_serialises_with_camel_case_key() {
        let uids = vec![OrderUid([0x11; 56])];
        let req = OrdersByUidsRequest { order_uids: &uids };
        let body = serde_json::to_value(&req).unwrap();
        assert!(body["orderUids"].is_array());
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
        assert_eq!(response.quote.app_data, AppDataHash::default());

        // The order data projected from the quote round-trips into the
        // signed-payload type and hashes deterministically.
        let order_data = response
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();
        let _ = order_data.hash_struct();
    }

    fn load_mainnet_quote() -> OrderQuoteResponse {
        serde_json::from_str(include_str!("../tests/fixtures/quote-mainnet.json")).unwrap()
    }

    /// `to_signed_order_data` for a sell-side quote adds `feeAmount` back
    /// into `sellAmount` and zeroes the fee: the documented submission
    /// adjustment.
    #[test]
    fn to_signed_order_data_adjusts_sell_amount_and_zeroes_fee() {
        let quote = load_mainnet_quote();
        assert_eq!(quote.quote.kind, OrderKind::Sell);
        let original_sell = quote.quote.sell_amount;
        let original_fee = quote.quote.fee_amount;

        let signed = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();

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
        // Match the mutated `kind` so the request-bound projection
        // does not reject this synthetic Buy-side quote.
        let request =
            QuoteRequest::buy_amount_after_fee(USDC, DAI, OWNER, U256::from(100_000_000_u64));

        let signed = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap();

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
        let signed = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();
        let signature = Signature::default_with(SigningScheme::Eip712);
        let creation = OrderCreation::from_signed_order_data(
            signed,
            signature,
            quote.from,
            EMPTY_APP_DATA_JSON.to_owned(),
            Some(quote.id),
        )
        .unwrap();

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

    /// JSON round-trip for [`OrderCreation`]. Deserialising what we
    /// serialise lets wasm / JS consumers hand the type back across the
    /// boundary without losing fields.
    fn round_trip_with_signature(signature: Signature) -> OrderCreation {
        let quote = load_mainnet_quote();
        let signed = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();
        let original = OrderCreation::from_signed_order_data(
            signed,
            signature,
            quote.from,
            EMPTY_APP_DATA_JSON.to_owned(),
            Some(quote.id),
        )
        .unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: OrderCreation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sell_token, original.sell_token);
        assert_eq!(parsed.buy_token, original.buy_token);
        assert_eq!(parsed.sell_amount, original.sell_amount);
        assert_eq!(parsed.buy_amount, original.buy_amount);
        assert_eq!(parsed.from, original.from);
        assert_eq!(parsed.quote_id, original.quote_id);
        assert_eq!(parsed.app_data, original.app_data);
        assert_eq!(parsed.app_data_hash, original.app_data_hash);
        assert_eq!(parsed.signing_scheme, original.signing_scheme);
        parsed
    }

    #[test]
    fn order_creation_json_round_trip() {
        let parsed = round_trip_with_signature(Signature::default_with(SigningScheme::Eip712));
        assert!(matches!(parsed.signature, Signature::Eip712(_)));
    }

    /// EthSign round-trip exercises the 65-byte EcdsaSignature path with a
    /// non-zero v; `Signature::from_bytes` normalises 0 / 27 to 27 and
    /// 1 / 28 to 28, so we use 27 here to keep the wire shape stable.
    #[test]
    fn order_creation_json_round_trip_ethsign() {
        let bytes = {
            let mut buf = [0u8; 65];
            buf[64] = 27;
            buf
        };
        let signature = EcdsaSignature::from_bytes(&bytes)
            .unwrap()
            .to_signature(EcdsaSigningScheme::EthSign);
        let parsed = round_trip_with_signature(signature);
        match &parsed.signature {
            Signature::EthSign(sig) => assert_eq!(sig.to_bytes(), bytes),
            other => panic!("expected EthSign, got {other:?}"),
        }
    }

    /// Eip1271 carries variable-length wrapper bytes; the round trip needs
    /// to preserve them exactly (length and content).
    #[test]
    fn order_creation_json_round_trip_eip1271() {
        let payload: Vec<u8> = (0..32).collect();
        let signature = Signature::Eip1271(payload.clone());
        let parsed = round_trip_with_signature(signature);
        match &parsed.signature {
            Signature::Eip1271(bytes) => assert_eq!(bytes, &payload),
            other => panic!("expected Eip1271, got {other:?}"),
        }
    }

    /// PreSign carries no bytes; the on-wire `signature` is the empty hex
    /// string `0x`. Make sure the round trip survives that.
    #[test]
    fn order_creation_json_round_trip_presign() {
        let parsed = round_trip_with_signature(Signature::PreSign);
        assert!(matches!(parsed.signature, Signature::PreSign));
    }

    /// JSON round-trip for [`QuoteRequest`]: serialise, deserialise,
    /// serialise again, compare the JSON values. Locks the wire shape
    /// against drift introduced by future serde-attribute tweaks.
    #[test]
    fn quote_request_json_round_trip() {
        use alloy_primitives::address;
        let original = QuoteRequest::sell_amount_before_fee(
            address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
            address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            U256::from(100_000_000_u64),
        );
        let first = serde_json::to_value(&original).unwrap();
        let parsed: QuoteRequest = serde_json::from_value(first.clone()).unwrap();
        let second = serde_json::to_value(&parsed).unwrap();
        assert_eq!(first, second);
    }

    /// `to_signed_order_data` rejects an overflowing sell-side adjustment
    /// instead of silently saturating, which would ship an on-chain order
    /// different from what the user signed off on.
    #[test]
    fn to_signed_order_data_rejects_overflowing_sell_adjustment() {
        let mut quote = load_mainnet_quote();
        quote.quote.kind = OrderKind::Sell;
        quote.quote.sell_amount = U256::MAX;
        quote.quote.fee_amount = U256::from(1u64);

        let err = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(matches!(err, Error::QuoteAmountOverflow { .. }));
    }

    /// Same fail-closed contract as the basic path: the
    /// fee-composition projection used by
    /// [`OrderQuoteResponse::to_signed_order_data_with_costs`] must
    /// reject an overflowing sell-side adjustment rather than copy a
    /// saturated `U256::MAX` into the signed `OrderData`.
    #[test]
    fn to_signed_order_data_with_costs_rejects_overflowing_sell_adjustment() {
        let mut quote = load_mainnet_quote();
        quote.quote.kind = OrderKind::Sell;
        quote.quote.sell_amount = U256::MAX;
        quote.quote.fee_amount = U256::from(1u64);

        let err = quote
            .to_signed_order_data_with_costs(
                &fixture_quote_request(),
                0,
                0,
                None,
                EMPTY_APP_DATA_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::QuoteFeeMathOverflow { .. }),
            "got: {err:?}",
        );
    }

    /// `OrderCreation::from_signed_order_data` rejects a zero `from`
    /// address locally rather than letting the orderbook reject it.
    #[test]
    fn order_creation_rejects_zero_from_address() {
        let err = OrderCreation::from_signed_order_data(
            OrderData::default(),
            Signature::default_with(SigningScheme::Eip712),
            Address::ZERO,
            EMPTY_APP_DATA_JSON.to_owned(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::OrderCreationInvalid { field: "from", .. }),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a tampered `buy_token`
    /// instead of letting the user sign an order paying out a different
    /// asset than they asked for.
    #[test]
    fn to_signed_order_data_rejects_swapped_buy_token() {
        use alloy_primitives::address;
        let quote = load_mainnet_quote();
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            // Asks for a different buy token than the response carries.
            address!("dead000000000000000000000000000000000000"),
            quote.from,
            U256::from(1u64),
        );
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "buyToken",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` returns an `OrderData` whose 12
    /// signed fields mirror the response when every caller-authorised
    /// field matches the request. The amount-side check pins the
    /// documented sell-side fee adjustment.
    #[test]
    fn to_signed_order_data_passes_when_request_matches_response() {
        let quote = load_mainnet_quote();
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        );
        let signed = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap();
        assert_eq!(signed.sell_token, quote.quote.sell_token);
        assert_eq!(signed.buy_token, quote.quote.buy_token);
        assert_eq!(signed.receiver, quote.quote.receiver);
        assert_eq!(signed.kind, quote.quote.kind);
        assert_eq!(signed.app_data, EMPTY_APP_DATA_HASH);
        assert_eq!(signed.fee_amount, U256::ZERO);
        assert_eq!(
            signed.sell_amount,
            quote.quote.sell_amount + quote.quote.fee_amount,
        );
    }

    /// R20: `to_signed_order_data` rejects a quote that swaps the
    /// receiver when the request omitted it (default owner-receives).
    /// Without normalising both sides, a hostile orderbook could
    /// redirect proceeds to an attacker while the caller never set a
    /// receiver in the request.
    #[test]
    fn to_signed_order_data_rejects_swapped_receiver_when_request_omits_receiver() {
        use alloy_primitives::address;
        let mut quote = load_mainnet_quote();
        quote.quote.receiver = Some(address!("dead00000000000000000000000000000000beef"));
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        );
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "receiver",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: a response that echoes `receiver = from` for a request that
    /// omitted receiver is semantically identical to "owner receives"
    /// and must not trip a mismatch. Mirrors the orderbook's
    /// normalisation.
    #[test]
    fn to_signed_order_data_accepts_owner_receiver_echo_when_request_omits_receiver() {
        let mut quote = load_mainnet_quote();
        quote.quote.receiver = Some(quote.from);
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        );
        quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .expect("owner-as-receiver echo should normalise to owner-receives");
    }

    /// R20: `to_signed_order_data_with_costs` shares the same
    /// `check_response_matches_request` guard and must reject the
    /// default-receiver swap on the costs-aware path too.
    #[test]
    fn to_signed_order_data_with_costs_rejects_swapped_receiver_when_request_omits_receiver() {
        use alloy_primitives::address;
        let mut quote = load_mainnet_quote();
        quote.quote.receiver = Some(address!("dead00000000000000000000000000000000beef"));
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        );
        let err = quote
            .to_signed_order_data_with_costs(&request, 0, 0, None, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "receiver",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose returned
    /// `app_data` digest disagrees with the digest the caller pinned in
    /// the request.
    #[test]
    fn to_signed_order_data_rejects_swapped_app_data() {
        let quote = load_mainnet_quote();
        let pinned = AppDataHash::from([0x42; 32]);
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        )
        .with_app_data(pinned);
        // The response's digest is `EMPTY_APP_DATA_HASH`, not `pinned`.
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "appData",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose `kind` flips
    /// the side of the order the user authorised. A Sell intent
    /// returning as Buy reinterprets which side is the fixed leg, so
    /// signing would commit to a different trade than the user saw.
    #[test]
    fn to_signed_order_data_rejects_swapped_kind() {
        let mut quote = load_mainnet_quote();
        quote.quote.kind = OrderKind::Buy;
        let request = fixture_quote_request();
        assert_eq!(request.kind, OrderKind::Sell);
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(&err, Error::QuoteFieldMismatch { field: "kind", .. }),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose envelope
    /// `from` does not match the request. The orderbook indexes the
    /// order under this address and the SDK derives the UID from it,
    /// so a swap silently changes the owner the order would settle
    /// for.
    #[test]
    fn to_signed_order_data_rejects_swapped_from() {
        use alloy_primitives::address;
        let mut quote = load_mainnet_quote();
        quote.from = address!("dead000000000000000000000000000000000000");
        let err = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(&err, Error::QuoteFieldMismatch { field: "from", .. }),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose `validTo`
    /// disagrees with the absolute expiry the caller pinned via
    /// [`QuoteRequest::with_valid_to`]. Unpinned `validTo` stays the
    /// orderbook's prerogative.
    #[test]
    fn to_signed_order_data_rejects_swapped_valid_to_when_request_pins_it() {
        let quote = load_mainnet_quote();
        let request = fixture_quote_request().with_valid_to(quote.quote.valid_to.wrapping_add(1));
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "validTo",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose
    /// `partiallyFillable` flips the value the caller pinned. Without
    /// the check, a hostile orderbook could partially fill an order
    /// the user expected to be fill-or-kill (or vice versa).
    #[test]
    fn to_signed_order_data_rejects_swapped_partially_fillable_when_request_pins_it() {
        let mut quote = load_mainnet_quote();
        quote.quote.partially_fillable = true;
        let request = fixture_quote_request().with_partially_fillable(false);
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "partiallyFillable",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose
    /// `sellTokenBalance` swaps the source the caller pinned (ERC20
    /// vs Vault internal balance vs external).
    #[test]
    fn to_signed_order_data_rejects_swapped_sell_token_balance_when_request_pins_it() {
        let mut quote = load_mainnet_quote();
        quote.quote.sell_token_balance = SellTokenSource::Internal;
        let request = fixture_quote_request().with_sell_token_balance(SellTokenSource::Erc20);
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "sellTokenBalance",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose
    /// `buyTokenBalance` swaps the destination the caller pinned.
    #[test]
    fn to_signed_order_data_rejects_swapped_buy_token_balance_when_request_pins_it() {
        let mut quote = load_mainnet_quote();
        quote.quote.buy_token_balance = BuyTokenDestination::Internal;
        let request = fixture_quote_request().with_buy_token_balance(BuyTokenDestination::Erc20);
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "buyTokenBalance",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R20: `to_signed_order_data` rejects a quote whose
    /// `signingScheme` swaps the scheme the caller pinned. The signed
    /// payload itself does not commit to the scheme, but the
    /// orderbook routes the resulting order under the wire scheme,
    /// and a smart-contract caller pinning EIP-1271 must not have it
    /// silently downgraded to PreSign.
    #[test]
    fn to_signed_order_data_rejects_swapped_signing_scheme_when_request_pins_it() {
        let mut quote = load_mainnet_quote();
        quote.quote.signing_scheme = SigningScheme::PreSign;
        let request = fixture_quote_request().with_signing_scheme(SigningScheme::Eip712);
        let err = quote
            .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::QuoteFieldMismatch {
                    field: "signingScheme",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R21: `from_signed_order_data` rejects an `app_data` JSON document
    /// whose keccak256 does not match the `OrderData::app_data` digest
    /// the user signed against.
    #[test]
    fn from_signed_order_data_rejects_app_data_digest_mismatch() {
        let quote = load_mainnet_quote();
        let signed = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();
        let err = OrderCreation::from_signed_order_data(
            signed,
            Signature::default_with(SigningScheme::Eip712),
            quote.from,
            // Document does NOT match `EMPTY_APP_DATA_HASH`.
            r#"{"version":"1.6.0","metadata":{}}"#.to_owned(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::OrderCreationInvalid {
                    field: "app_data",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// R21b: deserialising an `OrderCreation` JSON whose `appData` JSON
    /// document does not hash to `appDataHash` is rejected before the
    /// body can be relayed downstream. Mirrors R21 for the wire-path
    /// (`TryFrom<OrderCreationWire>`), defending callers that relay an
    /// `OrderCreation` they received from an untrusted source.
    #[test]
    fn deserialise_rejects_app_data_digest_mismatch() {
        let quote = load_mainnet_quote();
        let signed = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();
        let mut body = serde_json::to_value(
            OrderCreation::from_signed_order_data(
                signed,
                Signature::default_with(SigningScheme::Eip712),
                quote.from,
                EMPTY_APP_DATA_JSON.to_owned(),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        // Swap the document for one whose keccak256 differs from
        // `EMPTY_APP_DATA_HASH` while leaving `appDataHash` untouched.
        body["appData"] = serde_json::Value::String(r#"{"version":"1.6.0","metadata":{}}"#.into());
        let err = serde_json::from_value::<OrderCreation>(body).unwrap_err();
        assert!(
            err.to_string().contains("app_data"),
            "expected app_data digest mismatch surfaced through serde, got: {err}"
        );
    }

    /// R22: `verify_owner` rejects a synthesised EIP-1271 / PreSign body
    /// whose `from` is the zero address. The `Ok` arm must never act as
    /// a positive owner assertion for an obviously bogus body.
    #[test]
    fn verify_owner_rejects_zero_from_for_onchain_schemes() {
        // Build the OrderCreation directly, bypassing
        // `from_signed_order_data` (which already rejects zero-from), so
        // we reproduce the wire shape an attacker could synthesise.
        let creation = OrderCreation {
            sell_token: Address::ZERO,
            buy_token: Address::ZERO,
            receiver: None,
            sell_amount: U256::ZERO,
            buy_amount: U256::ZERO,
            valid_to: 0,
            app_data: EMPTY_APP_DATA_JSON.to_owned(),
            app_data_hash: EMPTY_APP_DATA_HASH,
            fee_amount: U256::ZERO,
            kind: OrderKind::Sell,
            partially_fillable: false,
            sell_token_balance: SellTokenSource::default(),
            buy_token_balance: BuyTokenDestination::default(),
            signing_scheme: SigningScheme::PreSign,
            signature: Signature::PreSign,
            from: Address::ZERO,
            quote_id: None,
        };
        let err = creation
            .verify_owner(&crate::domain::DomainSeparator::default())
            .unwrap_err();
        assert!(matches!(
            err,
            crate::signature::SignatureError::SignerMismatch { .. }
        ));
    }

    /// R23: `verify_owner` rejects an ECDSA-signed body whose declared
    /// `from` is not the address recovered from the signature. This is
    /// the typo-and-wallet-switch case the WASM
    /// `build_order_creation` shim relies on to fail fast client-side
    /// instead of pushing the bad pair to the orderbook.
    #[test]
    fn verify_owner_rejects_signer_mismatch_for_ecdsa() {
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::from_bytes(&U256::from(1u64).to_be_bytes().into()).unwrap();
        let real_signer = signer.address();
        let impostor = alloy_primitives::address!("dead0000dead0000dead0000dead0000dead0000");
        assert_ne!(real_signer, impostor);

        let domain = crate::domain::DomainSeparator(alloy_primitives::B256::repeat_byte(0xab).0);
        let order_data = OrderData {
            sell_token: alloy_primitives::address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            buy_token: alloy_primitives::address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            receiver: None,
            sell_amount: U256::from(1_000_000u64),
            buy_amount: U256::from(999u64),
            valid_to: 0xffffffff,
            app_data: EMPTY_APP_DATA_HASH,
            fee_amount: U256::ZERO,
            kind: OrderKind::Sell,
            partially_fillable: false,
            sell_token_balance: SellTokenSource::default(),
            buy_token_balance: BuyTokenDestination::default(),
        };
        let signature = order_data
            .sign(EcdsaSigningScheme::Eip712, &domain, &signer)
            .unwrap();
        // Build the body with the *wrong* declared owner.
        let creation = OrderCreation::from_signed_order_data(
            order_data,
            signature,
            impostor,
            EMPTY_APP_DATA_JSON.to_owned(),
            None,
        )
        .unwrap();
        let err = creation.verify_owner(&domain).unwrap_err();
        match err {
            crate::signature::SignatureError::SignerMismatch {
                declared,
                recovered,
            } => {
                assert_eq!(declared, impostor);
                assert_eq!(recovered, real_signer);
            }
            other => panic!("expected SignerMismatch, got {other:?}"),
        }
    }

    /// `quoteId` is omitted when not provided rather than emitted as `null`.
    #[test]
    fn order_creation_skips_optional_quote_id() {
        let quote = load_mainnet_quote();
        let signed = quote
            .to_signed_order_data(&fixture_quote_request(), EMPTY_APP_DATA_HASH)
            .unwrap();
        let creation = OrderCreation::from_signed_order_data(
            signed,
            Signature::default_with(SigningScheme::Eip712),
            quote.from,
            EMPTY_APP_DATA_JSON.to_owned(),
            None,
        )
        .unwrap();
        let body = serde_json::to_value(&creation).unwrap();
        assert!(body.get("quoteId").is_none());
    }
}
