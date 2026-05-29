//! Thin client for the CoW Protocol orderbook HTTP API.
//!
//! The first endpoint implemented here is [`OrderBookApi::quote`],
//! which mirrors the `getQuote` flow exposed by `@cowprotocol/cow-sdk`
//! and `cow-py`. The request and response shapes reflect the
//! production orderbook OpenAPI as of 2026-05.

use alloy_primitives::{Address, B256, U256, keccak256};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::collections::BTreeMap;
use std::time::Duration;

use crate::app_data::AppDataHash;
#[cfg(feature = "http-client")]
use crate::cancellation::{SignedOrderCancellation, SignedOrderCancellations};
#[cfg(feature = "http-client")]
use crate::chain::Chain;
#[cfg(feature = "http-client")]
use crate::error::ApiError;
use crate::error::{Error, Result};
#[cfg(feature = "http-client")]
use crate::order::Order;
use crate::order::{BuyTokenDestination, OrderData, OrderKind, OrderUid, SellTokenSource};
#[cfg(test)]
use crate::signature::Signature;
#[cfg(feature = "http-client")]
use crate::signature::{EcdsaSignature, ecdsa_wire};
#[cfg(feature = "http-client")]
use crate::signing_scheme::EcdsaSigningScheme;
use crate::signing_scheme::SigningScheme;

mod orders;
pub use orders::OrderCreation;

/// Default per-request timeout. A stuck or hostile orderbook cannot
/// hold a caller's task open longer; override via
/// [`OrderBookApi::with_client`]. Exposed feature-independently so the
/// `cow-sdk-wasm` fetch transport can reuse it without pulling in the
/// `http-client` stack.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum HTTP response body. Larger payloads return
/// [`Error::ResponseTooLarge`] before allocating. Exposed
/// feature-independently so the `cow-sdk-wasm` fetch transport can reuse
/// it without pulling in the `http-client` stack.
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
    /// Best solver answer within the quoting window.
    Optimal,
    /// `Optimal` plus on-chain simulation against balances/allowances.
    /// The server's default when `priceQuality` is omitted (openapi
    /// `OrderQuoteRequest.priceQuality.default: verified`), so it is the
    /// [`Default`] here too.
    #[default]
    Verified,
}

/// `GET /api/v2/trades` row: one per `GPv2Settlement.Trade` log.
///
/// The openapi `Trade` schema also carries `executedProtocolFees`; it is
/// not modelled here (cow-sdk drops it too). Serde tolerates the extra
/// field, so callers needing the per-trade fee breakdown can decode the
/// raw JSON body themselves.
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
    /// Settlement transaction hash, when indexed. Hex-decoded from the
    /// wire `0x..` string; serialises back to the same form.
    #[serde(default)]
    pub tx_hash: Option<B256>,
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
        keccak256(self.full_app_data.as_bytes())
    }
}

#[cfg(feature = "http-client")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OrdersByUidsRequest<'a> {
    order_uids: &'a [OrderUid],
}

/// Wire body for `DELETE /api/v1/orders/{uid}`. The UID lives in the URL,
/// so the body is just the signature material; this mirrors the upstream
/// `CancellationPayload` shape in `cowprotocol/services/crates/model/
/// src/order.rs`.
#[cfg(feature = "http-client")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancellationPayload {
    #[serde(with = "ecdsa_wire")]
    signature: EcdsaSignature,
    signing_scheme: EcdsaSigningScheme,
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
    /// Sell-side vs buy-side fix. Private so it cannot drift out of step
    /// with the set amount; read via [`Self::kind`], set via the
    /// constructors.
    kind: OrderKind,
    /// Sell amount before fee (sell-side quote). Private so callers cannot
    /// set more than one amount or one that disagrees with `kind`; use the
    /// constructors.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    sell_amount_before_fee: Option<U256>,
    /// Sell amount after fee (sell-side quote, fee already folded in).
    /// Private; see [`Self::sell_amount_before_fee`].
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    sell_amount_after_fee: Option<U256>,
    /// Buy amount after fee (buy-side quote). Private; see
    /// [`Self::sell_amount_before_fee`].
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    buy_amount_after_fee: Option<U256>,
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

impl QuoteRequest {
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

    fn check_response_matches_request(
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
fn ensure_eq<T>(field: &'static str, requested: T, returned: T) -> Result<()>
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

/// Thin client for the CoW Protocol orderbook.
#[cfg(feature = "http-client")]
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

#[cfg(feature = "http-client")]
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
#[cfg(feature = "http-client")]
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
#[cfg(all(feature = "http-client", not(target_arch = "wasm32")))]
async fn read_capped_body(mut response: reqwest::Response) -> Result<String> {
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
#[cfg(all(feature = "http-client", target_arch = "wasm32"))]
async fn read_capped_body(response: reqwest::Response) -> Result<String> {
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
#[cfg(feature = "http-client")]
fn error_from_status(status: reqwest::StatusCode, body: String) -> Error {
    serde_json::from_str::<ApiError>(&body).map_or_else(
        |_| Error::UnexpectedStatus { status, body },
        |api| Error::OrderbookApi { status, api },
    )
}

#[cfg(feature = "http-client")]
fn ensure_trailing_slash(mut url: url::Url) -> url::Url {
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    url
}

/// Append the optional `offset` / `limit` pagination pair to a query.
/// `None` leaves the parameter off so the server applies its default.
#[cfg(feature = "http-client")]
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

#[cfg(test)]
#[path = "order_book/tests.rs"]
mod tests;
