//! Thin client for the CoW Protocol orderbook HTTP API.
//!
//! The first endpoint implemented here is [`OrderBookApi::get_quote`],
//! which mirrors the `getQuote` flow exposed by `@cowprotocol/cow-sdk`
//! and `cow-py`. The request and response shapes reflect the
//! production orderbook OpenAPI as of 2026-05.

use alloy_primitives::{Address, B256, U256};
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

/// Wall-clock cap applied to every request the default
/// [`OrderBookApi`] client issues. A hostile or stuck orderbook cannot
/// otherwise hold a caller's task open indefinitely. Override by
/// constructing the client manually and passing
/// [`OrderBookApi::with_client`].
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum byte length the SDK will accept for any single HTTP response
/// body. Larger payloads are rejected with [`Error::ResponseTooLarge`]
/// before they can exhaust process memory. Eight MiB is generous for
/// every documented orderbook endpoint, including the solver-oriented
/// `/api/v1/auction` snapshot. Bumping this constant is the right knob
/// for callers who explicitly want to deserialise larger bodies.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// App-data binding on a quote request.
///
/// The orderbook's `POST /api/v1/quote` accepts a single `appData`
/// field whose content can be either the 32-byte digest (hex) or the
/// canonical JSON document. Solvers price against the resulting
/// `app_data` field of the [`OrderData`] they expect to sign, so the
/// caller decides whether to commit to a digest or hand the orderbook
/// the full document. Mirrors the `OrderCreationAppData::{Hash, Full}`
/// variants in `cowprotocol/services/crates/model/src/quote.rs`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum QuoteAppData {
    /// 32-byte digest only. Orderbook keeps the digest; the full
    /// document remains opaque until someone pins it via
    /// [`OrderBookApi::put_app_data`]. Serialises directly as a
    /// `0x`-prefixed hex string under the parent's `appData` key.
    Hash(AppDataHash),
    /// Canonical JSON document; orderbook computes the digest itself
    /// and serves it back on subsequent `GET /api/v1/app_data/{hash}`
    /// queries. Serialises as a JSON string literal whose body is the
    /// document JSON (not as a nested object).
    Full(String),
}

impl QuoteAppData {
    /// Bind the quote to a pre-computed digest.
    pub const fn hash(digest: AppDataHash) -> Self {
        Self::Hash(digest)
    }

    /// Bind the quote to a canonical JSON document; orderbook computes
    /// the digest.
    pub const fn full(full: String) -> Self {
        Self::Full(full)
    }
}

impl From<AppDataHash> for QuoteAppData {
    fn from(digest: AppDataHash) -> Self {
        Self::Hash(digest)
    }
}

/// Quote price-quality knob the orderbook accepts on `POST
/// /api/v1/quote`. Solvers honour the hint by trading off latency
/// against the depth of price discovery they perform.
///
/// Source: `cow-protocol/reference/apis/orderbook.mdx` §"Price Quality".
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PriceQuality {
    /// Fast: orderbook returns the first solver answer it gets.
    Fast,
    /// Optimal: orderbook waits for the best solver answer within the
    /// quoting window. This is the default the orderbook applies when
    /// the field is omitted.
    #[default]
    Optimal,
    /// Verified: like `Optimal`, plus the orderbook simulates the order
    /// against on-chain balances before answering. Slowest, but lets the
    /// caller skip the allowance / balance pre-flight check.
    Verified,
}

/// Settled trade as returned by `GET /api/v1/trades`.
///
/// The orderbook emits one record per `GPv2Settlement.Trade` log. Optional
/// fields are populated only when the orderbook has enough context to
/// surface them; callers should treat the absent state as informational.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trade {
    /// Block in which the settlement transaction landed.
    pub block_number: u64,
    /// Index of the `Trade` log within the settlement transaction.
    pub log_index: u32,
    /// UID of the order that produced this trade.
    pub order_uid: OrderUid,
    /// Address that signed the order.
    pub owner: Address,
    /// Token the owner sold.
    pub sell_token: Address,
    /// Token the owner received.
    pub buy_token: Address,
    /// Sell amount, net of fee, in atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Sell amount before the orderbook's fee was deducted.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub sell_amount_before_fees: Option<U256>,
    /// Buy amount delivered to the receiver.
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Settlement transaction hash, hex-encoded.
    #[serde(default)]
    pub tx_hash: Option<String>,
}

/// Price of one atomic unit of `token` denominated in the chain's native
/// token, as returned by `GET /api/v1/token/{token}/native_price`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct NativePrice {
    /// Price ratio. Note: the orderbook returns this as a JSON number, not
    /// a decimal string.
    pub price: f64,
}

/// Cumulative user surplus reported by
/// `GET /api/v1/users/{user}/total_surplus`. The field is a decimal string
/// for precision; we keep it as-is and let callers feed it into their own
/// big-number parser.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotalSurplus {
    /// User's cumulative surplus across all settled orders.
    pub total_surplus: String,
}

/// Snapshot returned by `GET /api/v1/auction`.
///
/// The endpoint is permissioned (intended for solvers; CoW grants access on
/// request), so most integrators will only see the unauthenticated 403 from
/// the public proxy. We expose the top-level fields ourselves and keep the
/// per-order array as opaque JSON: `AuctionOrder` carries solver-relevant
/// fields that drift across CIP changes and that we have no way to lock
/// byte-conformance for without solver access.
#[serde_as]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Auction {
    /// Monotonically increasing auction identifier (absent during reorgs).
    #[serde(default)]
    pub id: Option<u64>,
    /// Block the auction was anchored on; orders, prices and proposed
    /// settlements are valid at this block.
    #[serde(default)]
    pub block: Option<u64>,
    /// Solvable orders. Opaque JSON; deserialise into your own
    /// `AuctionOrder` shape if you need typed fields (the schema is
    /// volatile across CIP-67 / CIP-20).
    #[serde(default)]
    pub orders: Option<serde_json::Value>,
    /// External prices indexed by token address (decimal-string atomic
    /// units in the chain's native token).
    #[serde_as(as = "Option<BTreeMap<_, DisplayFromStr>>")]
    #[serde(default)]
    pub prices: Option<BTreeMap<Address, U256>>,
    /// JIT order owners whose surplus counts towards the solver's
    /// objective value.
    #[serde(default)]
    pub surplus_capturing_jit_order_owners: Option<Vec<Address>>,
}

/// Per-token metadata returned by `GET /api/v1/token/{token}/metadata`.
///
/// Both fields are absent for tokens the orderbook has never seen.
#[serde_as]
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMetadata {
    /// Block at which the first trade of this token was indexed, or
    /// `None` if the orderbook has not observed a trade for it.
    #[serde(default)]
    pub first_trade_block: Option<u32>,
    /// Most recent native-price quote in atomic units of the chain's
    /// native token. Encoded as a decimal-or-hex string on the wire.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub native_price: Option<U256>,
}

/// Response of `GET /api/v1/app_data/{hash}` and input to
/// [`OrderBookApi::put_app_data`]. Carries the canonical JSON string of
/// the document; when hashed with `keccak256` this yields the [`AppDataHash`]
/// stored on the signed order.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataDocument {
    /// JSON string of the document. The orderbook does not re-format this
    /// beyond verifying that it parses, so it round-trips byte-for-byte.
    pub full_app_data: String,
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

/// Auction-status payload returned by `GET /api/v1/orders/{uid}/status`.
///
/// `value` carries solver execution proposals when relevant
/// (`solved`/`executing`), and is empty for `open`/`cancelled`. We surface
/// it as opaque JSON to stay forward-compatible with solver-side schema
/// additions.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    /// Relative expiry in seconds from "now" (server clock). Wire field
    /// `validFor`. Mutually exclusive with [`QuoteRequest::valid_to`];
    /// when both are absent the orderbook applies a 30-minute default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_for: Option<u32>,
    /// Optional pre-computed app-data digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_data: Option<QuoteAppData>,
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
    /// Gas budget the orderbook should reserve for the on-chain
    /// `isValidSignature` callback when quoting an [`SigningScheme::Eip1271`]
    /// order. Defaults to `27_000` on the server side; smart-contract
    /// wallets with expensive verification logic should override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_gas_limit: Option<u64>,
    /// `true` when the resulting order will be placed on chain instead
    /// of via the off-chain orderbook (relevant for [`SigningScheme::Eip1271`]
    /// and [`SigningScheme::PreSign`]). Lets the orderbook reserve the
    /// right gas budget when simulating.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onchain_order: Option<bool>,
    /// Latency-vs-depth trade-off the orderbook should apply when
    /// discovering a price. Defaults to [`PriceQuality::Optimal`] when
    /// absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_quality: Option<PriceQuality>,
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

    /// Set the order's app-data digest (the common case). Wraps the
    /// hash into [`QuoteAppData::Hash`].
    ///
    /// Not `const fn` because [`QuoteAppData::Full`] holds a `String`,
    /// which the compiler cannot drop at const-evaluation time even
    /// though this constructor only ever stores the `Hash` variant.
    pub fn with_app_data(mut self, app_data: AppDataHash) -> Self {
        self.app_data = Some(QuoteAppData::Hash(app_data));
        self
    }

    /// Bind the quote to the canonical JSON document instead of just
    /// the digest. The orderbook computes and pins the hash itself.
    pub fn with_app_data_full(mut self, full_app_data: impl Into<String>) -> Self {
        self.app_data = Some(QuoteAppData::Full(full_app_data.into()));
        self
    }

    /// Pin the order's expiry timestamp.
    pub const fn with_valid_to(mut self, valid_to: u32) -> Self {
        self.valid_to = Some(valid_to);
        self
    }

    /// Pin the order's expiry as a relative offset (seconds from the
    /// orderbook's clock). Mutually exclusive with
    /// [`QuoteRequest::with_valid_to`]; the orderbook applies a
    /// 30-minute default when both are absent.
    pub const fn with_valid_for(mut self, valid_for: u32) -> Self {
        self.valid_for = Some(valid_for);
        self
    }

    /// Pin the gas budget for the on-chain `isValidSignature` callback
    /// when the resulting order will use [`SigningScheme::Eip1271`].
    pub const fn with_verification_gas_limit(mut self, gas: u64) -> Self {
        self.verification_gas_limit = Some(gas);
        self
    }

    /// Mark the resulting order as on-chain-placed (default: false).
    /// Relevant for [`SigningScheme::Eip1271`] and
    /// [`SigningScheme::PreSign`] flows.
    pub const fn with_onchain_order(mut self, onchain: bool) -> Self {
        self.onchain_order = Some(onchain);
        self
    }

    /// Ask the orderbook for a specific price-quality regime. Omitted by
    /// default, in which case the orderbook applies [`PriceQuality::Optimal`].
    pub const fn with_price_quality(mut self, quality: PriceQuality) -> Self {
        self.price_quality = Some(quality);
        self
    }

    /// Pin the signing scheme the resulting order will use. Lets the
    /// orderbook reject a quote / order combo with an incompatible scheme
    /// before signing.
    pub const fn with_signing_scheme(mut self, scheme: SigningScheme) -> Self {
        self.signing_scheme = Some(scheme);
        self
    }

    /// Mark the resulting order as partially fillable (default: false for
    /// market orders).
    pub const fn with_partially_fillable(mut self, partially_fillable: bool) -> Self {
        self.partially_fillable = Some(partially_fillable);
        self
    }

    /// Set the sell-side token-balance source.
    pub const fn with_sell_token_balance(mut self, balance: SellTokenSource) -> Self {
        self.sell_token_balance = Some(balance);
        self
    }

    /// Set the buy-side token-balance destination.
    pub const fn with_buy_token_balance(mut self, balance: BuyTokenDestination) -> Self {
        self.buy_token_balance = Some(balance);
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
    /// - `fee_amount` is always `0` at submission: solvers price gas at
    ///   settlement time.
    /// - `app_data` is the 32-byte digest of the canonical metadata JSON
    ///   the caller will submit (use [`crate::EMPTY_APP_DATA_HASH`] for the
    ///   empty document `"{}"`).
    ///
    /// [step3]: https://docs.cow.fi/cow-protocol/howto/integrate/api#step-3-compute-the-amounts-to-sign
    pub fn to_signed_order_data(&self, app_data: AppDataHash) -> Result<OrderData> {
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
        Ok(OrderData {
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
        })
    }

    /// Like [`OrderQuoteResponse::to_signed_order_data`] but cross-checks
    /// the quote's `sell_token`, `buy_token`, `receiver` and (when the
    /// caller pinned a digest) `app_data` against the original
    /// [`QuoteRequest`] before producing the [`OrderData`] the user will
    /// sign.
    ///
    /// Defends against a hostile orderbook that swaps any of those
    /// fields between request and response: the SDK refuses to project
    /// the response into a signable order until every caller-authorised
    /// field round-trips. Returns [`Error::QuoteFieldMismatch`] on the
    /// first divergence.
    /// Project this quote into [`QuoteAmountsAndCosts`], threading the
    /// caller's partner fee, slippage and any `protocolFeeBps` echoed
    /// by the response through the same arithmetic the TypeScript SDK
    /// uses (`getQuoteAmountsAndCosts`). Use this when posting an order
    /// that combines a partner fee with a quote that carries a
    /// protocol fee, otherwise the partner-fee base is computed against
    /// the wrong spot price and the orderbook receives an inflated
    /// `buyAmount` (see [`cow-sdk` #867]).
    ///
    /// `protocol_fee_bps_override` lets the caller pin a specific value
    /// instead of trusting [`Self::protocol_fee_bps`]; `None` falls
    /// back to the on-wire field.
    ///
    /// [`cow-sdk` #867]: https://github.com/cowprotocol/cow-sdk/pull/867
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

    /// Like [`Self::to_signed_order_data`] but applies the full
    /// partner-fee + protocol-fee + slippage composition through
    /// [`Self::amounts_with_costs`] before projecting into
    /// [`OrderData`]. Use this whenever the order being submitted
    /// carries an `AppDataPartnerFee`, or when the quote response
    /// echoes a non-zero `protocolFeeBps`.
    pub fn to_signed_order_data_with_costs(
        &self,
        partner_fee_bps: u32,
        slippage_bps: u32,
        protocol_fee_bps_override: Option<&str>,
        app_data: AppDataHash,
    ) -> Result<OrderData> {
        let amounts =
            self.amounts_with_costs(partner_fee_bps, slippage_bps, protocol_fee_bps_override)?;
        let q = &self.quote;
        Ok(OrderData {
            sell_token: q.sell_token,
            buy_token: q.buy_token,
            receiver: q.receiver,
            sell_amount: amounts.amounts_to_sign.sell_amount,
            buy_amount: amounts.amounts_to_sign.buy_amount,
            valid_to: q.valid_to,
            app_data,
            fee_amount: U256::ZERO,
            kind: q.kind,
            partially_fillable: q.partially_fillable,
            sell_token_balance: q.sell_token_balance,
            buy_token_balance: q.buy_token_balance,
        })
    }

    /// Like [`Self::to_signed_order_data_with_costs`] but also
    /// cross-checks the quote's `sell_token`, `buy_token`, `receiver`
    /// and (when the caller pinned a digest) `app_data` against the
    /// original [`QuoteRequest`] before producing the [`OrderData`]
    /// the user will sign.
    pub fn to_signed_order_data_with_costs_for(
        &self,
        request: &QuoteRequest,
        partner_fee_bps: u32,
        slippage_bps: u32,
        protocol_fee_bps_override: Option<&str>,
        app_data: AppDataHash,
    ) -> Result<OrderData> {
        self.check_response_matches_request(request, app_data)?;
        self.to_signed_order_data_with_costs(
            partner_fee_bps,
            slippage_bps,
            protocol_fee_bps_override,
            app_data,
        )
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
        if let Some(requested_receiver) = request.receiver {
            // Treat zero-receiver as "owner receives" on both sides; the
            // orderbook normalises the same way.
            let normalise = |a: Option<Address>| match a {
                Some(addr) if addr == Address::ZERO => None,
                other => other,
            };
            let req = normalise(Some(requested_receiver));
            let got = normalise(q.receiver);
            if req != got {
                return Err(Error::QuoteFieldMismatch {
                    field: "receiver",
                    requested: format!("{req:?}"),
                    returned: format!("{got:?}"),
                });
            }
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

    /// Like [`Self::to_signed_order_data`] but cross-checks the
    /// quote's `sell_token`, `buy_token`, `receiver` and (when the
    /// caller pinned a digest) `app_data` against the original
    /// [`QuoteRequest`] before producing the [`OrderData`] the user
    /// will sign. Defends against a hostile orderbook that swaps any
    /// of those fields between request and response. Returns
    /// [`Error::QuoteFieldMismatch`] on the first divergence.
    pub fn to_signed_order_data_for(
        &self,
        request: &QuoteRequest,
        app_data: AppDataHash,
    ) -> Result<OrderData> {
        self.check_response_matches_request(request, app_data)?;
        self.to_signed_order_data(app_data)
    }
}

/// Full response body of `POST /api/v1/quote`.
#[derive(Clone, Debug, Deserialize, Serialize)]
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

    /// Build a client against a custom base URL: useful for tests against
    /// a recorded server or a staging deployment. The default reqwest
    /// client carries a [`DEFAULT_HTTP_TIMEOUT`] cap so a stuck
    /// orderbook cannot hold the caller open indefinitely.
    pub fn new_with_base_url(base_url: url::Url) -> Self {
        // `ClientBuilder::timeout` only exists on non-wasm32 targets;
        // reqwest's wasm32 backend delegates to the browser's fetch
        // and inherits its timeout behaviour instead.
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(DEFAULT_HTTP_TIMEOUT);
        let client = builder
            .build()
            .expect("reqwest client builder cannot fail with default settings");
        Self::with_client(base_url, client)
    }

    /// Build a client around a pre-configured [`reqwest::Client`].
    /// Use this when you need to override timeouts, install proxies,
    /// pin TLS roots, or inject auth middleware.
    pub fn with_client(base_url: url::Url, client: reqwest::Client) -> Self {
        Self {
            base_url: ensure_trailing_slash(base_url),
            client,
        }
    }

    /// The base URL the client points at, with the trailing slash that path
    /// joining relies on.
    pub const fn base_url(&self) -> &url::Url {
        &self.base_url
    }

    /// `POST /api/v1/quote`: ask the orderbook for a quote that the
    /// requester can sign and submit.
    pub async fn get_quote(&self, request: &QuoteRequest) -> Result<OrderQuoteResponse> {
        self.post_json("api/v1/quote", request).await
    }

    /// `POST /api/v1/orders`: submit a signed order. Returns the
    /// 56-byte UID assigned by the orderbook.
    pub async fn post_order(&self, order: &OrderCreation) -> Result<OrderUid> {
        self.post_json("api/v1/orders", order).await
    }

    /// `GET /api/v1/orders/{uid}`: fetch the full order record, including
    /// execution counters and lifecycle status.
    pub async fn get_order(&self, uid: &OrderUid) -> Result<Order> {
        self.get_json(&format!("api/v1/orders/{uid}")).await
    }

    /// `GET /api/v1/orders/{uid}/status`: fetch the auction lifecycle
    /// stage and any attached solver proposals.
    pub async fn get_order_status(&self, uid: &OrderUid) -> Result<AuctionStatus> {
        self.get_json(&format!("api/v1/orders/{uid}/status")).await
    }

    /// Poll [`OrderBookApi::get_order`] until `should_stop` returns
    /// `true`, sleeping between polls via the caller-supplied closure.
    ///
    /// Runtime-agnostic: works under tokio (`tokio::time::sleep`),
    /// async-std, `gloo_timers::future::sleep` in browsers, or anything
    /// else that exposes a `Future<Output = ()>`. The function does not
    /// look at the wall clock; callers that want a deadline bake it into
    /// `should_stop` (e.g. capture an `Instant` in the closure).
    ///
    /// Each iteration calls `should_stop(&order)` first; the helper
    /// returns the latest [`Order`] as soon as the predicate is
    /// satisfied. If the predicate never returns `true`, the loop
    /// continues until a HTTP error from [`OrderBookApi::get_order`]
    /// short-circuits it.
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

    /// Convenience wrapper around [`OrderBookApi::poll_until`] that uses
    /// `tokio::time::sleep` and a wall-clock deadline. Stops when the
    /// order reaches a terminal status ([`crate::OrderStatus::Fulfilled`],
    /// [`crate::OrderStatus::Cancelled`], [`crate::OrderStatus::Expired`])
    /// or `deadline` elapses, whichever comes first.
    ///
    /// Available on non-wasm targets only. WASM callers should compose
    /// [`OrderBookApi::poll_until`] with `gloo_timers::future::sleep`
    /// (or equivalent) directly.
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

    /// `GET /api/v1/account/{owner}/orders`: list every order the
    /// orderbook knows about for `owner`, most recent first. `offset` and
    /// `limit` page the result; pass `None` for both to use the orderbook
    /// defaults.
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

    /// `POST /api/v1/orders/by_uids`: fetch many orders in a single round
    /// trip. The orderbook returns them in the order requested, with
    /// unknown UIDs omitted (not nulled).
    pub async fn get_orders_by_uids(&self, uids: &[OrderUid]) -> Result<Vec<Order>> {
        self.post_json(
            "api/v1/orders/by_uids",
            &OrdersByUidsRequest { order_uids: uids },
        )
        .await
    }

    /// `GET /api/v1/trades?owner=...`: trades produced by orders signed
    /// by `owner`.
    pub async fn trades_by_owner(&self, owner: Address) -> Result<Vec<Trade>> {
        let mut url = self.base_url.join("api/v1/trades")?;
        url.query_pairs_mut()
            .append_pair("owner", &format!("{owner:?}"));
        let response = self.client.get(url).send().await?;
        Self::decode_response(response).await
    }

    /// `GET /api/v1/trades?orderUid=...`: trades that filled a specific
    /// order UID.
    pub async fn trades_by_order_uid(&self, uid: &OrderUid) -> Result<Vec<Trade>> {
        let mut url = self.base_url.join("api/v1/trades")?;
        url.query_pairs_mut()
            .append_pair("orderUid", &uid.to_string());
        let response = self.client.get(url).send().await?;
        Self::decode_response(response).await
    }

    /// `GET /api/v1/token/{token}/native_price`: price of one atomic
    /// unit of `token` in the chain's native gas token. Used by solvers
    /// to denominate gas costs uniformly across pairs.
    pub async fn native_price(&self, token: Address) -> Result<NativePrice> {
        self.get_json(&format!("api/v1/token/{token:?}/native_price"))
            .await
    }

    /// `GET /api/v1/token/{token}/metadata`: first-trade block and the
    /// most recent native-price quote the orderbook has cached.
    pub async fn token_metadata(&self, token: Address) -> Result<TokenMetadata> {
        self.get_json(&format!("api/v1/token/{token:?}/metadata"))
            .await
    }

    /// `GET /api/v1/transactions/{hash}/orders`: every order settled in
    /// the given transaction. Returns an empty list if the hash does not
    /// correspond to a known settlement.
    pub async fn orders_by_tx(&self, tx_hash: B256) -> Result<Vec<Order>> {
        self.get_json(&format!("api/v1/transactions/{tx_hash:?}/orders"))
            .await
    }

    /// `GET /api/v1/auction`: the current batch auction snapshot.
    ///
    /// Permissioned: the public-facing proxy returns `403 Forbidden` to
    /// unauthenticated callers. The CoW autopilot exposes it to solvers
    /// (access granted on request). The method is shipped here for parity
    /// with cow-py and cow-sdk; the auction shape is solver-oriented and
    /// changes across CIP-20 / CIP-67, so the per-order array is left as
    /// raw JSON.
    pub async fn get_auction(&self) -> Result<Auction> {
        self.get_json("api/v1/auction").await
    }

    /// `GET /api/v1/users/{user}/total_surplus`: cumulative surplus the
    /// user has captured across all of their orders.
    pub async fn total_surplus(&self, user: Address) -> Result<TotalSurplus> {
        self.get_json(&format!("api/v1/users/{user:?}/total_surplus"))
            .await
    }

    /// `GET /api/v1/app_data/{hash}`: retrieve the canonical JSON the
    /// orderbook has on file for an app-data digest. Returns
    /// [`Error::OrderbookApi`] with `NotFound` when the orderbook has not
    /// seen the document.
    pub async fn get_app_data(&self, hash: &AppDataHash) -> Result<AppDataDocument> {
        self.get_json(&format!("api/v1/app_data/{}", hex_string(hash.as_ref())))
            .await
    }

    /// `PUT /api/v1/app_data/{hash}`: pre-pin a document so the orderbook
    /// can serve it back for the matching hash. Used to bind an order to
    /// specific metadata before the order itself is submitted, notably for
    /// the EIP-1271 owner-pinning replay defence.
    pub async fn put_app_data(&self, hash: &AppDataHash, document: &AppDataDocument) -> Result<()> {
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

    /// `PUT /api/v1/app_data`: pin a document without committing to a
    /// hash upfront; the orderbook computes the digest from the body and
    /// returns it. Use this when the client wants the server to be the
    /// source of truth for the canonical hash, or when porting code that
    /// has the document but not its digest. The hashed variant
    /// ([`OrderBookApi::put_app_data`]) is preferred when the caller has
    /// already pinned an [`AppDataHash`] in a signed order.
    ///
    /// Returns the digest the orderbook computed; status `201 Created`
    /// for a fresh pin or `200 OK` if the orderbook already had it on
    /// file.
    pub async fn upload_app_data(&self, document: &AppDataDocument) -> Result<AppDataHash> {
        self.put_json("api/v1/app_data", document).await
    }

    /// `GET /api/v1/version`: the orderbook server's free-form version
    /// string. Useful as a quick liveness probe; the format is plain text,
    /// not JSON.
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

    /// `DELETE /api/v1/orders`: submit a signed cancellation collection.
    ///
    /// Note that the endpoint is `/api/v1/orders` (collection), not
    /// `/api/v1/orders/{uid}`; the orders to cancel are identified by the
    /// `orderUids` array in the body. The cancellation is "soft": orders
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
        let text = read_capped_text(response).await?;
        serde_json::from_str::<ApiError>(&text).map_or_else(
            |_| Err(Error::UnexpectedStatus { status, body: text }),
            |api| Err(Error::OrderbookApi { status, api }),
        )
    }

    /// `DELETE /api/v1/orders/{uid}`: soft-cancel a single order. The
    /// UID is taken from `cancellation.order_uid` and placed in the URL;
    /// the body carries only the signature and signing scheme, matching
    /// the upstream `CancellationPayload` wire shape.
    ///
    /// Like [`OrderBookApi::cancel_orders`], the cancellation is "soft":
    /// orders that have already been picked up by a solver may still
    /// settle. For pre-signed and EthFlow orders use the on-chain
    /// invalidation path instead.
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

/// Read a response body as UTF-8 text, rejecting payloads larger than
/// [`MAX_RESPONSE_BYTES`]. Honours the `Content-Length` header when
/// present (early reject) and re-checks the materialised body
/// afterwards as a backstop for servers that omit or under-declare the
/// header.
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
    /// into `sellAmount` and zeroes the fee: the documented submission
    /// adjustment.
    #[test]
    fn to_signed_order_data_adjusts_sell_amount_and_zeroes_fee() {
        let quote = load_mainnet_quote();
        assert_eq!(quote.quote.kind, OrderKind::Sell);
        let original_sell = quote.quote.sell_amount;
        let original_fee = quote.quote.fee_amount;

        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();

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

        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();

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
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();
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
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();
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

        let err = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap_err();
        assert!(matches!(err, Error::QuoteAmountOverflow { .. }));
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

    /// R20: `to_signed_order_data_for` rejects a tampered `buy_token`
    /// instead of letting the user sign an order paying out a different
    /// asset than they asked for.
    #[test]
    fn to_signed_order_data_for_rejects_swapped_buy_token() {
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
            .to_signed_order_data_for(&request, EMPTY_APP_DATA_HASH)
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

    /// R20: `to_signed_order_data_for` returns the same `OrderData` as
    /// the unchecked path when every caller-authorised field matches.
    #[test]
    fn to_signed_order_data_for_passes_when_request_matches_response() {
        let quote = load_mainnet_quote();
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        );
        let signed = quote
            .to_signed_order_data_for(&request, EMPTY_APP_DATA_HASH)
            .unwrap();
        let unchecked = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();
        assert_eq!(signed, unchecked);
    }

    /// R20: `to_signed_order_data_for` rejects a quote whose returned
    /// `app_data` digest disagrees with the digest the caller pinned in
    /// the request.
    #[test]
    fn to_signed_order_data_for_rejects_swapped_app_data() {
        let quote = load_mainnet_quote();
        let pinned = AppDataHash([0x42; 32]);
        let request = QuoteRequest::sell_amount_before_fee(
            quote.quote.sell_token,
            quote.quote.buy_token,
            quote.from,
            U256::from(1u64),
        )
        .with_app_data(pinned);
        // The response's digest is `EMPTY_APP_DATA_HASH`, not `pinned`.
        let err = quote
            .to_signed_order_data_for(&request, EMPTY_APP_DATA_HASH)
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

    /// R21: `from_signed_order_data` rejects an `app_data` JSON document
    /// whose keccak256 does not match the `OrderData::app_data` digest
    /// the user signed against.
    #[test]
    fn from_signed_order_data_rejects_app_data_digest_mismatch() {
        let quote = load_mainnet_quote();
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();
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
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();
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
        let signed = quote.to_signed_order_data(EMPTY_APP_DATA_HASH).unwrap();
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
