//! Error and `Result` types for the `cow-rs` crate.

use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "subgraph")]
use crate::subgraph::SubgraphError;
use crate::{chain::UnsupportedChain, signature::SignatureError};

/// Crate-wide `Result` alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Top-level error type for `cow-rs`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP transport, redirect, body or response error. Only present
    /// when the `http-client` feature is enabled.
    #[cfg(feature = "http-client")]
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON serialisation or deserialisation error.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// URL build error.
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    /// Chain id not supported by [`crate::Chain`].
    #[error(transparent)]
    UnsupportedChain(#[from] UnsupportedChain),

    /// The CoW orderbook responded with a structured error envelope.
    /// Only present when the `http-client` feature is enabled.
    #[cfg(feature = "http-client")]
    #[error("orderbook error ({}{}): {}",
        api.error_type,
        api.data.as_ref().map(|_| ", +data").unwrap_or(""),
        api.description,
    )]
    OrderbookApi {
        /// HTTP status returned with the error.
        status: reqwest::StatusCode,
        /// Decoded `ApiError` body.
        api: ApiError,
    },

    /// The orderbook returned a non-2xx status with an unparseable body.
    /// Only present when the `http-client` feature is enabled.
    #[cfg(feature = "http-client")]
    #[error("unexpected orderbook status {status}: {body}")]
    UnexpectedStatus {
        /// HTTP status.
        status: reqwest::StatusCode,
        /// Raw body verbatim.
        body: String,
    },

    /// The CoW Protocol subgraph returned GraphQL errors or an
    /// unrecognised envelope.
    #[cfg(feature = "subgraph")]
    #[error(transparent)]
    Subgraph(#[from] SubgraphError),

    /// Signature parsing, signing, or recovery failed.
    #[error(transparent)]
    Signature(#[from] SignatureError),

    /// An app-data document failed to hash or serialise (e.g. it
    /// exceeded [`crate::app_data::APP_DATA_SIZE_LIMIT`]). Surfaced
    /// instead of panicking when the document comes from a caller.
    #[error(transparent)]
    AppData(#[from] crate::app_data::AppDataError),

    /// The submission-side adjustment `sellAmount + feeAmount` overflowed
    /// the U256 range. Real quotes never come anywhere close, but the
    /// orderbook would silently accept the saturated value and produce a
    /// different on-chain order than the user signed.
    #[error("quote amount overflow: sell={sell} + fee={fee} exceeds U256")]
    QuoteAmountOverflow {
        /// `quote.sellAmount` before adjustment.
        sell: alloy_primitives::U256,
        /// `quote.feeAmount` we tried to fold into it.
        fee: alloy_primitives::U256,
    },

    /// An [`crate::OrderCreation`] field did not satisfy the orderbook's
    /// preconditions; surfaced locally so the body is never shipped.
    #[error("invalid OrderCreation: {field} {reason}")]
    OrderCreationInvalid {
        /// Field that failed validation.
        field: &'static str,
        /// Why it failed.
        reason: &'static str,
    },

    /// The caller's [`crate::QuoteRequest`] was internally inconsistent
    /// (e.g. both `valid_to` and `valid_for` set). Surfaced at the
    /// signing chokepoint so an ambiguous request is never projected
    /// into a signed `OrderData`.
    #[error("invalid QuoteRequest: {field} {reason}")]
    QuoteRequestInvalid {
        /// Field that failed validation.
        field: &'static str,
        /// Why it failed.
        reason: &'static str,
    },

    /// A [`crate::TradingClient`] was built with a `chain` that disagrees
    /// with the chain its [`crate::OrderBookApi`] targets. Signing under
    /// one chain and posting to another's orderbook produces an order the
    /// orderbook rejects, so it is refused at construction.
    #[error("chain mismatch: TradingClient signs for {client} but its OrderBookApi targets {api}")]
    ChainMismatch {
        /// Chain the [`crate::TradingClient`] would sign for.
        client: crate::chain::Chain,
        /// Chain the [`crate::OrderBookApi`] targets.
        api: crate::chain::Chain,
    },

    /// A field on the orderbook's quote response did not match the
    /// caller's [`crate::QuoteRequest`]. Raised by
    /// [`crate::OrderQuoteResponse::try_into_signed_order_data`] before any
    /// `OrderData` is returned, so a hostile orderbook cannot trick the
    /// caller into signing an order with a swapped buy token, recipient,
    /// or app-data digest.
    #[error("quote field {field} mismatch: requested {requested}, returned {returned}")]
    QuoteFieldMismatch {
        /// Which field of the response disagreed with the request.
        field: &'static str,
        /// What the caller asked for, formatted via `Display`.
        requested: String,
        /// What the orderbook returned, formatted via `Display`.
        returned: String,
    },

    /// An HTTP response body exceeded the configured cap before being
    /// fully read. Defends against a hostile orderbook streaming a
    /// multi-GB body to exhaust the SDK's memory.
    #[error("orderbook response exceeded {max} byte cap")]
    ResponseTooLarge {
        /// Maximum byte length the SDK accepts for this endpoint.
        max: usize,
    },

    /// `protocol_fee_bps` could not be parsed as a non-negative decimal
    /// with at most 5 fractional digits. The orderbook serialises the
    /// field as a JSON string (e.g. `"0.3"`); this variant fires when
    /// the value is malformed or carries more precision than the
    /// internal `bps * 100_000` scale can represent.
    #[error("invalid protocol_fee_bps {value:?}: {reason}")]
    InvalidProtocolFeeBps {
        /// The string the caller (or orderbook) passed in.
        value: String,
        /// Why parsing failed.
        reason: &'static str,
    },

    /// A `quote.sellAmount` of zero made [`crate::quote_amounts::compute`]
    /// unable to project network costs into the buy currency. This is a
    /// degenerate quote (no input to sell) and never appears for orders
    /// the orderbook would settle; we refuse it explicitly so the fee
    /// math cannot divide by zero downstream.
    #[error("quote sellAmount is zero, network cost projection undefined")]
    QuoteSellAmountZero,

    /// A [`crate::quote_amounts::compute`] intermediate overflowed or
    /// underflowed before reaching the signed [`crate::OrderData`].
    /// Mirrors the fail-closed contract of [`Self::QuoteAmountOverflow`]
    /// for the full fee-composition path: a hostile or malformed
    /// orderbook response that would push `sellAmount`, `buyAmount`,
    /// `feeAmount`, or `protocolFeeBps` into a U256-saturating
    /// computation is rejected before any saturated bytes are folded
    /// into a signature. `stage` labels the leg that failed (e.g.
    /// `"before_all_fees.buy"`, `"protocol_fee.mul_div"`,
    /// `"after_slippage.sell"`) so the offending input is greppable.
    #[error("quote fee math overflow at {stage}")]
    QuoteFeeMathOverflow {
        /// Name of the projection leg whose checked arithmetic failed.
        stage: &'static str,
    },

    /// The keccak256 of an [`crate::AppDataDocument`]'s `fullAppData`
    /// bytes did not match the [`crate::AppDataHash`] it was paired with.
    /// Raised by [`crate::OrderBookApi::app_data`] when the orderbook
    /// serves a document that does not hash to the requested digest, and
    /// by [`crate::OrderBookApi::put_app_data`] before issuing a pin
    /// whose payload would be rejected server-side. The signed order
    /// commits only to the digest, so a divergent body would let
    /// downstream wallets, bots, or UIs display or validate metadata
    /// different from what the order actually commits to.
    #[error("app-data hash mismatch: expected {expected}, computed {computed}")]
    AppDataHashMismatch {
        /// The hash the caller asked for or paired with the document.
        expected: String,
        /// `keccak256(document.fullAppData.as_bytes())` as actually
        /// computed.
        computed: String,
    },
}

/// Structured error envelope returned by the CoW orderbook for 4xx / 5xx
/// responses. Mirrors the `Error` schema declared by the orderbook OpenAPI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApiError {
    /// Short machine-readable code (e.g. `"InvalidSignature"`).
    #[serde(rename = "errorType")]
    pub error_type: String,
    /// Human-readable description.
    pub description: String,
    /// Optional structured data attached by the orderbook.
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

impl ApiError {
    /// Classify the `errorType` string into a typed variant.
    pub fn kind(&self) -> OrderPostErrorKind<'_> {
        OrderPostErrorKind::from_str(&self.error_type)
    }

    /// Whether this error is transient and the order may be resubmitted
    /// after re-quoting. Returns `false` for permanent rejections (invalid
    /// signature, unsupported token, etc.) and `true` for transient ones
    /// where a fresh quote and a new submission are likely to succeed.
    pub fn retry_hint(&self) -> bool {
        self.kind().is_retriable()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_type, self.description)
    }
}

/// Typed classification of the orderbook's `errorType` field on a failed
/// `POST /api/v1/orders`. The string is parsed against the known variants
/// documented in the CoW Protocol orderbook OpenAPI; unrecognised strings
/// fall through to [`Self::Unknown`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrderPostErrorKind<'a> {
    /// Fee was below the current minimum; re-quote and resubmit.
    InsufficientFee,
    /// Order with this UID already exists in the orderbook.
    DuplicateOrder,
    /// ECDSA or EIP-1271 signature is not valid for the order hash.
    InvalidSignature,
    /// Invalid EIP-1271 contract signature.
    InvalidErc1271Signature,
    /// Signer's sell-token balance is insufficient to cover the order.
    InsufficientBalance,
    /// Sell-token allowance to the vault relayer is too low.
    InsufficientAllowance,
    /// The sell or buy token is not accepted by the orderbook.
    UnsupportedToken,
    /// The `from` field does not match the signature recovery.
    WrongOwner,
    /// The `appData` hash in the order does not match the pinned document.
    InvalidAppData,
    /// `appData` hash in the order body disagrees with the pre-image pinned.
    AppDataHashMismatch,
    /// Sell and buy tokens are the same address.
    SameBuyAndSellToken,
    /// Unsupported buy-token destination flag.
    UnsupportedBuyTokenDestination,
    /// Unsupported sell-token balance source flag.
    UnsupportedSellTokenSource,
    /// Order type (e.g. pre-sign) not supported on this chain.
    UnsupportedOrderType,
    /// ETH transfer to a contract is rejected; wrap to WETH first.
    TransferEthToContract,
    /// Per-user limit order quota exceeded; back off and retry.
    TooManyLimitOrders,
    /// Order limit price exceeds current market; re-quote and retry.
    PriceExceedsMarketPrice,
    /// Any `errorType` string not covered by the variants above.
    Unknown(&'a str),
}

impl<'a> OrderPostErrorKind<'a> {
    fn from_str(s: &'a str) -> Self {
        match s {
            "InsufficientFee" => Self::InsufficientFee,
            "DuplicateOrder" => Self::DuplicateOrder,
            "InvalidSignature" => Self::InvalidSignature,
            "InvalidErc1271Signature" => Self::InvalidErc1271Signature,
            "InsufficientBalance" => Self::InsufficientBalance,
            "InsufficientAllowance" => Self::InsufficientAllowance,
            "UnsupportedToken" => Self::UnsupportedToken,
            "WrongOwner" => Self::WrongOwner,
            "InvalidAppData" => Self::InvalidAppData,
            "AppDataHashMismatch" => Self::AppDataHashMismatch,
            "SameBuyAndSellToken" => Self::SameBuyAndSellToken,
            "UnsupportedBuyTokenDestination" => Self::UnsupportedBuyTokenDestination,
            "UnsupportedSellTokenSource" => Self::UnsupportedSellTokenSource,
            "UnsupportedOrderType" => Self::UnsupportedOrderType,
            "TransferEthToContract" => Self::TransferEthToContract,
            "TooManyLimitOrders" => Self::TooManyLimitOrders,
            "PriceExceedsMarketPrice" => Self::PriceExceedsMarketPrice,
            other => Self::Unknown(other),
        }
    }

    /// `true` when the error is transient and a re-quote + resubmit is
    /// likely to succeed. `false` for permanent rejections.
    pub const fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::InsufficientFee | Self::TooManyLimitOrders | Self::PriceExceedsMarketPrice
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_round_trips_minimal_body() {
        let json = serde_json::json!({
            "errorType": "InsufficientFee",
            "description": "fee too low",
        });
        let parsed: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.error_type, "InsufficientFee");
        assert_eq!(parsed.description, "fee too low");
        assert!(parsed.data.is_none());
    }

    #[test]
    fn api_error_keeps_data_field_when_present() {
        let json = serde_json::json!({
            "errorType": "QuoteNotFound",
            "description": "no quote for token pair",
            "data": { "fee_amount": "1234" },
        });
        let parsed: ApiError = serde_json::from_value(json).unwrap();
        assert!(parsed.data.is_some());
        assert_eq!(parsed.data.unwrap()["fee_amount"], "1234");
    }

    #[test]
    fn known_retriable_kinds_hint_true() {
        for error_type in ["InsufficientFee", "TooManyLimitOrders", "PriceExceedsMarketPrice"] {
            let e = ApiError {
                error_type: error_type.to_owned(),
                description: String::new(),
                data: None,
            };
            assert!(e.retry_hint(), "{error_type} should be retriable");
        }
    }

    #[test]
    fn known_permanent_kinds_hint_false() {
        for error_type in [
            "DuplicateOrder",
            "InvalidSignature",
            "InvalidErc1271Signature",
            "InsufficientBalance",
            "InsufficientAllowance",
            "UnsupportedToken",
            "WrongOwner",
            "InvalidAppData",
            "AppDataHashMismatch",
            "SameBuyAndSellToken",
            "UnsupportedBuyTokenDestination",
            "UnsupportedSellTokenSource",
            "UnsupportedOrderType",
            "TransferEthToContract",
        ] {
            let e = ApiError {
                error_type: error_type.to_owned(),
                description: String::new(),
                data: None,
            };
            assert!(!e.retry_hint(), "{error_type} should be permanent");
        }
    }

    #[test]
    fn unknown_error_type_does_not_retry() {
        let e = ApiError {
            error_type: "SomeNewUnknownError".to_owned(),
            description: String::new(),
            data: None,
        };
        assert_eq!(e.kind(), OrderPostErrorKind::Unknown("SomeNewUnknownError"));
        assert!(!e.retry_hint());
    }

    #[test]
    fn kind_parses_all_documented_variants() {
        let cases = [
            ("InsufficientFee", OrderPostErrorKind::InsufficientFee),
            ("DuplicateOrder", OrderPostErrorKind::DuplicateOrder),
            ("InvalidSignature", OrderPostErrorKind::InvalidSignature),
        ];
        for (s, expected) in cases {
            let e = ApiError {
                error_type: s.to_owned(),
                description: String::new(),
                data: None,
            };
            assert_eq!(e.kind(), expected);
        }
    }
}
