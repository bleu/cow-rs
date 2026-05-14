//! Error and `Result` types for the `cow-rs` crate.

use serde::Deserialize;
use std::fmt;

use crate::{chain::UnsupportedChain, signature::SignatureError, subgraph::SubgraphError};

/// Crate-wide `Result` alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Top-level error type for `cow-rs`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP transport, redirect, body or response error.
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
    #[error("unexpected orderbook status {status}: {body}")]
    UnexpectedStatus {
        /// HTTP status.
        status: reqwest::StatusCode,
        /// Raw body verbatim.
        body: String,
    },

    /// The CoW Protocol subgraph returned GraphQL errors or an
    /// unrecognised envelope.
    #[error(transparent)]
    Subgraph(#[from] SubgraphError),

    /// Signature parsing, signing, or recovery failed.
    #[error(transparent)]
    Signature(#[from] SignatureError),

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

    /// A field on the orderbook's quote response did not match the
    /// caller's [`crate::QuoteRequest`]. Raised by
    /// [`crate::OrderQuoteResponse::to_signed_order_data_for`] before any
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
}

/// Structured error envelope returned by the CoW orderbook for 4xx / 5xx
/// responses. Mirrors the `Error` schema declared by the orderbook OpenAPI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
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

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_type, self.description)
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
}
