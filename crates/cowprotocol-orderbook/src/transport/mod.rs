//! Transport abstraction decoupling [`OrderBookApi`] from a concrete HTTP
//! backend.
//!
//! [`OrderBookApi`] builds a transport-agnostic [`HttpRequest`] for each
//! endpoint and hands it to an [`HttpTransport`]; the transport performs
//! the actual I/O and returns an [`HttpResponse`] whose body has already
//! been bounded by [`MAX_RESPONSE_BYTES`]. This is what lets the native
//! (reqwest) and wasm (`fetch`) builds share one client and one set of
//! endpoint logic instead of re-implementing request shaping, status
//! handling and JSON decoding per target.
//!
//! The concrete backends live as submodules behind the `http-client`
//! feature; the trait itself stays feature-independent so out-of-tree
//! backends can implement it.
//!
//! [`OrderBookApi`]: crate::OrderBookApi
//! [`MAX_RESPONSE_BYTES`]: crate::order_book::MAX_RESPONSE_BYTES

use serde::de::DeserializeOwned;

use crate::error::{ApiError, Error, Result};

// Pathed as `self::reqwest` so the submodule never shadows the extern
// crate of the same name under uniform paths.
#[cfg(feature = "http-client")]
pub(crate) mod reqwest;
#[cfg(feature = "http-client")]
pub use self::reqwest::ReqwestTransport;

/// HTTP method for an orderbook request. Kept minimal: the orderbook only
/// uses these four verbs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

/// A fully-formed, transport-agnostic request the orderbook client hands to
/// an [`HttpTransport`]. The body, when present, is already serialised JSON
/// and implies a `content-type: application/json` header.
#[derive(Clone)]
pub struct HttpRequest {
    /// Request method.
    pub method: HttpMethod,
    /// Absolute request URL (base URL joined with the endpoint path and any
    /// query string).
    pub url: url::Url,
    /// Pre-serialised JSON body, or `None` for body-less requests.
    pub json_body: Option<Vec<u8>>,
    /// `Authorization: Bearer` credential for authenticated gateways (The
    /// Graph). `None` for the orderbook.
    pub bearer: Option<String>,
}

/// Manual `Debug` impl that renders `bearer` as `Some("<redacted>")` so a
/// logging transport cannot leak the credential.
impl core::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("json_body", &self.json_body)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The response an [`HttpTransport`] returns after applying the body-size
/// cap. The body is decoded UTF-8 text; status handling and JSON decoding
/// happen in [`OrderBookApi`](crate::OrderBookApi) via the `decode_*`
/// helpers so both transports share one path.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body as UTF-8 text, already bounded by the transport's cap.
    pub body: String,
}

/// HTTP backend [`OrderBookApi`](crate::OrderBookApi) issues requests
/// through. Implemented by `ReqwestTransport` on native targets (behind the
/// `http-client` feature) and by `cow-sdk-wasm`'s fetch transport on
/// wasm32.
///
/// The method is `async fn` rather than `-> impl Future + Send` on purpose:
/// the wasm `fetch` transport's future is `!Send`, so requiring `Send`
/// would make the trait unimplementable there. Native callers drive it with
/// a direct `.await` (no `tokio::spawn`), so the missing `Send` bound is not
/// a limitation in practice.
#[allow(async_fn_in_trait)]
pub trait HttpTransport {
    /// Execute `request` and return the capped response, or an [`Error`] for
    /// a transport-level failure (connection, timeout, oversized body).
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse>;
}

impl HttpResponse {
    /// `true` for a 2xx status.
    pub(crate) const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Decode a 2xx body as JSON, or map a non-2xx `(status, body)` to an
    /// [`Error`] via [`Self::into_status_error`].
    pub(crate) fn decode_json<T: DeserializeOwned>(self) -> Result<T> {
        if self.is_success() {
            serde_json::from_str(&self.body).map_err(Error::from)
        } else {
            Err(self.into_status_error())
        }
    }

    /// Accept a 2xx response that carries no meaningful body (`PUT` /
    /// `DELETE`), or map a non-2xx status through [`Self::into_status_error`].
    pub(crate) fn decode_empty(self) -> Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            Err(self.into_status_error())
        }
    }

    /// Return a 2xx body verbatim (the `/version` endpoint is plain text,
    /// not JSON), or map a non-2xx status through [`Self::into_status_error`].
    pub(crate) fn decode_text(self) -> Result<String> {
        if self.is_success() {
            Ok(self.body)
        } else {
            Err(self.into_status_error())
        }
    }

    /// Map a non-success response to an [`Error`]. Decodes the body as an
    /// [`ApiError`] when it parses, falling back to
    /// [`Error::UnexpectedStatus`] with the raw body otherwise.
    fn into_status_error(self) -> Error {
        serde_json::from_str::<ApiError>(&self.body).map_or_else(
            |_| Error::UnexpectedStatus {
                status: self.status,
                body: self.body,
            },
            |api| Error::OrderbookApi {
                status: self.status,
                api,
            },
        )
    }
}
