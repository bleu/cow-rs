//! JS `fetch` implementation of [`cowprotocol::transport::HttpTransport`].
//!
//! Invokes the global `fetch` function via `js_sys::Reflect` so the linker
//! is free to drop reqwest from the wasm output (no wasm-bindgen export
//! links the native `ReqwestTransport`). Skipping `web-sys` keeps the
//! binding overhead to a few kilobytes.
//!
//! [`FetchTransport`] only performs the I/O: it returns the raw
//! `(status, body)` and lets the shared [`cowprotocol::OrderBookApi`]
//! endpoint logic map the status to an error and decode the JSON, so the
//! wasm and native paths share one implementation of that logic.
//!
//! Every request is bounded in two dimensions:
//!
//! - a wall-clock timeout enforced via a globalThis `AbortController`
//!   (see [`FETCH_TIMEOUT_MS`]). A stuck or hostile orderbook cannot hold
//!   the caller's task open indefinitely;
//! - a response body size cap (see [`MAX_RESPONSE_BYTES`]). A hostile
//!   orderbook streaming a multi-GB body cannot exhaust wasm linear memory.

use {
    cowprotocol::{
        Error,
        order_book::{DEFAULT_HTTP_TIMEOUT, MAX_RESPONSE_BYTES},
        transport::{HttpMethod, HttpRequest, HttpResponse, HttpTransport},
    },
    js_sys::{Function, Object, Promise, Reflect, global},
    wasm_bindgen::{JsCast, JsValue, closure::Closure},
    wasm_bindgen_futures::JsFuture,
};

/// Wall-clock cap applied to every `fetch` call this module issues.
/// Derived from [`cowprotocol::order_book::DEFAULT_HTTP_TIMEOUT`], the same
/// timeout the reqwest client applies on native targets, so the two
/// transports cannot drift.
pub(crate) const FETCH_TIMEOUT_MS: u32 = DEFAULT_HTTP_TIMEOUT.as_secs() as u32 * 1000;

/// The JS `fetch`-backed [`HttpTransport`]. Stateless: each call reads the
/// global `fetch` afresh, so a single instance is reused across requests.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FetchTransport;

impl HttpTransport for FetchTransport {
    async fn execute(&self, request: HttpRequest) -> cowprotocol::Result<HttpResponse> {
        let method = match request.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        };
        // `json_body` is serialised JSON, so it is valid UTF-8.
        let body = request
            .json_body
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        let (status, body) = fetch(method, request.url.as_str(), body.as_deref())
            .await
            .map_err(FetchError::into_cow)?;
        Ok(HttpResponse { status, body })
    }
}

/// Transport-internal failure, mapped to a [`cowprotocol::Error`] at the
/// [`FetchTransport::execute`] boundary. `TooLarge` becomes
/// [`Error::ResponseTooLarge`]; everything else carries the JS error text
/// into [`Error::TransportFailed`].
enum FetchError {
    Js(JsValue),
    TooLarge,
}

impl From<JsValue> for FetchError {
    fn from(value: JsValue) -> Self {
        Self::Js(value)
    }
}

impl FetchError {
    fn into_cow(self) -> Error {
        match self {
            Self::TooLarge => Error::ResponseTooLarge {
                max: MAX_RESPONSE_BYTES,
            },
            Self::Js(value) => {
                Error::TransportFailed(value.as_string().unwrap_or_else(|| format!("{value:?}")))
            }
        }
    }
}

/// Issue one `fetch` and return the raw `(status, body)`. Bounds the body
/// by [`MAX_RESPONSE_BYTES`] and aborts after [`FETCH_TIMEOUT_MS`]. Status
/// interpretation and JSON decoding are the caller's job.
async fn fetch(method: &str, url: &str, body: Option<&str>) -> Result<(u16, String), FetchError> {
    let init = Object::new();
    Reflect::set(
        &init,
        &JsValue::from_str("method"),
        &JsValue::from_str(method),
    )?;
    if let Some(body) = body {
        let headers = Object::new();
        Reflect::set(
            &headers,
            &JsValue::from_str("content-type"),
            &JsValue::from_str("application/json"),
        )?;
        Reflect::set(&init, &JsValue::from_str("headers"), &headers)?;
        Reflect::set(&init, &JsValue::from_str("body"), &JsValue::from_str(body))?;
    }

    let global = global();

    // Wire up an AbortController so the fetch is cancellable. If the
    // setTimeout fires before the response arrives, the in-flight fetch
    // rejects with an `AbortError` we surface as a timeout.
    let abort_guard = AbortGuard::install(&global, &init, FETCH_TIMEOUT_MS)?;

    let fetch = Reflect::get(&global, &JsValue::from_str("fetch"))?
        .dyn_into::<Function>()
        .map_err(|_| JsValue::from_str("global fetch is not a function"))?;
    let promise: Promise = fetch
        .call2(&global, &JsValue::from_str(url), &init)?
        .dyn_into()
        .map_err(|_| JsValue::from_str("fetch did not return a Promise"))?;
    let response = match JsFuture::from(promise).await {
        Ok(r) => r,
        Err(err) => {
            return Err(FetchError::Js(if abort_guard.fired() {
                JsValue::from_str(&format!("request timed out after {FETCH_TIMEOUT_MS} ms"))
            } else {
                err
            }));
        }
    };

    let status: u16 = Reflect::get(&response, &JsValue::from_str("status"))?
        .as_f64()
        .ok_or_else(|| JsValue::from_str("response.status missing"))? as u16;

    // Reject oversized bodies before reading them into linear memory.
    // The header is advisory (proxies strip it, some servers omit it); a
    // post-read backstop below catches the cases it does not cover.
    if let Some(headers) = Reflect::get(&response, &JsValue::from_str("headers"))
        .ok()
        .filter(|h| !h.is_undefined() && !h.is_null())
        && let Some(get_fn) = Reflect::get(&headers, &JsValue::from_str("get"))
            .ok()
            .and_then(|f| f.dyn_into::<Function>().ok())
        && let Ok(declared) = get_fn.call1(&headers, &JsValue::from_str("content-length"))
        && let Some(declared) = declared.as_string()
        && let Ok(declared) = declared.parse::<u64>()
        && declared > MAX_RESPONSE_BYTES as u64
    {
        return Err(FetchError::TooLarge);
    }

    let text_fn = Reflect::get(&response, &JsValue::from_str("text"))?
        .dyn_into::<Function>()
        .map_err(|_| JsValue::from_str("response.text is not a function"))?;
    let text_promise: Promise = text_fn
        .call0(&response)?
        .dyn_into()
        .map_err(|_| JsValue::from_str("response.text() did not return a Promise"))?;
    let text = JsFuture::from(text_promise)
        .await?
        .as_string()
        .ok_or_else(|| JsValue::from_str("response body not a string"))?;

    drop(abort_guard);

    if text.len() > MAX_RESPONSE_BYTES {
        return Err(FetchError::TooLarge);
    }

    Ok((status, text))
}

/// RAII wrapper around `AbortController` + `setTimeout`. Aborts the pending
/// fetch if `timeout_ms` elapses; cleared on drop so a fast response does
/// not leave a stray timer behind. `fired()` reports whether the timer
/// triggered the abort, so the caller can re-tag the resulting `AbortError`
/// as a transport timeout.
struct AbortGuard {
    global: JsValue,
    timer: JsValue,
    fired: std::rc::Rc<std::cell::Cell<bool>>,
    // Held to keep the JS-callable wrapper alive until drop, since the
    // setTimeout queue retains a reference to it that drops when the timer
    // fires or is cleared.
    _on_timeout: Closure<dyn FnMut()>,
}

impl AbortGuard {
    fn install(global: &JsValue, init: &Object, timeout_ms: u32) -> Result<Self, JsValue> {
        let ctor = Reflect::get(global, &JsValue::from_str("AbortController"))?
            .dyn_into::<Function>()
            .map_err(|_| JsValue::from_str("globalThis.AbortController missing"))?;
        let controller = Reflect::construct(&ctor, &js_sys::Array::new())?;
        let signal = Reflect::get(&controller, &JsValue::from_str("signal"))?;
        Reflect::set(init, &JsValue::from_str("signal"), &signal)?;

        let abort_fn = Reflect::get(&controller, &JsValue::from_str("abort"))?
            .dyn_into::<Function>()
            .map_err(|_| JsValue::from_str("AbortController.abort missing"))?;
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let fired_clone = fired.clone();
        let on_timeout = Closure::wrap(Box::new(move || {
            fired_clone.set(true);
            let _ = abort_fn.call0(&controller);
        }) as Box<dyn FnMut()>);

        let set_timeout = Reflect::get(global, &JsValue::from_str("setTimeout"))?
            .dyn_into::<Function>()
            .map_err(|_| JsValue::from_str("globalThis.setTimeout missing"))?;
        let timer = set_timeout.call2(
            global,
            on_timeout.as_ref().unchecked_ref(),
            &JsValue::from_f64(f64::from(timeout_ms)),
        )?;

        Ok(Self {
            global: global.clone(),
            timer,
            fired,
            _on_timeout: on_timeout,
        })
    }

    fn fired(&self) -> bool {
        self.fired.get()
    }
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Ok(clear_timeout) = Reflect::get(&self.global, &JsValue::from_str("clearTimeout"))
            && let Ok(clear_timeout) = clear_timeout.dyn_into::<Function>()
        {
            let _ = clear_timeout.call1(&self.global, &self.timer);
        }
    }
}
