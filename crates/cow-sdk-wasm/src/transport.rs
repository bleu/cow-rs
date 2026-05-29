//! JS `fetch` transport. Replaces reqwest in the wasm exports.
//!
//! Invokes the global `fetch` function via `js_sys::Reflect` so the
//! linker is free to drop reqwest from the wasm output (no
//! wasm-bindgen export needs to reach `OrderBookApi`). Skipping
//! `web-sys` keeps the binding overhead to a few kilobytes.
//!
//! Every request is bounded in two dimensions:
//!
//! - a wall-clock timeout enforced via a globalThis `AbortController`
//!   (see [`FETCH_TIMEOUT_MS`]). A stuck or hostile orderbook cannot
//!   hold the caller's task open indefinitely;
//! - a response body size cap (see [`MAX_RESPONSE_BYTES`]). A hostile
//!   orderbook streaming a multi-GB body cannot exhaust wasm linear
//!   memory.

use {
    js_sys::{Function, Object, Promise, Reflect, global},
    serde::{Serialize, de::DeserializeOwned},
    wasm_bindgen::{JsCast, JsValue, closure::Closure},
    wasm_bindgen_futures::JsFuture,
};

/// Wall-clock cap applied to every `fetch` call this module issues.
/// Derived from [`cowprotocol::order_book::DEFAULT_HTTP_TIMEOUT`], the
/// same timeout the reqwest client applies on native targets, so the two
/// transports cannot drift. The cap (30 s) is long enough for legitimate
/// orderbook traffic and short enough that a hostile peer cannot hold a
/// wasm task open indefinitely.
pub(crate) const FETCH_TIMEOUT_MS: u32 =
    cowprotocol::order_book::DEFAULT_HTTP_TIMEOUT.as_secs() as u32 * 1000;

/// Maximum byte length the wasm transport will accept for any single
/// response body. Larger payloads are rejected before being decoded
/// into a Rust `String`, so a hostile orderbook cannot OOM the wasm
/// process by streaming a multi-GB body. Imported from
/// [`cowprotocol::order_book::MAX_RESPONSE_BYTES`] so the wasm and native
/// caps cannot drift.
pub(crate) const MAX_RESPONSE_BYTES: usize = cowprotocol::order_book::MAX_RESPONSE_BYTES;

/// `GET <url>` decoded as JSON.
pub(crate) async fn get<T: DeserializeOwned>(url: &str) -> Result<T, JsValue> {
    fetch_text("GET", url, None).await.and_then(parse_json)
}

/// `POST <url>` with a JSON body, response decoded as JSON.
pub(crate) async fn post_json<TReq: Serialize + ?Sized, TResp: DeserializeOwned>(
    url: &str,
    body: &TReq,
) -> Result<TResp, JsValue> {
    let body = serde_json::to_string(body)
        .map_err(|err| JsValue::from_str(&format!("serialise failed: {err}")))?;
    fetch_text("POST", url, Some(&body))
        .await
        .and_then(parse_json)
}

/// `POST <url>` with a JSON body, response decoded as a plain string.
/// `POST /api/v1/orders` returns the UID as a bare JSON string; this
/// keeps the `Result<String, JsValue>` shape ergonomic for the caller.
pub(crate) async fn post_json_string<TReq: Serialize + ?Sized>(
    url: &str,
    body: &TReq,
) -> Result<String, JsValue> {
    post_json::<TReq, String>(url, body).await
}

/// `DELETE <url>` with a JSON body, response discarded on 2xx.
pub(crate) async fn delete_json<TReq: Serialize + ?Sized>(
    url: &str,
    body: &TReq,
) -> Result<(), JsValue> {
    let body = serde_json::to_string(body)
        .map_err(|err| JsValue::from_str(&format!("serialise failed: {err}")))?;
    fetch_text("DELETE", url, Some(&body)).await.map(|_| ())
}

/// `GET <url>` decoded as plain text (the `/version` endpoint returns a
/// bare string, not JSON).
pub(crate) async fn get_text(url: &str) -> Result<String, JsValue> {
    fetch_text("GET", url, None).await
}

async fn fetch_text(method: &str, url: &str, body: Option<&str>) -> Result<String, JsValue> {
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
    // setTimeout fires before the response arrives, the in-flight
    // fetch rejects with an `AbortError` we surface as a timeout.
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
            return Err(if abort_guard.fired() {
                JsValue::from_str(&format!("request timed out after {FETCH_TIMEOUT_MS} ms"))
            } else {
                err
            });
        }
    };

    let status: u32 = Reflect::get(&response, &JsValue::from_str("status"))?
        .as_f64()
        .ok_or_else(|| JsValue::from_str("response.status missing"))? as u32;

    // Reject oversized bodies before reading them into linear memory.
    // The header is advisory (proxies strip it, some servers omit it);
    // a post-read backstop below catches the cases it does not cover.
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
        return Err(JsValue::from_str(&format!(
            "response too large: Content-Length {declared} exceeds {MAX_RESPONSE_BYTES}-byte cap"
        )));
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
        return Err(JsValue::from_str(&format!(
            "response too large: {} bytes exceeds {MAX_RESPONSE_BYTES}-byte cap",
            text.len()
        )));
    }

    if !(200..300).contains(&status) {
        return Err(JsValue::from_str(&format!("HTTP {status}: {text}")));
    }
    Ok(text)
}

/// RAII wrapper around `AbortController` + `setTimeout`. Aborts the
/// pending fetch if `timeout_ms` elapses; cleared on drop so a fast
/// response does not leave a stray timer behind. `fired()` reports
/// whether the timer triggered the abort, so the caller can re-tag
/// the resulting `AbortError` as a transport timeout.
struct AbortGuard {
    global: JsValue,
    timer: JsValue,
    fired: std::rc::Rc<std::cell::Cell<bool>>,
    // Held to keep the JS-callable wrapper alive until drop, since the
    // setTimeout queue retains a reference to it that drops when the
    // timer fires or is cleared.
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

fn parse_json<T: DeserializeOwned>(text: String) -> Result<T, JsValue> {
    serde_json::from_str(&text)
        .map_err(|err| JsValue::from_str(&format!("deserialise failed: {err}")))
}
