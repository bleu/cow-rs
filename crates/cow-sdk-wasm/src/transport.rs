//! JS `fetch` transport. Replaces reqwest in the wasm exports.
//!
//! Invokes the global `fetch` function via `js_sys::Reflect` so the
//! linker is free to drop reqwest from the wasm output (no
//! wasm-bindgen export needs to reach `OrderBookApi`). Skipping
//! `web-sys` keeps the binding overhead to a few kilobytes.

use {
    js_sys::{Function, Object, Promise, Reflect, global},
    serde::{Serialize, de::DeserializeOwned},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

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
    fetch_text("POST", url, Some(&body)).await.and_then(parse_json)
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
    Reflect::set(&init, &JsValue::from_str("method"), &JsValue::from_str(method))?;
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
    let fetch = Reflect::get(&global, &JsValue::from_str("fetch"))?
        .dyn_into::<Function>()
        .map_err(|_| JsValue::from_str("global fetch is not a function"))?;
    let promise: Promise = fetch
        .call2(&global, &JsValue::from_str(url), &init)?
        .dyn_into()
        .map_err(|_| JsValue::from_str("fetch did not return a Promise"))?;
    let response = JsFuture::from(promise).await?;

    let status: u32 = Reflect::get(&response, &JsValue::from_str("status"))?
        .as_f64()
        .ok_or_else(|| JsValue::from_str("response.status missing"))? as u32;

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

    if !(200..300).contains(&status) {
        return Err(JsValue::from_str(&format!("HTTP {status}: {text}")));
    }
    Ok(text)
}

fn parse_json<T: DeserializeOwned>(text: String) -> Result<T, JsValue> {
    serde_json::from_str(&text)
        .map_err(|err| JsValue::from_str(&format!("deserialise failed: {err}")))
}
