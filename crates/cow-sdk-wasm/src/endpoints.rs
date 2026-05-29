//! Networked endpoint bindings.
//!
//! All requests go through `transport::*` (a thin wrapper over the JS
//! `fetch` global) rather than through `cowprotocol::OrderBookApi`. This
//! keeps reqwest out of the wasm output: with `lto = "fat"`, any
//! reqwest-using code in `cowprotocol` that is not reached from a
//! wasm-bindgen export gets pruned during linking.

use {
    crate::{
        endpoint, from_js, js_err, parse_address, parse_chain, parse_uid, push_pagination, to_js,
        transport,
    },
    alloy_primitives::U256,
    cowprotocol::{EMPTY_APP_DATA_HASH, QuoteRequest, SignedOrderCancellation},
    wasm_bindgen::prelude::*,
};

fn parse_u256(value: &str) -> Result<U256, JsValue> {
    crate::parse_typed(value, "u256")
}

/// `POST /api/v1/quote`. Accepts a `QuoteRequest` JSON object.
///
/// Cross-checks the response against the request via
/// [`cowprotocol::OrderQuoteResponse::try_into_signed_order_data`] before
/// returning, so a hostile orderbook cannot hand JS callers a swapped
/// `sellToken` / `buyToken` / `receiver` / `from` / `kind` they would
/// then pass into
/// [`to_signed_order_data`](crate::app_data::to_signed_order_data) /
/// [`build_order_creation`](crate::signing::build_order_creation).
/// The empty-document app-data hash is used for the bind check; the
/// caller's eventual signing-time digest is checked again when they
/// call [`to_signed_order_data`](crate::app_data::to_signed_order_data).
#[wasm_bindgen]
pub async fn get_quote(chain: &str, request: JsValue) -> Result<JsValue, JsValue> {
    let request: QuoteRequest = from_js(request)?;
    // This wasm path posts straight through `transport`, so it skips the
    // `request.validate()` core's `OrderBookApi::quote` runs. Re-assert
    // the request-shape invariants here so a deserialised, inconsistent
    // request never reaches the orderbook.
    request
        .validate()
        .map_err(js_err("invalid quote request"))?;
    let url = endpoint(parse_chain(chain)?, "api/v1/quote");
    let response: cowprotocol::OrderQuoteResponse = transport::post_json(&url, &request).await?;
    response
        .try_into_signed_order_data(&request, EMPTY_APP_DATA_HASH)
        .map_err(js_err("quote response binding failed"))?;
    to_js(&response)
}

/// Convenience: same as [`get_quote`] but accepts the four most-common
/// inputs as plain strings and uses `sellAmountBeforeFee`. Returns the
/// raw response plus the derived `OrderUid` (the next signing step's
/// target).
#[wasm_bindgen]
pub async fn get_quote_simple(
    chain: &str,
    sell_token: &str,
    buy_token: &str,
    from: &str,
    sell_amount_before_fee: &str,
) -> Result<JsValue, JsValue> {
    let request = QuoteRequest::sell_before_fee(
        parse_address(sell_token)?,
        parse_address(buy_token)?,
        parse_address(from)?,
        parse_u256(sell_amount_before_fee)?,
    );
    let c = parse_chain(chain)?;
    let url = endpoint(c, "api/v1/quote");
    let response: cowprotocol::OrderQuoteResponse = transport::post_json(&url, &request).await?;
    let order_data = response
        .try_into_signed_order_data(&request, cowprotocol::EMPTY_APP_DATA_HASH)
        .map_err(js_err("to_signed_order_data failed"))?;
    let domain = c.settlement_domain();
    let uid = order_data.uid(&domain, response.from);
    let payload = serde_json::json!({
        "response": response,
        "uid": uid.to_string(),
    });
    to_js(&payload)
}

/// `POST /api/v1/orders`. Returns the assigned 56-byte UID.
///
/// The assembled `OrderCreation` is verified locally via
/// [`cowprotocol::OrderCreation::verify_owner`] before any network
/// call, mirroring the guard
/// [`build_order_creation`](crate::signing::build_order_creation)
/// performs, so a
/// hand-assembled body with a typo'd `from` is rejected client-side
/// rather than as a 4xx from the orderbook.
#[wasm_bindgen]
pub async fn post_order(chain: &str, creation: JsValue) -> Result<String, JsValue> {
    let creation: cowprotocol::OrderCreation = from_js(creation)?;
    let c = parse_chain(chain)?;
    let domain = c.settlement_domain();
    creation
        .verify_owner(&domain)
        .map_err(js_err("verify_owner"))?;
    let url = endpoint(c, "api/v1/orders");
    transport::post_json_string(&url, &creation).await
}

/// `GET /api/v1/orders/{uid}`.
#[wasm_bindgen]
pub async fn get_order(chain: &str, uid: &str) -> Result<JsValue, JsValue> {
    let uid = parse_uid(uid)?;
    let url = endpoint(parse_chain(chain)?, &format!("api/v1/orders/{uid}"));
    let order: cowprotocol::Order = transport::get(&url).await?;
    to_js(&order)
}

/// `GET /api/v1/orders/{uid}/status`.
#[wasm_bindgen]
pub async fn get_order_status(chain: &str, uid: &str) -> Result<JsValue, JsValue> {
    let uid = parse_uid(uid)?;
    let url = endpoint(parse_chain(chain)?, &format!("api/v1/orders/{uid}/status"));
    let status: cowprotocol::AuctionStatus = transport::get(&url).await?;
    to_js(&status)
}

/// `GET /api/v1/account/{owner}/orders`.
#[wasm_bindgen]
pub async fn account_orders(
    chain: &str,
    owner: &str,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<JsValue, JsValue> {
    let owner = parse_address(owner)?;
    let mut path = format!("api/v1/account/{owner:?}/orders");
    push_pagination(&mut path, offset, limit);
    let url = endpoint(parse_chain(chain)?, &path);
    let orders: Vec<cowprotocol::Order> = transport::get(&url).await?;
    to_js(&orders)
}

/// `GET /api/v2/trades?owner=...`. Paginated; omit `offset` / `limit`
/// for the server defaults.
#[wasm_bindgen]
pub async fn trades_by_owner(
    chain: &str,
    owner: &str,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<JsValue, JsValue> {
    let owner = parse_address(owner)?;
    let mut path = format!("api/v2/trades?owner={owner:?}");
    push_pagination(&mut path, offset, limit);
    let url = endpoint(parse_chain(chain)?, &path);
    let trades: Vec<cowprotocol::Trade> = transport::get(&url).await?;
    to_js(&trades)
}

/// `GET /api/v2/trades?orderUid=...`. Paginated; omit `offset` / `limit`
/// for the server defaults.
#[wasm_bindgen]
pub async fn trades_by_order_uid(
    chain: &str,
    uid: &str,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<JsValue, JsValue> {
    let uid = parse_uid(uid)?;
    let mut path = format!("api/v2/trades?orderUid={uid}");
    push_pagination(&mut path, offset, limit);
    let url = endpoint(parse_chain(chain)?, &path);
    let trades: Vec<cowprotocol::Trade> = transport::get(&url).await?;
    to_js(&trades)
}

/// `GET /api/v1/token/{token}/native_price`.
#[wasm_bindgen]
pub async fn native_price(chain: &str, token: &str) -> Result<JsValue, JsValue> {
    let token = parse_address(token)?;
    let url = endpoint(
        parse_chain(chain)?,
        &format!("api/v1/token/{token:?}/native_price"),
    );
    let price: cowprotocol::NativePrice = transport::get(&url).await?;
    to_js(&price)
}

/// `GET /api/v1/version`.
#[wasm_bindgen]
pub async fn version(chain: &str) -> Result<String, JsValue> {
    let url = endpoint(parse_chain(chain)?, "api/v1/version");
    transport::get_text(&url).await
}

/// `DELETE /api/v1/orders/{uid}`. Caller must construct the signed
/// `SignedOrderCancellation` (see `cancel_order_signed`) and pass it here.
#[wasm_bindgen]
pub async fn cancel_order(chain: &str, cancellation: JsValue) -> Result<(), JsValue> {
    let cancellation: SignedOrderCancellation = from_js(cancellation)?;
    let url = endpoint(
        parse_chain(chain)?,
        &format!("api/v1/orders/{}", cancellation.order_uid),
    );
    transport::delete_json(&url, &cancellation).await
}
