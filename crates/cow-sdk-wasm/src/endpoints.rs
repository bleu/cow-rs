//! Networked endpoint bindings.
//!
//! Every binding drives a shared [`cowprotocol::OrderBookApi`] backed by
//! the JS [`FetchTransport`](crate::transport::FetchTransport), so request
//! shaping, pagination, status handling and JSON decoding come from the
//! core crate rather than being re-implemented here. reqwest stays out of
//! the wasm output because `OrderBookApi<FetchTransport>` never links the
//! native `ReqwestTransport` (gated behind the `http-client` feature, which
//! this crate leaves off).

use {
    crate::{
        from_js, js_err, parse_address, parse_chain, parse_typed, parse_uid, to_js,
        transport::FetchTransport,
    },
    alloy_primitives::U256,
    cowprotocol::{
        Chain, EMPTY_APP_DATA_HASH, OrderBookApi, OrderCosts, OrderCreation, QuoteRequest,
        SignedOrderCancellation,
    },
    wasm_bindgen::prelude::*,
};

fn parse_u256(value: &str) -> Result<U256, JsValue> {
    parse_typed(value, "u256")
}

/// A `fetch`-backed orderbook client for `chain`. Cheap to build per call:
/// [`FetchTransport`] is a unit struct and the base URL is a single join.
fn client(chain: Chain) -> OrderBookApi<FetchTransport> {
    OrderBookApi::new_with_transport(chain.orderbook_base_url(), FetchTransport)
        .with_chain_hint(chain)
}

/// `POST /api/v1/quote`. Accepts a `QuoteRequest` JSON object.
///
/// [`OrderBookApi::quote`] re-asserts the request-shape invariants
/// ([`QuoteRequest::validate`]) before issuing the request. The
/// hostile-orderbook response binding (cross-checking `sellToken` /
/// `buyToken` / `receiver` / `from` / `kind` / pinned `appData`
/// against the request) runs at the projection chokepoint instead:
/// [`to_signed_order_data`](crate::app_data::to_signed_order_data) and
/// [`build_order_creation`](crate::signing::build_order_creation) both
/// re-run it with the caller's real app-data digest, so checking here
/// with a guessed digest would only reject requests that pin a
/// non-empty `appData`.
#[wasm_bindgen]
pub async fn get_quote(chain: &str, request: JsValue) -> Result<JsValue, JsValue> {
    let request: QuoteRequest = from_js(request)?;
    let response = client(parse_chain(chain)?)
        .quote(&request)
        .await
        .map_err(js_err("quote request failed"))?;
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
    let response = client(c)
        .quote(&request)
        .await
        .map_err(js_err("quote request failed"))?;
    let order_data = response
        .try_to_order_data(&request, EMPTY_APP_DATA_HASH, &OrderCosts::default())
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
/// [`cowprotocol::OrderCreation::verify_owner`] before any network call,
/// mirroring the guard
/// [`build_order_creation`](crate::signing::build_order_creation)
/// performs, so a hand-assembled body with a typo'd `from` is rejected
/// client-side rather than as a 4xx from the orderbook.
#[wasm_bindgen]
pub async fn post_order(chain: &str, creation: JsValue) -> Result<String, JsValue> {
    let creation: OrderCreation = from_js(creation)?;
    let c = parse_chain(chain)?;
    let domain = c.settlement_domain();
    creation
        .verify_owner(&domain)
        .map_err(js_err("verify_owner"))?;
    client(c)
        .post_order(&creation)
        .await
        .map(|uid| uid.to_string())
        .map_err(js_err("post_order failed"))
}

/// `GET /api/v1/orders/{uid}`.
#[wasm_bindgen]
pub async fn get_order(chain: &str, uid: &str) -> Result<JsValue, JsValue> {
    let order = client(parse_chain(chain)?)
        .order(&parse_uid(uid)?)
        .await
        .map_err(js_err("get_order failed"))?;
    to_js(&order)
}

/// `GET /api/v1/orders/{uid}/status`.
#[wasm_bindgen]
pub async fn get_order_status(chain: &str, uid: &str) -> Result<JsValue, JsValue> {
    let status = client(parse_chain(chain)?)
        .order_status(&parse_uid(uid)?)
        .await
        .map_err(js_err("get_order_status failed"))?;
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
    let orders = client(parse_chain(chain)?)
        .account_orders(parse_address(owner)?, offset, limit)
        .await
        .map_err(js_err("account_orders failed"))?;
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
    let trades = client(parse_chain(chain)?)
        .trades_by_owner(parse_address(owner)?, offset, limit)
        .await
        .map_err(js_err("trades_by_owner failed"))?;
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
    let trades = client(parse_chain(chain)?)
        .trades_by_order_uid(&parse_uid(uid)?, offset, limit)
        .await
        .map_err(js_err("trades_by_order_uid failed"))?;
    to_js(&trades)
}

/// `GET /api/v1/token/{token}/native_price`.
#[wasm_bindgen]
pub async fn native_price(chain: &str, token: &str) -> Result<JsValue, JsValue> {
    let price = client(parse_chain(chain)?)
        .native_price(parse_address(token)?)
        .await
        .map_err(js_err("native_price failed"))?;
    to_js(&price)
}

/// `GET /api/v1/version`.
#[wasm_bindgen]
pub async fn version(chain: &str) -> Result<String, JsValue> {
    client(parse_chain(chain)?)
        .version()
        .await
        .map_err(js_err("version failed"))
}

/// `DELETE /api/v1/orders/{uid}`. Caller must construct the signed
/// `SignedOrderCancellation` (see `cancel_order_signed`) and pass it here.
#[wasm_bindgen]
pub async fn cancel_order(chain: &str, cancellation: JsValue) -> Result<(), JsValue> {
    let cancellation: SignedOrderCancellation = from_js(cancellation)?;
    client(parse_chain(chain)?)
        .cancel_order(&cancellation)
        .await
        .map_err(js_err("cancel_order failed"))
}
