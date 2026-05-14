//! In-browser end-to-end harness for the `cowprotocol` crate.
//!
//! This shim exists to prove that the wasm32 build of `cowprotocol` not
//! only compiles (which `cargo check --target wasm32-unknown-unknown`
//! already verifies in CI) but is actually callable from JavaScript:
//! reqwest's browser-fetch backend reaches `api.cow.fi`, ECDSA key
//! material survives the wasm boundary, and the pure-compute primitives
//! (`OrderData::uid`) produce the same bytes the Rust example produces.
//!
//! Not published to crates.io; see `test-harness/index.html` for the
//! browser-side driver.

use {
    alloy_primitives::{Address, U256},
    cowprotocol::{
        Chain, DomainSeparator, EMPTY_APP_DATA_HASH, OrderBookApi, OrderBuilder, OrderKind,
        QuoteRequest,
    },
    serde::Serialize,
    wasm_bindgen::prelude::*,
};

/// Install a panic hook that writes Rust panics to the browser console.
/// Idempotent; safe to call from every entry point.
#[wasm_bindgen(start)]
pub fn _start() {
    console_error_panic_hook::set_once();
}

fn parse_address(value: &str) -> Result<Address, JsValue> {
    value
        .parse::<Address>()
        .map_err(|err| JsValue::from_str(&format!("invalid address {value}: {err}")))
}

fn parse_u256(value: &str) -> Result<U256, JsValue> {
    value
        .parse::<U256>()
        .map_err(|err| JsValue::from_str(&format!("invalid u256 {value}: {err}")))
}

/// `GET /api/v1/quote` against mainnet. Returns the orderbook response
/// as a plain JS object, plus the derived `OrderUid` the next signing
/// step would consume.
#[wasm_bindgen]
pub async fn get_quote(
    sell_token: &str,
    buy_token: &str,
    from: &str,
    sell_amount_before_fee: &str,
) -> Result<JsValue, JsValue> {
    let request = QuoteRequest::sell_amount_before_fee(
        parse_address(sell_token)?,
        parse_address(buy_token)?,
        parse_address(from)?,
        parse_u256(sell_amount_before_fee)?,
    );
    let api = OrderBookApi::new(Chain::Mainnet);
    let response = api
        .get_quote(&request)
        .await
        .map_err(|err| JsValue::from_str(&format!("get_quote failed: {err}")))?;
    let order_data = response.quote.to_order_data();
    let domain = DomainSeparator::new(Chain::Mainnet.id(), Chain::Mainnet.settlement());
    let uid = order_data.uid(&domain, response.from);
    let payload = serde_json::json!({
        "response": response,
        "uid": uid.to_string(),
    });
    // Default serializer emits JS `Map`; force plain objects so JS code can
    // do `result.response.quote.buyAmount` rather than `result.get("response").get(...)`.
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    payload
        .serialize(&serializer)
        .map_err(|err| JsValue::from_str(&format!("serialise failed: {err}")))
}

/// Pure-compute UID derivation for a minimal sell order. No network call.
/// Used by the harness to confirm the wasm boundary preserves byte-exact
/// EIP-712 hashing.
#[wasm_bindgen]
pub fn compute_order_uid(
    sell_token: &str,
    buy_token: &str,
    owner: &str,
    sell_amount: &str,
    buy_amount: &str,
    valid_to: u32,
) -> Result<String, JsValue> {
    let order = OrderBuilder::new(parse_address(sell_token)?, parse_address(buy_token)?)
        .sell_amount(parse_u256(sell_amount)?)
        .buy_amount(parse_u256(buy_amount)?)
        .valid_to(valid_to)
        .kind(OrderKind::Sell)
        .app_data(EMPTY_APP_DATA_HASH)
        .build();
    let domain = DomainSeparator::new(Chain::Mainnet.id(), Chain::Mainnet.settlement());
    let uid = order.uid(&domain, parse_address(owner)?);
    Ok(uid.to_string())
}
