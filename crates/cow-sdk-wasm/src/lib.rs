//! `@cowdao-grants/cow-sdk-wasm`: JavaScript-facing bindings for the
//! `cowprotocol` Rust SDK, generated via `wasm-bindgen`.
//!
//! Every exported function takes / returns JSON-compatible values
//! (`JsValue`s serialised by `serde-wasm-bindgen` with
//! `serialize_maps_as_objects(true)`). Hex strings, addresses and
//! `U256` values cross the boundary as strings to side-step JS's
//! `Number` precision limits.
//!
//! Two signing flows are supported:
//!
//! 1. **In-shim signing** (gated behind the `in_shim_signing` cargo
//!    feature; *test- and script-only*): pass a 0x-prefixed 32-byte
//!    private-key hex string to `sign_eip712` / `sign_ethsign`.
//!    The signer stays in wasm linear memory rather than crossing
//!    the JS boundary, but the **hex string itself is owned by JS**
//!    and is not zeroised after it crosses into wasm. Any other code
//!    running in the same JS realm (extensions, ad scripts,
//!    third-party libraries) can read it. **Never hand a production
//!    key to this path.** Treat it the same as `console.log`-ing
//!    the key. Production integrations sign with viem / ethers /
//!    Safe and never pass a raw private key to wasm.
//! 2. **External signing** (recommended for production): build the
//!    EIP-712 hash with [`order_struct_hash`] +
//!    [`eip712_message_hash`], have the caller's wallet (viem,
//!    ethers, Safe, WalletConnect) sign it, then feed the (r, s, v)
//!    back through [`build_order_creation`].

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![deny(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]

mod allocator;
mod app_data;
mod endpoints;
mod signing;
mod transport;

#[doc(inline)]
pub use {
    app_data::{
        app_data_cid_from_hash, app_data_hash_from_json, empty_app_data_hash, sdk_app_data_hash,
        sdk_app_data_json, to_signed_order_data,
    },
    endpoints::{
        account_orders, cancel_order, get_order, get_order_status, get_quote, get_quote_simple,
        native_price, post_order, trades_by_order_uid, trades_by_owner, version,
    },
    signing::{
        build_order_creation, build_order_creation_eip1271, eip712_message_hash, eip712_payload,
        order_struct_hash, order_uid,
    },
};

#[cfg(feature = "in_shim_signing")]
#[doc(inline)]
pub use signing::{cancel_order_signed, sign_eip712, sign_ethsign};

use {
    alloy_primitives::{Address, B256},
    cowprotocol::{Chain, EcdsaSigningScheme, OrderUid},
    serde::{Deserialize, Serialize},
    wasm_bindgen::prelude::*,
};

/// `wasm-pack` start hook. Installs a panic handler that surfaces Rust
/// panics in the browser console; idempotent so it is safe for every
/// entry point. Invoked automatically by `init()`.
#[wasm_bindgen(start)]
pub fn _start() {
    console_error_panic_hook::set_once();
}

pub(crate) fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value
        .serialize(&serializer)
        .map_err(js_err("serialise failed"))
}

pub(crate) fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js_err("deserialise failed"))
}

/// `map_err` adapter that prefixes a fixed context onto any
/// [`Display`](core::fmt::Display) error, producing the
/// `"<ctx>: <err>"` string the JS boundary surfaces. Lets the call
/// sites write `.map_err(js_err("<ctx>"))` instead of repeating the
/// `format!` closure.
pub(crate) fn js_err<E: core::fmt::Display>(ctx: &'static str) -> impl FnOnce(E) -> JsValue {
    move |err| JsValue::from_str(&format!("{ctx}: {err}"))
}

pub(crate) fn parse_typed<T>(value: &str, kind: &str) -> Result<T, JsValue>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|err| JsValue::from_str(&format!("invalid {kind} {value}: {err}")))
}

pub(crate) fn parse_address(value: &str) -> Result<Address, JsValue> {
    parse_typed(value, "address")
}

pub(crate) fn parse_uid(value: &str) -> Result<OrderUid, JsValue> {
    parse_typed(value, "order uid")
}

pub(crate) fn parse_b256(value: &str) -> Result<B256, JsValue> {
    parse_typed(value, "32-byte hex")
}

pub(crate) fn parse_chain(value: &str) -> Result<Chain, JsValue> {
    parse_typed(value, "chain")
}

pub(crate) fn parse_scheme(value: &str) -> Result<EcdsaSigningScheme, JsValue> {
    match value.to_ascii_lowercase().as_str() {
        "eip712" => Ok(EcdsaSigningScheme::Eip712),
        "ethsign" => Ok(EcdsaSigningScheme::EthSign),
        other => Err(JsValue::from_str(&format!(
            "unknown signing scheme {other}; expected eip712 or ethsign"
        ))),
    }
}

// ===== Pure-compute helpers ============================================

/// Per-chain config: numeric id, settlement / vault-relayer / ETH-flow
/// contract addresses, orderbook (prod and barn) URLs, subgraph gateway
/// deployment id, and ComposableCoW support flag.
#[wasm_bindgen]
pub fn chain_info(chain: &str) -> Result<JsValue, JsValue> {
    let c = parse_chain(chain)?;
    let info = serde_json::json!({
        "id": c.id(),
        "settlement": c.settlement().to_string(),
        "vaultRelayer": c.vault_relayer().to_string(),
        "orderbookBaseUrl": c.orderbook_base_url().to_string(),
        "orderbookBarnUrl": c.orderbook_barn_url().map(|u| u.to_string()),
        "subgraphGatewayDeploymentId": c.subgraph_gateway_deployment_id(),
        "supportsComposableCow": c.supports_composable_cow(),
        "composableCow": c.composable_cow_address().map(|a| a.to_string()),
        "extensibleFallbackHandler": c.extensible_fallback_handler_address().map(|a| a.to_string()),
        "currentBlockTimestampFactory": c.current_block_timestamp_factory_address().map(|a| a.to_string()),
    });
    to_js(&info)
}

/// EIP-712 domain separator for a given chain. Returns 32-byte hex.
#[wasm_bindgen]
pub fn domain_separator(chain: &str) -> Result<String, JsValue> {
    let c = parse_chain(chain)?;
    let domain = c.settlement_domain();
    Ok(domain.separator().to_string())
}
