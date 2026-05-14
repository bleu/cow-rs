//! `@cowdao-grants/cow-sdk-wasm`: JavaScript-facing surface of the
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
//! 1. **In-shim signing**: pass a 0x-prefixed 32-byte private-key hex
//!    string to [`sign_eip712`] / [`sign_ethsign`]. The signer never
//!    leaves wasm linear memory but is in-process; suitable for tests
//!    and scripts.
//! 2. **External signing**: build the EIP-712 hash with
//!    [`order_struct_hash`] + [`hashed_eip712_message`], have the
//!    caller's wallet (viem, ethers, Safe, WalletConnect) sign it, then
//!    feed the (r, s, v) back through [`build_order_creation`].

mod allocator;
mod transport;

use {
    alloy_primitives::{Address, B256, U256},
    cowprotocol::{
        AppDataCid, AppDataDoc, AppDataHash, Chain, DomainSeparator, EMPTY_APP_DATA_HASH,
        EcdsaSignature, EcdsaSigningScheme, OrderBuilder, OrderCancellation, OrderData, OrderKind,
        OrderUid, QuoteRequest, Signature, hashed_eip712_message,
    },
    serde::{Deserialize, Serialize},
    wasm_bindgen::prelude::*,
};

#[cfg(feature = "in_shim_signing")]
use alloy_signer_local::PrivateKeySigner;

/// `wasm-pack` start hook. Installs a panic handler that surfaces Rust
/// panics in the browser console; idempotent so it is safe for every
/// entry point. Invoked automatically by `init()`.
#[wasm_bindgen(start)]
pub fn _start() {
    console_error_panic_hook::set_once();
}

fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value
        .serialize(&serializer)
        .map_err(|err| JsValue::from_str(&format!("serialise failed: {err}")))
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|err| JsValue::from_str(&format!("deserialise failed: {err}")))
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

fn parse_uid(value: &str) -> Result<OrderUid, JsValue> {
    value
        .parse::<OrderUid>()
        .map_err(|err| JsValue::from_str(&format!("invalid order uid {value}: {err}")))
}

fn parse_b256(value: &str) -> Result<B256, JsValue> {
    value
        .parse::<B256>()
        .map_err(|err| JsValue::from_str(&format!("invalid 32-byte hex {value}: {err}")))
}

fn parse_chain(chain: &str) -> Result<Chain, JsValue> {
    let normalised = chain.to_ascii_lowercase().replace('-', "");
    let chain = match normalised.as_str() {
        "mainnet" | "1" => Chain::Mainnet,
        "bnb" | "56" => Chain::Bnb,
        "gnosis" | "100" => Chain::Gnosis,
        "polygon" | "137" => Chain::Polygon,
        "base" | "8453" => Chain::Base,
        "plasma" | "9745" => Chain::Plasma,
        "arbitrum" | "arbitrumone" | "42161" => Chain::ArbitrumOne,
        "avalanche" | "43114" => Chain::Avalanche,
        "ink" | "57073" => Chain::Ink,
        "linea" | "59144" => Chain::Linea,
        "sepolia" | "11155111" => Chain::Sepolia,
        _ => return Err(JsValue::from_str(&format!("unknown chain {chain}"))),
    };
    Ok(chain)
}

#[cfg(feature = "in_shim_signing")]
fn parse_signer(private_key_hex: &str) -> Result<PrivateKeySigner, JsValue> {
    private_key_hex
        .parse::<PrivateKeySigner>()
        .map_err(|err| JsValue::from_str(&format!("invalid private key: {err}")))
}

fn parse_scheme(value: &str) -> Result<EcdsaSigningScheme, JsValue> {
    match value.to_ascii_lowercase().as_str() {
        "eip712" => Ok(EcdsaSigningScheme::Eip712),
        "ethsign" => Ok(EcdsaSigningScheme::EthSign),
        other => Err(JsValue::from_str(&format!(
            "unknown signing scheme {other}; expected eip712 or ethsign"
        ))),
    }
}

/// Build an `api/v1/...` URL against the given chain's orderbook base.
/// Used by every networked endpoint below. Replaces the prior
/// `OrderBookApi::new(...)` path so the wasm output does not need to
/// link reqwest.
fn endpoint(chain: Chain, path: &str) -> String {
    let base = chain.orderbook_base_url();
    let base = base.as_str();
    if base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

// ===== Pure-compute helpers ============================================

/// Per-chain config: numeric id, settlement / vault-relayer / ETH-flow
/// contract addresses, orderbook (prod and barn) URLs, subgraph URL,
/// and ComposableCoW support flag.
#[wasm_bindgen]
pub fn chain_info(chain: &str) -> Result<JsValue, JsValue> {
    let c = parse_chain(chain)?;
    let info = serde_json::json!({
        "id": c.id(),
        "settlement": c.settlement().to_string(),
        "vaultRelayer": c.vault_relayer().to_string(),
        "orderbookBaseUrl": c.orderbook_base_url().to_string(),
        "orderbookBarnUrl": c.orderbook_barn_url().map(|u| u.to_string()),
        "subgraphStudioUrl": c.subgraph_studio_url().map(|u| u.to_string()),
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
    let domain = DomainSeparator::new(c.id(), c.settlement());
    Ok(format!("0x{}", const_hex::encode(domain.0)))
}

/// Canonical EIP-712 typed-data payload for an order, ready to feed
/// into viem's `signTypedData` or ethers' `signer.signTypedData`. Lets
/// JS callers sign with their own wallet without redefining the
/// `Order` type or the `Gnosis Protocol` domain separator.
///
/// Returns `{ domain, primaryType, types, message }`. The `message`
/// normalises `receiver: null` to `address(0)` so the hash the wallet
/// signs matches what `OrderData::hash_struct` computes server-side.
#[wasm_bindgen]
pub fn eip712_payload(order_data: JsValue, chain: &str) -> Result<JsValue, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let c = parse_chain(chain)?;
    let mut message = serde_json::to_value(order)
        .map_err(|err| JsValue::from_str(&format!("serialise order failed: {err}")))?;
    // null receiver gets hashed as address(0); make that explicit.
    if message.get("receiver").is_none_or(serde_json::Value::is_null) {
        message["receiver"] = serde_json::Value::String(Address::ZERO.to_string());
    }
    let payload = serde_json::json!({
        "domain": {
            "name": "Gnosis Protocol",
            "version": "v2",
            "chainId": c.id(),
            "verifyingContract": c.settlement().to_string(),
        },
        "primaryType": "Order",
        "types": {
            "Order": [
                {"name": "sellToken",          "type": "address"},
                {"name": "buyToken",           "type": "address"},
                {"name": "receiver",           "type": "address"},
                {"name": "sellAmount",         "type": "uint256"},
                {"name": "buyAmount",          "type": "uint256"},
                {"name": "validTo",            "type": "uint32"},
                {"name": "appData",            "type": "bytes32"},
                {"name": "feeAmount",          "type": "uint256"},
                {"name": "kind",               "type": "string"},
                {"name": "partiallyFillable",  "type": "bool"},
                {"name": "sellTokenBalance",   "type": "string"},
                {"name": "buyTokenBalance",    "type": "string"},
            ],
        },
        "message": message,
    });
    to_js(&payload)
}

/// `keccak256(order)` struct hash (the input to EIP-712's `_hashTypedData`).
/// Accepts the same JSON shape that `OrderData` serialises to.
#[wasm_bindgen]
pub fn order_struct_hash(order_data: JsValue) -> Result<String, JsValue> {
    let order: OrderData = from_js(order_data)?;
    Ok(format!("0x{}", const_hex::encode(order.hash_struct())))
}

/// 56-byte `OrderUid` for the order against the given chain's domain.
/// Returns `0x` + 112 hex chars.
#[wasm_bindgen]
pub fn order_uid(order_data: JsValue, chain: &str, owner: &str) -> Result<String, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let c = parse_chain(chain)?;
    let domain = DomainSeparator::new(c.id(), c.settlement());
    Ok(order.uid(&domain, parse_address(owner)?).to_string())
}

/// EIP-712 wrapped hash `keccak256(0x1901 || domain || struct_hash)`.
#[wasm_bindgen]
pub fn eip712_message_hash(domain_hex: &str, struct_hash_hex: &str) -> Result<String, JsValue> {
    let domain = parse_b256(domain_hex)?;
    let struct_hash = parse_b256(struct_hash_hex)?;
    let separator = DomainSeparator(domain.0);
    let digest = hashed_eip712_message(&separator, &struct_hash);
    Ok(format!("0x{}", const_hex::encode(digest)))
}

/// In-shim ECDSA signing. Returns the (r, s, v) packed signature plus
/// the chosen scheme; feed the result into [`build_order_creation`].
/// Requires the `in_shim_signing` cargo feature.
#[cfg(feature = "in_shim_signing")]
#[wasm_bindgen]
pub fn sign_eip712(
    order_data: JsValue,
    chain: &str,
    private_key_hex: &str,
) -> Result<JsValue, JsValue> {
    sign_with_scheme(
        order_data,
        chain,
        private_key_hex,
        EcdsaSigningScheme::Eip712,
    )
}

/// In-shim signing with the EthSign (personal_sign) variant.
/// Requires the `in_shim_signing` cargo feature.
#[cfg(feature = "in_shim_signing")]
#[wasm_bindgen]
pub fn sign_ethsign(
    order_data: JsValue,
    chain: &str,
    private_key_hex: &str,
) -> Result<JsValue, JsValue> {
    sign_with_scheme(
        order_data,
        chain,
        private_key_hex,
        EcdsaSigningScheme::EthSign,
    )
}

#[cfg(feature = "in_shim_signing")]
fn sign_with_scheme(
    order_data: JsValue,
    chain: &str,
    private_key_hex: &str,
    scheme: EcdsaSigningScheme,
) -> Result<JsValue, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let c = parse_chain(chain)?;
    let domain = DomainSeparator::new(c.id(), c.settlement());
    let signer = parse_signer(private_key_hex)?;
    let ecdsa = EcdsaSignature::sign(scheme, &domain, &order.hash_struct(), &signer)
        .map_err(|err| JsValue::from_str(&format!("sign failed: {err}")))?;
    let payload = serde_json::json!({
        "signingScheme": scheme_to_str(scheme),
        "r": format!("0x{}", const_hex::encode(ecdsa.r.0)),
        "s": format!("0x{}", const_hex::encode(ecdsa.s.0)),
        "v": ecdsa.v,
        "owner": signer.address().to_string(),
    });
    to_js(&payload)
}

#[cfg(feature = "in_shim_signing")]
fn scheme_to_str(scheme: EcdsaSigningScheme) -> &'static str {
    match scheme {
        EcdsaSigningScheme::Eip712 => "eip712",
        EcdsaSigningScheme::EthSign => "ethsign",
    }
}

/// Build a `POST /orders` payload from a signed order. Accepts a
/// signature object produced by [`sign_eip712`] / [`sign_ethsign`], or
/// an externally signed `{ signingScheme, r, s, v }` bag with matching
/// shape.
#[wasm_bindgen]
pub fn build_order_creation(
    order_data: JsValue,
    signature: JsValue,
    owner: &str,
    app_data_json: &str,
    quote_id: Option<u64>,
) -> Result<JsValue, JsValue> {
    let order: OrderData = from_js(order_data)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SigInput {
        signing_scheme: String,
        r: String,
        s: String,
        v: u8,
    }
    let sig: SigInput = from_js(signature)?;
    let scheme = parse_scheme(&sig.signing_scheme)?;
    let r = parse_b256(&sig.r)?;
    let s = parse_b256(&sig.s)?;
    let ecdsa = EcdsaSignature { r, s, v: sig.v };
    let signature = ecdsa.to_signature(scheme);
    let creation = cowprotocol::OrderCreation::from_signed_order_data(
        order,
        signature,
        parse_address(owner)?,
        app_data_json.to_owned(),
        quote_id.map(|id| id as i64),
    )
    .map_err(|err| JsValue::from_str(&format!("build creation failed: {err}")))?;
    to_js(&creation)
}

/// Apply an externally produced EIP-1271 signature (Safe / contract
/// wallet). `owner` must be the smart-wallet contract address that
/// `isValidSignature` will be called on. `signature_hex` is the
/// contract's expected calldata (often the wrapper bytes Safe's
/// `signMessage` returns).
#[wasm_bindgen]
pub fn build_order_creation_eip1271(
    order_data: JsValue,
    signature_hex: &str,
    owner: &str,
    app_data_json: &str,
    quote_id: Option<u64>,
) -> Result<JsValue, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let bytes = const_hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|err| JsValue::from_str(&format!("invalid signature hex: {err}")))?;
    let signature = Signature::Eip1271(bytes);
    let creation = cowprotocol::OrderCreation::from_signed_order_data(
        order,
        signature,
        parse_address(owner)?,
        app_data_json.to_owned(),
        quote_id.map(|id| id as i64),
    )
    .map_err(|err| JsValue::from_str(&format!("build creation failed: {err}")))?;
    to_js(&creation)
}

/// Canonicalise an app-data document (deep-sorted keys, fixed
/// stringification) and return the keccak256 of the bytes. This is the
/// `appData` field written into the signed order.
#[wasm_bindgen]
pub fn app_data_hash_from_doc(doc: JsValue) -> Result<String, JsValue> {
    let parsed: AppDataDoc = from_js(doc)?;
    let hash = parsed
        .try_hash()
        .map_err(|err| JsValue::from_str(&format!("hash failed: {err}")))?;
    Ok(hash.to_string())
}

/// Same as [`app_data_hash_from_doc`] but takes the document as a raw
/// JSON string (no further canonicalisation; the caller is responsible
/// for matching the orderbook's canonicalisation).
#[wasm_bindgen]
pub fn app_data_hash_from_json(canonical_json: &str) -> Result<String, JsValue> {
    let doc = AppDataDoc::try_from_str(canonical_json)
        .map_err(|err| JsValue::from_str(&format!("parse failed: {err}")))?;
    let hash = doc
        .try_hash()
        .map_err(|err| JsValue::from_str(&format!("hash failed: {err}")))?;
    Ok(hash.to_string())
}

/// IPFS CIDv1 the orderbook pins for a given app-data digest.
#[wasm_bindgen]
pub fn app_data_cid_from_hash(hash_hex: &str) -> Result<String, JsValue> {
    let bytes = const_hex::decode(hash_hex.trim_start_matches("0x"))
        .map_err(|err| JsValue::from_str(&format!("invalid app-data hash hex: {err}")))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("app-data hash must be 32 bytes"))?;
    Ok(AppDataCid::from_hash(AppDataHash(array)).to_string())
}

/// 32-byte digest of `keccak256("{}")` — the empty app-data sentinel.
#[wasm_bindgen]
pub fn empty_app_data_hash() -> String {
    EMPTY_APP_DATA_HASH.to_string()
}

// ===== Networked endpoints =============================================
//
// All requests go through `transport::*` (a thin wrapper over the JS
// `fetch` global) rather than through `cowprotocol::OrderBookApi`. This
// keeps reqwest out of the wasm output: with `lto = "fat"`, any
// reqwest-using code in `cowprotocol` that is not reached from a
// wasm-bindgen export gets pruned during linking.

/// `GET /api/v1/quote`. Accepts a `QuoteRequest` JSON object.
#[wasm_bindgen]
pub async fn get_quote(chain: &str, request: JsValue) -> Result<JsValue, JsValue> {
    let request: QuoteRequest = from_js(request)?;
    let url = endpoint(parse_chain(chain)?, "api/v1/quote");
    let response: cowprotocol::OrderQuoteResponse =
        transport::post_json(&url, &request).await?;
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
    let request = QuoteRequest::sell_amount_before_fee(
        parse_address(sell_token)?,
        parse_address(buy_token)?,
        parse_address(from)?,
        parse_u256(sell_amount_before_fee)?,
    );
    let c = parse_chain(chain)?;
    let url = endpoint(c, "api/v1/quote");
    let response: cowprotocol::OrderQuoteResponse =
        transport::post_json(&url, &request).await?;
    let order_data = response.quote.to_order_data();
    let domain = DomainSeparator::new(c.id(), c.settlement());
    let uid = order_data.uid(&domain, response.from);
    let payload = serde_json::json!({
        "response": response,
        "uid": uid.to_string(),
    });
    to_js(&payload)
}

/// `POST /api/v1/orders`. Returns the assigned 56-byte UID.
#[wasm_bindgen]
pub async fn post_order(chain: &str, creation: JsValue) -> Result<String, JsValue> {
    let creation: cowprotocol::OrderCreation = from_js(creation)?;
    let url = endpoint(parse_chain(chain)?, "api/v1/orders");
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
    let mut query = Vec::with_capacity(2);
    if let Some(offset) = offset {
        query.push(format!("offset={offset}"));
    }
    if let Some(limit) = limit {
        query.push(format!("limit={limit}"));
    }
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    let url = endpoint(parse_chain(chain)?, &path);
    let orders: Vec<cowprotocol::Order> = transport::get(&url).await?;
    to_js(&orders)
}

/// `GET /api/v1/trades?owner=...`.
#[wasm_bindgen]
pub async fn trades_by_owner(chain: &str, owner: &str) -> Result<JsValue, JsValue> {
    let owner = parse_address(owner)?;
    let url = endpoint(
        parse_chain(chain)?,
        &format!("api/v1/trades?owner={owner:?}"),
    );
    let trades: Vec<cowprotocol::Trade> = transport::get(&url).await?;
    to_js(&trades)
}

/// `GET /api/v1/trades?orderUid=...`.
#[wasm_bindgen]
pub async fn trades_by_order_uid(chain: &str, uid: &str) -> Result<JsValue, JsValue> {
    let uid = parse_uid(uid)?;
    let url = endpoint(
        parse_chain(chain)?,
        &format!("api/v1/trades?orderUid={uid}"),
    );
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
/// `OrderCancellation` (see `cancel_order_signed`) and pass it here.
#[wasm_bindgen]
pub async fn cancel_order(chain: &str, cancellation: JsValue) -> Result<(), JsValue> {
    let cancellation: OrderCancellation = from_js(cancellation)?;
    let url = endpoint(
        parse_chain(chain)?,
        &format!("api/v1/orders/{}", cancellation.order_uid),
    );
    transport::delete_json(&url, &cancellation).await
}

/// Pure-compute helper: sign a single-order cancellation in-shim and
/// return the wire-shape payload `cancel_order` expects. Requires the
/// `in_shim_signing` cargo feature.
#[cfg(feature = "in_shim_signing")]
#[wasm_bindgen]
pub fn cancel_order_signed(
    uid: &str,
    chain: &str,
    private_key_hex: &str,
) -> Result<JsValue, JsValue> {
    let uid = parse_uid(uid)?;
    let c = parse_chain(chain)?;
    let domain = DomainSeparator::new(c.id(), c.settlement());
    let signer = parse_signer(private_key_hex)?;
    let cancellation =
        OrderCancellation::sign(uid, EcdsaSigningScheme::Eip712, &domain, &signer)
            .map_err(|err| JsValue::from_str(&format!("sign cancellation failed: {err}")))?;
    to_js(&cancellation)
}

// ===== Compatibility wrappers (legacy harness) =========================

/// Legacy wrapper kept stable for the pre-expansion `test-harness/`.
/// New callers should use [`order_uid`] which takes a full `OrderData`.
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
