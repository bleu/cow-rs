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
//!    private-key hex string to [`sign_eip712`] / [`sign_ethsign`].
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
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]

mod allocator;
mod transport;

use {
    alloy_primitives::{Address, B256, U256},
    cowprotocol::{
        AppDataDoc, AppDataHash, Chain, EMPTY_APP_DATA_HASH, EcdsaSignature, EcdsaSigningScheme,
        OrderCancellation, OrderData, OrderUid, QuoteRequest, Signature, SigningScheme,
        app_data_cid, settlement_domain,
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
    let domain = settlement_domain(c.id(), c.settlement());
    Ok(domain.separator().to_string())
}

/// Canonical EIP-712 typed-data payload for an order, ready to feed
/// into viem's `signTypedData` or ethers' `signer.signTypedData`. Lets
/// JS callers sign with their own wallet without redefining the
/// `Order` type or the `Gnosis Protocol` domain separator.
///
/// Returns `{ domain, primaryType, types, message }`. The `message`
/// normalises `receiver: null` to `address(0)` so the hash the wallet
/// signs matches what `OrderData::hash_struct` computes server-side.
///
/// # Raw `eth_signTypedData_v4` callers
///
/// `types` deliberately omits the `EIP712Domain` entry: ethers v6 and
/// viem build the domain typedef from the `domain` object and throw on
/// a duplicate. Callers using the raw EIP-1193 RPC (`window.ethereum`,
/// WalletConnect, Safe SDK) must inject `EIP712Domain` before
/// stringifying the payload for the wallet, otherwise the wallet
/// hashes the domain with the wrong typedef and the signature won't
/// verify. Example:
///
/// ```js
/// const payload = eip712_payload(order, 'mainnet');
/// const v4 = {
///   ...payload,
///   types: {
///     EIP712Domain: [
///       { name: 'name',              type: 'string'  },
///       { name: 'version',           type: 'string'  },
///       { name: 'chainId',           type: 'uint256' },
///       { name: 'verifyingContract', type: 'address' },
///     ],
///     ...payload.types,
///   },
/// };
/// await window.ethereum.request({
///   method: 'eth_signTypedData_v4',
///   params: [account, JSON.stringify(v4)],
/// });
/// ```
#[wasm_bindgen]
pub fn eip712_payload(order_data: JsValue, chain: &str) -> Result<JsValue, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let c = parse_chain(chain)?;
    let mut message = serde_json::to_value(order)
        .map_err(|err| JsValue::from_str(&format!("serialise order failed: {err}")))?;
    // null receiver gets hashed as address(0); make that explicit.
    if message
        .get("receiver")
        .is_none_or(serde_json::Value::is_null)
    {
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
        // `EIP712Domain` is deliberately not in `types`: ethers v6 and
        // viem build the domain typedef from the `domain` object and
        // throw on a duplicate entry. Raw `eth_signTypedData_v4`
        // callers (window.ethereum.request, WalletConnect, Safe SDK)
        // must inject EIP712Domain themselves before stringifying for
        // the wallet RPC. See `test-harness/index.html`'s shim button
        // for an example.
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
    let domain = settlement_domain(c.id(), c.settlement());
    Ok(order.uid(&domain, parse_address(owner)?).to_string())
}

/// EIP-712 wrapped hash `keccak256(0x1901 || domain || struct_hash)`.
/// JS interop helper: callers that already hold the 32-byte domain
/// separator and struct hash get the typed-data hash without having to
/// reassemble an [`alloy_sol_types::Eip712Domain`].
#[wasm_bindgen]
pub fn eip712_message_hash(domain_hex: &str, struct_hash_hex: &str) -> Result<String, JsValue> {
    let separator = parse_b256(domain_hex)?;
    let struct_hash = parse_b256(struct_hash_hex)?;
    let mut buf = [0u8; 66];
    buf[..2].copy_from_slice(&[0x19, 0x01]);
    buf[2..34].copy_from_slice(separator.as_slice());
    buf[34..].copy_from_slice(struct_hash.as_slice());
    Ok(alloy_primitives::keccak256(buf).to_string())
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
    let domain = settlement_domain(c.id(), c.settlement());
    let signer = parse_signer(private_key_hex)?;
    let ecdsa = order
        .sign_ecdsa(scheme, &domain, &signer)
        .map_err(|err| JsValue::from_str(&format!("sign failed: {err}")))?;
    let payload = serde_json::json!({
        "signingScheme": scheme_to_str(scheme),
        "r": ecdsa.r.to_string(),
        "s": ecdsa.s.to_string(),
        "v": ecdsa.v,
        "owner": signer.address().to_string(),
    });
    to_js(&payload)
}

#[cfg(feature = "in_shim_signing")]
const fn scheme_to_str(scheme: EcdsaSigningScheme) -> &'static str {
    match scheme {
        EcdsaSigningScheme::Eip712 => "eip712",
        EcdsaSigningScheme::EthSign => "ethsign",
    }
}

/// Build a `POST /orders` payload from a signed order. Accepts a
/// signature object produced by [`sign_eip712`] / [`sign_ethsign`], or
/// an externally signed `{ signingScheme, r, s, v }` bag with matching
/// shape.
///
/// `chain` selects the EIP-712 domain (chain id + settlement
/// `verifyingContract`) used to recover the signer; the assembled
/// `OrderCreation` is rejected locally with a `verify_owner` error if
/// the recovered signer does not match `owner`. This catches the
/// typo-and-wallet-switch family of bugs that would otherwise only
/// surface as a 4xx from the orderbook.
///
/// The `{ r, s, v }` bag is funnelled through
/// [`EcdsaSignature::from_bytes`] so `v` is normalised to `27` / `28`
/// even when the originating wallet returns the raw `0` / `1` form.
#[wasm_bindgen]
pub fn build_order_creation(
    order_data: JsValue,
    signature: JsValue,
    owner: &str,
    chain: &str,
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
    let mut raw = [0u8; 65];
    raw[..32].copy_from_slice(r.as_slice());
    raw[32..64].copy_from_slice(s.as_slice());
    raw[64] = sig.v;
    let ecdsa = EcdsaSignature::from_bytes(&raw)
        .map_err(|err| JsValue::from_str(&format!("invalid signature: {err}")))?;
    let signature = ecdsa.into_signature(scheme);
    let owner = parse_address(owner)?;
    let c = parse_chain(chain)?;
    let domain = settlement_domain(c.id(), c.settlement());
    let creation = cowprotocol::OrderCreation::from_signed_order_data(
        order,
        signature,
        owner,
        app_data_json.to_owned(),
        quote_id.map(|id| id as i64),
    )
    .map_err(|err| JsValue::from_str(&format!("build creation failed: {err}")))?;
    creation
        .verify_owner(&domain)
        .map_err(|err| JsValue::from_str(&format!("verify_owner: {err}")))?;
    to_js(&creation)
}

/// Apply an externally produced EIP-1271 signature (Safe / contract
/// wallet). `owner` must be the smart-wallet contract address that
/// `isValidSignature` will be called on. `signature_hex` is the
/// contract's expected calldata (often the wrapper bytes Safe's
/// `signMessage` returns).
///
/// The signature is funnelled through
/// [`Signature::from_bytes`] so the
/// [`cowprotocol::signature::EIP1271_MAX_LEN`] (32 KiB) cap applies here as well
/// as on the deserialise path. `chain` is accepted for parity with the
/// ECDSA constructor; for EIP-1271 it is informational (owner
/// verification is on-chain via `isValidSignature`, not via signer
/// recovery) but it lets us reject a malformed bag of arguments
/// uniformly.
#[wasm_bindgen]
pub fn build_order_creation_eip1271(
    order_data: JsValue,
    signature_hex: &str,
    owner: &str,
    chain: &str,
    app_data_json: &str,
    quote_id: Option<u64>,
) -> Result<JsValue, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let bytes: alloy_primitives::Bytes = signature_hex
        .parse()
        .map_err(|err| JsValue::from_str(&format!("invalid signature hex: {err}")))?;
    let signature = Signature::from_bytes(SigningScheme::Eip1271, &bytes)
        .map_err(|err| JsValue::from_str(&format!("invalid eip1271 signature: {err}")))?;
    let owner = parse_address(owner)?;
    let c = parse_chain(chain)?;
    let domain = settlement_domain(c.id(), c.settlement());
    let creation = cowprotocol::OrderCreation::from_signed_order_data(
        order,
        signature,
        owner,
        app_data_json.to_owned(),
        quote_id.map(|id| id as i64),
    )
    .map_err(|err| JsValue::from_str(&format!("build creation failed: {err}")))?;
    creation
        .verify_owner(&domain)
        .map_err(|err| JsValue::from_str(&format!("verify_owner: {err}")))?;
    to_js(&creation)
}

/// Parse a JSON app-data document and return its keccak256 digest.
/// The caller is responsible for canonicalising the JSON before
/// passing it in (the orderbook indexes documents byte-exactly; any
/// reformatting after this call changes the hash).
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
    let hash: AppDataHash = parse_b256(hash_hex)?;
    Ok(app_data_cid(hash).to_string())
}

/// 32-byte digest of `keccak256("{}")` — the empty app-data sentinel.
#[wasm_bindgen]
pub fn empty_app_data_hash() -> String {
    EMPTY_APP_DATA_HASH.to_string()
}

/// Canonical SDK-attribution app-data document JSON, with
/// `appCode: "cow-rs-wasm"` and the wasm crate's version pinned in
/// `metadata.quote.version`. Pass this to [`build_order_creation`] as
/// the `app_data_json` argument so the orderbook indexer can
/// attribute the order back to this SDK; pair with
/// [`sdk_app_data_hash`] for the signed `appData` field.
#[wasm_bindgen]
pub fn sdk_app_data_json() -> String {
    cowprotocol::AppDataDoc::sdk_attribution(cowprotocol::COW_RS_WASM_APP_CODE).canonical_json()
}

/// 32-byte keccak256 digest of [`sdk_app_data_json`], 0x-prefixed.
/// Embed in [`OrderData::app_data`] before signing so the wire shape
/// matches what the orderbook will hash server-side.
#[wasm_bindgen]
pub fn sdk_app_data_hash() -> String {
    cowprotocol::AppDataDoc::sdk_attribution(cowprotocol::COW_RS_WASM_APP_CODE)
        .hash()
        .to_string()
}

/// Project an `OrderQuoteResponse` into the 12-field `OrderData` the
/// owner will sign, after cross-checking the response against the
/// originating `QuoteRequest`.
///
/// The single chokepoint for assembling signable bytes from a quote
/// in JS-land. Mirrors the native
/// [`cowprotocol::OrderQuoteResponse::to_signed_order_data`]: rejects
/// any response whose `sellToken`, `buyToken`, normalised `receiver`,
/// `from`, `kind`, or pinned `appData` disagrees with the request,
/// plus `validTo` / `partiallyFillable` / `sellTokenBalance` /
/// `buyTokenBalance` / `signingScheme` when the caller pinned them.
/// Use this instead of hand-copying `response.quote.*` into an
/// `orderData` object before passing it to `eip712_payload` and
/// `build_order_creation`.
///
/// `app_data_hash_hex` is the 32-byte digest of the app-data document
/// the caller will submit (commonly [`sdk_app_data_hash`] for SDK
/// attribution, or [`empty_app_data_hash`] for the empty document).
#[wasm_bindgen]
pub fn to_signed_order_data(
    request: JsValue,
    response: JsValue,
    app_data_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let request: QuoteRequest = from_js(request)?;
    let response: cowprotocol::OrderQuoteResponse = from_js(response)?;
    let app_data: AppDataHash = parse_b256(app_data_hash_hex)?;
    let order_data = response
        .to_signed_order_data(&request, app_data)
        .map_err(|err| JsValue::from_str(&format!("to_signed_order_data failed: {err}")))?;
    to_js(&order_data)
}

// ===== Networked endpoints =============================================
//
// All requests go through `transport::*` (a thin wrapper over the JS
// `fetch` global) rather than through `cowprotocol::OrderBookApi`. This
// keeps reqwest out of the wasm output: with `lto = "fat"`, any
// reqwest-using code in `cowprotocol` that is not reached from a
// wasm-bindgen export gets pruned during linking.

/// `POST /api/v1/quote`. Accepts a `QuoteRequest` JSON object.
///
/// Cross-checks the response against the request via
/// [`cowprotocol::OrderQuoteResponse::to_signed_order_data`] before
/// returning, so a hostile orderbook cannot hand JS callers a swapped
/// `sellToken` / `buyToken` / `receiver` / `from` / `kind` they would
/// then pass into [`to_signed_order_data`] / [`build_order_creation`].
/// The empty-document app-data hash is used for the bind check; the
/// caller's eventual signing-time digest is checked again when they
/// call [`to_signed_order_data`].
#[wasm_bindgen]
pub async fn get_quote(chain: &str, request: JsValue) -> Result<JsValue, JsValue> {
    let request: QuoteRequest = from_js(request)?;
    let url = endpoint(parse_chain(chain)?, "api/v1/quote");
    let response: cowprotocol::OrderQuoteResponse = transport::post_json(&url, &request).await?;
    response
        .to_signed_order_data(&request, EMPTY_APP_DATA_HASH)
        .map_err(|err| JsValue::from_str(&format!("quote response binding failed: {err}")))?;
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
    let response: cowprotocol::OrderQuoteResponse = transport::post_json(&url, &request).await?;
    let order_data = response
        .to_signed_order_data(&request, cowprotocol::EMPTY_APP_DATA_HASH)
        .map_err(|err| JsValue::from_str(&format!("to_signed_order_data failed: {err}")))?;
    let domain = settlement_domain(c.id(), c.settlement());
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
    let domain = settlement_domain(c.id(), c.settlement());
    let signer = parse_signer(private_key_hex)?;
    let cancellation =
        OrderCancellation::sign(uid, EcdsaSigningScheme::Eip712, &domain, &signer)
            .map_err(|err| JsValue::from_str(&format!("sign cancellation failed: {err}")))?;
    to_js(&cancellation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet's base URL ends with `/orderbook/`. The joined path should
    /// land at `/orderbook/api/v1/quote` with exactly one slash between
    /// the base and the path, regardless of trailing-slash quirks.
    #[test]
    fn endpoint_joins_mainnet_quote_without_double_slash() {
        let url = endpoint(Chain::Mainnet, "api/v1/quote");
        assert!(
            url.ends_with("/api/v1/quote"),
            "expected /api/v1/quote suffix, got: {url}"
        );
        assert!(!url.contains("//api/"), "double-slash in: {url}");
        assert!(url.starts_with("https://api.cow.fi/"), "wrong host: {url}");
    }

    /// All eleven chains should produce a parseable absolute URL when
    /// asked for the same path. Catches an accidental missing
    /// `orderbook_base_url()` impl on a future chain.
    #[test]
    fn endpoint_works_for_every_chain() {
        for chain in [
            Chain::Mainnet,
            Chain::Bnb,
            Chain::Gnosis,
            Chain::Polygon,
            Chain::Base,
            Chain::Plasma,
            Chain::ArbitrumOne,
            Chain::Avalanche,
            Chain::Ink,
            Chain::Linea,
            Chain::Sepolia,
        ] {
            let url = endpoint(chain, "api/v1/quote");
            assert!(url.ends_with("/api/v1/quote"), "{chain:?} -> {url}");
            assert!(
                url.starts_with("https://"),
                "{chain:?} produced a non-https URL: {url}"
            );
            // Reject double-slashes in the joined path. Allow exactly one
            // pair (the `https://` after the scheme).
            let after_scheme = url.trim_start_matches("https://");
            assert!(
                !after_scheme.contains("//"),
                "{chain:?} double-slash: {url}"
            );
        }
    }

    /// `cancel_order` builds paths of the form `api/v1/orders/{uid}`; the
    /// uid is hex-prefixed and must not be percent-encoded by us (the
    /// orderbook decodes it raw).
    #[test]
    fn endpoint_preserves_hex_path_segments() {
        let uid = "0x0000000000000000000000000000000000000000000000000000000000000000\
                   0000000000000000000000000000000000000000\
                   00000000";
        let path = format!("api/v1/orders/{uid}");
        let url = endpoint(Chain::Mainnet, &path);
        assert!(url.contains(uid), "uid stripped from: {url}");
    }
}
