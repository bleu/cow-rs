//! Signing and order-creation bindings: EIP-712 typed-data assembly,
//! struct hashing, in-shim ECDSA signing (test- and script-only), and
//! the `OrderCreation` assemblers fed back from external wallets.

use {
    crate::{from_js, js_err, parse_address, parse_b256, parse_chain, to_js},
    cowprotocol::{EcdsaSigningScheme, OrderData, Signature, SigningScheme, ecdsa_from_components},
    serde::Deserialize,
    wasm_bindgen::prelude::*,
};

#[cfg(feature = "in_shim_signing")]
use {
    crate::parse_uid, alloy_primitives::B256, alloy_signer_local::PrivateKeySigner,
    cowprotocol::SignedOrderCancellation,
};

#[cfg(feature = "in_shim_signing")]
fn parse_signer(private_key_hex: &str) -> Result<PrivateKeySigner, JsValue> {
    private_key_hex
        .parse::<PrivateKeySigner>()
        .map_err(js_err("invalid private key"))
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
    // The whole `{ domain, primaryType, types, message }` envelope
    // (including the receiver normalisation, the deliberate
    // `EIP712Domain` omission, and the centralised domain name /
    // version) is built by core, byte-identical to the prior hand table.
    to_js(&cowprotocol::order_typed_data(
        &order,
        c.id(),
        c.settlement(),
    ))
}

/// `keccak256(order)` struct hash (the input to EIP-712's `_hashTypedData`).
/// Accepts the same JSON shape that `OrderData` serialises to.
#[wasm_bindgen]
pub fn order_struct_hash(order_data: JsValue) -> Result<String, JsValue> {
    let order: OrderData = from_js(order_data)?;
    Ok(order.hash_struct().to_string())
}

/// 56-byte `OrderUid` for the order against the given chain's domain.
/// Returns `0x` + 112 hex chars.
#[wasm_bindgen]
pub fn order_uid(order_data: JsValue, chain: &str, owner: &str) -> Result<String, JsValue> {
    let order: OrderData = from_js(order_data)?;
    let c = parse_chain(chain)?;
    let domain = c.settlement_domain();
    Ok(order.uid(&domain, parse_address(owner)?).to_string())
}

/// EIP-712 wrapped hash `keccak256(0x1901 || domain || struct_hash)`.
/// JS interop helper: callers that already hold the 32-byte domain
/// separator and struct hash get the typed-data hash without having to
/// reassemble an `alloy_sol_types::Eip712Domain`.
#[wasm_bindgen]
pub fn eip712_message_hash(domain_hex: &str, struct_hash_hex: &str) -> Result<String, JsValue> {
    let separator = parse_b256(domain_hex)?;
    let struct_hash = parse_b256(struct_hash_hex)?;
    Ok(cowprotocol::eip712_message_hash(separator, struct_hash).to_string())
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
    let domain = c.settlement_domain();
    let signer = parse_signer(private_key_hex)?;
    let ecdsa = order
        .sign_ecdsa(scheme, &domain, &signer)
        .map_err(js_err("sign failed"))?;
    let bytes = ecdsa.as_bytes();
    let r = B256::from_slice(&bytes[..32]);
    let s = B256::from_slice(&bytes[32..64]);
    // `EcdsaSigningScheme` serialises to its wire names ("eip712" /
    // "ethsign") directly.
    let payload = serde_json::json!({
        "signingScheme": scheme,
        "r": r.to_string(),
        "s": s.to_string(),
        "v": bytes[64],
        "owner": signer.address().to_string(),
    });
    to_js(&payload)
}

/// Build a `POST /orders` payload from a signed order. Accepts a
/// signature object produced by `sign_eip712` / `sign_ethsign`
/// (`in_shim_signing` feature), or an externally signed
/// `{ signingScheme, r, s, v }` bag with matching shape.
///
/// `chain` selects the EIP-712 domain (chain id + settlement
/// `verifyingContract`) used to recover the signer; the assembled
/// `OrderCreation` is rejected locally with a `verify_owner` error if
/// the recovered signer does not match `owner`. This catches the
/// typo-and-wallet-switch family of bugs that would otherwise only
/// surface as a 4xx from the orderbook.
///
/// The `{ r, s, v }` bag is funnelled through `ecdsa_from_components`
/// so `v` is normalised to `27` / `28` even when the originating
/// wallet returns the raw `0` / `1` form.
///
/// `quote_id` is forwarded as the orderbook's `i64` quote id; a JS
/// BigInt that exceeds `i64::MAX` is rejected rather than silently
/// wrapping to a negative value.
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
        // Deserialised straight into the enum: serde owns the
        // "eip712" / "ethsign" wire names, so the shim no longer
        // duplicates them. The scheme strings are case-sensitive.
        signing_scheme: EcdsaSigningScheme,
        r: String,
        s: String,
        v: u8,
    }
    let sig: SigInput = from_js(signature)?;
    let scheme = sig.signing_scheme;
    let r = parse_b256(&sig.r)?;
    let s = parse_b256(&sig.s)?;
    let ecdsa = ecdsa_from_components(r, s, sig.v).map_err(js_err("invalid signature"))?;
    let signature = Signature::from_ecdsa(ecdsa, scheme);
    assemble_creation(order, signature, owner, chain, app_data_json, quote_id)
}

/// Convert a JS-supplied `quote_id` (`u64`) into the orderbook's `i64`
/// quote id, rejecting a value above `i64::MAX` rather than letting it
/// wrap to a negative id. `None` stays `None`.
fn to_quote_id(quote_id: Option<u64>) -> Result<Option<i64>, JsValue> {
    quote_id
        .map(|id| i64::try_from(id).map_err(|_| JsValue::from_str("quote_id exceeds i64::MAX")))
        .transpose()
}

/// Shared tail of [`build_order_creation`] and
/// [`build_order_creation_eip1271`]: thread the parsed `signature`,
/// `owner`, `chain`, app-data JSON and `quote_id` into core's
/// `OrderCreation::from_signed_order_data`, then run the local
/// `verify_owner` guard against the chain's settlement domain before
/// handing the body back to JS. The two public exports differ only in
/// how they build `signature`.
fn assemble_creation(
    order: OrderData,
    signature: Signature,
    owner: &str,
    chain: &str,
    app_data_json: &str,
    quote_id: Option<u64>,
) -> Result<JsValue, JsValue> {
    let owner = parse_address(owner)?;
    let domain = parse_chain(chain)?.settlement_domain();
    let quote_id = to_quote_id(quote_id)?;
    let creation = cowprotocol::OrderCreation::from_signed_order_data(
        &order,
        signature,
        owner,
        app_data_json.to_owned(),
        quote_id,
    )
    .map_err(js_err("build creation failed"))?;
    creation
        .verify_owner(&domain)
        .map_err(js_err("verify_owner"))?;
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
///
/// `quote_id` is forwarded as the orderbook's `i64` quote id; a JS
/// BigInt that exceeds `i64::MAX` is rejected rather than silently
/// wrapping to a negative value.
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
        .map_err(js_err("invalid signature hex"))?;
    let signature = Signature::from_bytes(SigningScheme::Eip1271, &bytes)
        .map_err(js_err("invalid eip1271 signature"))?;
    assemble_creation(order, signature, owner, chain, app_data_json, quote_id)
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
    let domain = c.settlement_domain();
    let signer = parse_signer(private_key_hex)?;
    let cancellation =
        SignedOrderCancellation::sign(uid, EcdsaSigningScheme::Eip712, &domain, &signer)
            .map_err(js_err("sign cancellation failed"))?;
    to_js(&cancellation)
}
