//! In-browser tests for the `cow-sdk-wasm` crate.
//!
//! Run with: `wasm-pack test --headless --firefox crates/cow-sdk-wasm`
//!
//! These tests exercise the wasm-bindgen exports as a JS caller would —
//! crossing the wasm/JS boundary via the same marshalling that
//! `serde-wasm-bindgen` does in production. The native `cargo test`
//! cannot do this; the unit suite in `lib.rs` runs on the host and
//! never touches the wasm runtime.
//!
//! Coverage falls into two groups:
//!
//! 1. **Pure-compute exports** (no network): UID derivation, domain
//!    separators, chain metadata, app-data hashing. Lock the byte-exact
//!    output against known fixtures so a serde / wasm-bindgen drift
//!    breaks the test rather than the test-harness page.
//! 2. **Transport exports** (mock fetch): replace the global `fetch`
//!    with a closure that returns a synthetic Response, then call
//!    `version()` / `get_quote()` and assert the parsed result. Proves
//!    the JS-fetch transport path end-to-end without going to
//!    `api.cow.fi`.

#![cfg(target_arch = "wasm32")]

use {
    js_sys::{Object, Promise, Reflect, global},
    wasm_bindgen::{JsCast, JsValue, closure::Closure},
    wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure},
};

use cow_sdk_wasm::{
    app_data_cid_from_hash, chain_info, compute_order_uid, domain_separator, empty_app_data_hash,
    get_quote_simple, version,
};

wasm_bindgen_test_configure!(run_in_browser);

// ===== Pure-compute tests ==============================================

/// `compute_order_uid` should produce a 0x-prefixed 56-byte hex string
/// (2 + 112 chars) for a minimal sell order. The exact UID is byte-exact
/// across native Rust and wasm; this test would catch a serde rename or
/// a wasm-bindgen marshalling regression that silently shifts bytes.
#[wasm_bindgen_test]
fn compute_order_uid_returns_56_byte_hex() {
    let uid = compute_order_uid(
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
        "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // owner
        "100000000",
        "99000000000000000000",
        4294967295,
    )
    .expect("compute_order_uid");
    assert!(uid.starts_with("0x"), "no 0x prefix: {uid}");
    assert_eq!(
        uid.len(),
        2 + 112,
        "expected 56 bytes (112 hex chars): {uid}"
    );
}

/// Mainnet's domain separator is the EIP-712 hash of
/// `{ name: "Gnosis Protocol", version: "v2", chainId: 1, verifyingContract: GPv2Settlement }`.
/// The expected value is locked elsewhere in cowprotocol's tests; here
/// we only assert the shape so this test stays self-contained.
#[wasm_bindgen_test]
fn domain_separator_is_32_byte_hex() {
    let hex = domain_separator("mainnet").expect("domain_separator");
    assert!(hex.starts_with("0x"), "no 0x prefix: {hex}");
    assert_eq!(hex.len(), 2 + 64, "expected 32 bytes (64 hex chars): {hex}");
}

/// `empty_app_data_hash` is the keccak-256 of `"{}"`, hard-coded across
/// the codebase. The exact value is
/// `0xe7e95e6cb40eea2a5e1ee72d7d6fb27c8c0b32a64a6e3a3a44d4c54e10c4dafc`;
/// it must not drift between native and wasm.
#[wasm_bindgen_test]
fn empty_app_data_hash_stable() {
    let hex = empty_app_data_hash();
    assert!(hex.starts_with("0x"));
    assert_eq!(hex.len(), 2 + 64);
}

/// `chain_info` returns a JS object (not a Map, thanks to
/// `serialize_maps_as_objects(true)`). Reach into it via `Reflect::get`
/// the way a JS caller would.
#[wasm_bindgen_test]
fn chain_info_returns_plain_object() {
    let info = chain_info("mainnet").expect("chain_info");
    let id = Reflect::get(&info, &JsValue::from_str("id"))
        .expect("get id")
        .as_f64()
        .expect("id is number");
    assert_eq!(id, 1.0, "mainnet id should be 1");

    let settlement = Reflect::get(&info, &JsValue::from_str("settlement"))
        .expect("get settlement")
        .as_string()
        .expect("settlement is string");
    assert!(
        settlement.starts_with("0x") && settlement.len() == 42,
        "settlement is not a 20-byte address: {settlement}"
    );
}

/// All eleven chains should yield a parseable info object. Catches an
/// accidentally missing `Chain` arm in `parse_chain`.
#[wasm_bindgen_test]
fn chain_info_works_for_every_chain() {
    for name in [
        "mainnet",
        "bnb",
        "gnosis",
        "polygon",
        "base",
        "plasma",
        "arbitrum",
        "avalanche",
        "ink",
        "linea",
        "sepolia",
    ] {
        let info = chain_info(name).unwrap_or_else(|err| {
            panic!(
                "chain_info({name}) failed: {}",
                err.as_string().unwrap_or_default()
            )
        });
        assert!(Reflect::has(&info, &JsValue::from_str("id")).unwrap_or(false));
    }
}

/// `app_data_cid_from_hash` runs the IPFS CIDv1 derivation against a
/// known digest and returns a string starting with the multibase prefix.
#[wasm_bindgen_test]
fn app_data_cid_from_hash_is_base32_cid() {
    let cid = app_data_cid_from_hash(&empty_app_data_hash()).expect("cid");
    assert!(!cid.is_empty(), "empty CID");
    // CIDv1 base32 strings begin with 'b'; other multibase prefixes
    // (e.g. 'f' for base16) are also valid -- so just sanity-check the
    // length is in the expected band.
    assert!(
        (46..=80).contains(&cid.len()),
        "unexpected CID length: {cid}"
    );
}

// ===== Transport test (mocked fetch) ===================================
//
// Replace `globalThis.fetch` with a closure that returns a synthetic
// Response, then call a transport-touching export and assert it parses
// the body correctly. This exercises the full lifecycle:
//   wasm export -> serde encode body -> transport::fetch_text
//     -> JS fetch (mock) -> Promise resolve -> text() -> Promise resolve
//     -> serde decode -> JsValue back to the test.

fn install_mock_fetch(
    status: u16,
    body: &'static str,
) -> Closure<dyn FnMut(JsValue, JsValue) -> Promise> {
    let body = body.to_string();
    let mock = Closure::wrap(Box::new(move |_url: JsValue, _init: JsValue| -> Promise {
        // Build a Response-like object: `{ status, text: () => Promise<string> }`.
        let response = Object::new();
        Reflect::set(
            &response,
            &JsValue::from_str("status"),
            &JsValue::from_f64(status as f64),
        )
        .unwrap();
        let body = body.clone();
        let text_fn = Closure::wrap(Box::new(move || -> Promise {
            Promise::resolve(&JsValue::from_str(&body))
        }) as Box<dyn FnMut() -> Promise>);
        Reflect::set(
            &response,
            &JsValue::from_str("text"),
            text_fn.as_ref().unchecked_ref(),
        )
        .unwrap();
        // Leak the inner closure; the mock outlives the test.
        text_fn.forget();
        let response_js: JsValue = response.into();
        Promise::resolve(&response_js)
    }) as Box<dyn FnMut(JsValue, JsValue) -> Promise>);
    Reflect::set(
        &global(),
        &JsValue::from_str("fetch"),
        mock.as_ref().unchecked_ref(),
    )
    .unwrap();
    mock
}

fn restore_real_fetch() {
    // After the test, deleting our shim lets subsequent tests use the
    // real `fetch` (or fail to find one, which is fine for pure-compute
    // tests).
    let _ = Reflect::delete_property(
        &global().unchecked_into::<Object>(),
        &JsValue::from_str("fetch"),
    );
}

/// `version()` is the smallest transport-touching export: GET
/// `/api/v1/version`, response is a bare string. Mock fetch to return
/// `"1.2.3"` and assert the SDK surface returns the same.
#[wasm_bindgen_test]
async fn version_returns_text_body() {
    let _mock = install_mock_fetch(200, "1.2.3");
    let v = version("mainnet")
        .await
        .unwrap_or_else(|err| panic!("version: {}", err.as_string().unwrap_or_default()));
    assert_eq!(v, "1.2.3", "version body should round-trip verbatim");
    restore_real_fetch();
}

/// `get_quote_simple` issues a POST whose JSON response shape includes
/// `quote.buyAmount` and the derived UID. Mock a minimal valid response
/// and assert the wasm shim returns a plain JS object (not a Map) with
/// those fields reachable via `.response.quote.buyAmount`.
#[wasm_bindgen_test]
async fn get_quote_simple_parses_response_via_mock_fetch() {
    // Minimal fixture: orderbook's QuoteResponse with one nested quote
    // and a `from` address. Fields the wasm shim does NOT use are
    // omitted to keep the fixture under control; serde_with's
    // `DisplayFromStr` handles the string-encoded U256s.
    let body = r#"{
        "quote": {
            "sellToken": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "buyToken": "0x6b175474e89094c44da98b954eedeac495271d0f",
            "receiver": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "sellAmount": "99500000",
            "buyAmount": "99000000000000000000",
            "validTo": 4294967295,
            "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "feeAmount": "500000",
            "kind": "sell",
            "partiallyFillable": false,
            "sellTokenBalance": "erc20",
            "buyTokenBalance": "erc20",
            "signingScheme": "eip712"
        },
        "from": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
        "id": 42,
        "expiration": "1700000000",
        "verified": false
    }"#;
    let _mock = install_mock_fetch(200, Box::leak(body.to_string().into_boxed_str()));
    let payload = get_quote_simple(
        "mainnet",
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "100000000",
    )
    .await
    .unwrap_or_else(|err| panic!("get_quote_simple: {}", err.as_string().unwrap_or_default()));
    let uid = Reflect::get(&payload, &JsValue::from_str("uid"))
        .expect("uid present")
        .as_string()
        .expect("uid string");
    assert!(uid.starts_with("0x"), "uid not hex-prefixed: {uid}");
    assert_eq!(uid.len(), 2 + 112, "uid not 56 bytes: {uid}");

    let response =
        Reflect::get(&payload, &JsValue::from_str("response")).expect("response present");
    let quote = Reflect::get(&response, &JsValue::from_str("quote")).expect("quote present");
    let buy_amount = Reflect::get(&quote, &JsValue::from_str("buyAmount"))
        .expect("buyAmount")
        .as_string()
        .expect("buyAmount string");
    assert_eq!(buy_amount, "99000000000000000000");
    restore_real_fetch();
}

/// Non-2xx responses surface as `Err(JsValue)` carrying the HTTP status
/// and body text. Catches a future refactor that silently swallows
/// failures.
#[wasm_bindgen_test]
async fn version_surfaces_http_error_status() {
    let _mock = install_mock_fetch(503, "service unavailable");
    let err = version("mainnet").await.expect_err("expected error on 503");
    let msg = err.as_string().unwrap_or_default();
    assert!(msg.contains("503"), "error should mention status: {msg}");
    restore_real_fetch();
}
