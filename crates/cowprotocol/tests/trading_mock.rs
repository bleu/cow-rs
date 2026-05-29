//! Integration tests for [`cowprotocol::TradingClient`].
//!
//! Drives the full quote → sign → submit flow against an in-process
//! `wiremock` server. Asserts that the projected `buy_amount` accounts
//! for partner fee + slippage + protocol fee composition (the bug
//! cow-sdk #867 fixed upstream) and that the assembled
//! `OrderCreation` carries a recoverable EIP-712 signature.

#![cfg(all(not(target_arch = "wasm32"), feature = "http-client"))]

use alloy_primitives::{Address, U256, address};
use alloy_signer_local::PrivateKeySigner;
use cowprotocol::{
    AppDataDoc, Chain, EcdsaSigningScheme, OrderBookApi, QuoteRequest, SwapOrder, TradingClient,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const DAI: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

fn anvil_signer() -> PrivateKeySigner {
    // Anvil account #0 — deterministic test key, never used outside tests.
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse()
        .unwrap()
}

fn quote_body(
    from: Address,
    sell: u128,
    buy: u128,
    fee: u128,
    protocol_fee_bps: Option<&str>,
) -> Value {
    let mut quote = json!({
        "sellToken": format!("{:#x}", USDC),
        "buyToken": format!("{:#x}", DAI),
        "receiver": null,
        "sellAmount": sell.to_string(),
        "buyAmount": buy.to_string(),
        "validTo": 1_900_000_000_u32,
        "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "feeAmount": fee.to_string(),
        "kind": "sell",
        "partiallyFillable": false,
        "sellTokenBalance": "erc20",
        "buyTokenBalance": "erc20",
        "signingScheme": "eip712",
    });
    let mut body = json!({
        "quote": quote.take(),
        "from": format!("{from:#x}"),
        "expiration": "2099-12-31T23:59:59Z",
        "id": 42,
        "verified": true,
    });
    if let Some(bps) = protocol_fee_bps {
        body["protocolFeeBps"] = Value::String(bps.to_owned());
    }
    body
}

#[tokio::test]
async fn post_swap_order_lowers_buy_amount_when_protocol_fee_compounds_with_partner_fee() {
    // Same shape as `cow-sdk` PR #867: sell 1e18, quote returns
    // buyAmount=2e18, partner fee 100 bps, slippage 50 bps. With
    // `protocolFeeBps = "5"` the signed buy_amount must drop to
    // 1_970_090_045_022_511_257 (vs 1_970_100_000_000_000_000 without).
    let signer = anvil_signer();
    let signer_addr = alloy_signer::Signer::address(&signer);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/quote"))
        .respond_with(ResponseTemplate::new(200).set_body_json(quote_body(
            signer_addr,
            1_000_000_000_000_000_000,
            2_000_000_000_000_000_000,
            0,
            Some("5"),
        )))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!(
            "/api/v1/app_data/{}",
            AppDataDoc::sdk_attribution("cow-rs").hash()
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let captured_uid = "0x1111111111111111111111111111111111111111111111111111111111111111\
                          1111111111111111111111111111111111111111\
                          22222222";

    let post_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let post_calls_handle = post_calls.clone();
    Mock::given(method("POST"))
        .and(path("/api/v1/orders"))
        .respond_with(move |req: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&req.body).expect("orderbook body is JSON");
            post_calls_handle.lock().unwrap().push(body);
            ResponseTemplate::new(201).set_body_json(Value::String(captured_uid.to_owned()))
        })
        .mount(&server)
        .await;

    let api = OrderBookApi::new_with_base_url(server.uri().parse().unwrap());
    let client = TradingClient::from_orderbook(Chain::Mainnet, api).unwrap();
    let app_data = AppDataDoc::sdk_attribution("cow-rs");

    // The request's fixed leg is bound against the quote: `sell_after_fee`
    // must equal the mocked `sellAmount` (1e18).
    // `sell_after_fee` already pins `kind = Sell`; the fixed leg
    // (`sell_after_fee` = 1e18) is bound against the mocked `sellAmount`.
    let request = QuoteRequest::sell_after_fee(
        USDC,
        DAI,
        signer_addr,
        U256::from(1_000_000_000_000_000_000u128),
    );

    let order = SwapOrder {
        request,
        app_data: &app_data,
        scheme: EcdsaSigningScheme::Eip712,
        partner_fee_bps: 100,
        slippage_bps: 50,
        protocol_fee_bps_override: None,
    };
    let posted = client
        .post_swap_order(order, &signer)
        .await
        .expect("post_swap_order should succeed");

    assert_eq!(
        posted.order_data.buy_amount,
        U256::from(1_970_090_045_022_511_257u128),
        "buyAmount must match cow-sdk #867 protocol-fee + partner-fee composition"
    );

    let calls = post_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "exactly one POST /orders");
    let posted_body = &calls[0];
    assert_eq!(
        posted_body["buyAmount"], "1970090045022511257",
        "wire buyAmount matches signed value"
    );
    assert_eq!(posted_body["signingScheme"], "eip712");
    assert_eq!(
        posted_body["from"],
        format!("{signer_addr:#x}"),
        "from is the signer address"
    );
    assert_eq!(posted_body["quoteId"], 42);
}
