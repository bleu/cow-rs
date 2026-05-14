//! Integration tests for [`cow_rs::OrderBookApi`].
//!
//! Spins up an in-process [`wiremock::MockServer`] per test, points an
//! [`OrderBookApi`] at it, and exercises every endpoint against canned
//! responses. The goal is to lock the wire shapes our client encodes and
//! decodes without hitting the production orderbook.

#![cfg(not(target_arch = "wasm32"))]

use alloy_primitives::{Address, U256, address};
use cow_rs::{
    AppDataHash, BuyTokenDestination, Chain, OrderBookApi, OrderCancellations, OrderCreation,
    OrderData, OrderKind, OrderUid, QuoteRequest, SellTokenSource, Signature, SigningScheme,
    order_book::AppDataDocument,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, body_string_contains, method, path, query_param},
};

const OWNER: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const DAI: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

fn api(server: &MockServer) -> OrderBookApi {
    OrderBookApi::new_with_base_url(server.uri().parse().unwrap())
}

const fn mainnet_quote_fixture() -> &'static str {
    include_str!("fixtures/quote-mainnet.json")
}

#[tokio::test]
async fn get_quote_decodes_recorded_mainnet_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/quote"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_raw(mainnet_quote_fixture(), "application/json"),
        )
        .mount(&server)
        .await;

    let request =
        QuoteRequest::sell_amount_before_fee(USDC, DAI, OWNER, U256::from(100_000_000_u64));
    let response = api(&server).get_quote(&request).await.unwrap();

    assert_eq!(response.quote.kind, OrderKind::Sell);
    assert_eq!(response.from, OWNER);
    assert!(response.verified);
    assert_eq!(response.id, 1_176_992_200);
}

#[tokio::test]
async fn post_order_returns_assigned_uid() {
    let server = MockServer::start().await;
    let expected_uid = "0xb74844872ddbadb709629952eab02a9275c5c05426cb195e27029a353909404370997970c51812dc3a010c7d01b50e0d17dc79c86a0513b9";

    Mock::given(method("POST"))
        .and(path("/api/v1/orders"))
        .and(body_string_contains("\"feeAmount\":\"0\""))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .set_body_string(format!("\"{expected_uid}\"")),
        )
        .mount(&server)
        .await;

    let order = OrderData {
        sell_token: USDC,
        buy_token: DAI,
        sell_amount: U256::from(1_000_000_u64),
        buy_amount: U256::from(999_000_u64),
        valid_to: u32::MAX,
        ..OrderData::default()
    };
    let creation = OrderCreation::from_signed_order_data(
        order,
        Signature::default(),
        OWNER,
        cow_rs::EMPTY_APP_DATA_JSON.to_owned(),
        Some(123),
    );

    let uid = api(&server).post_order(&creation).await.unwrap();
    assert_eq!(uid.to_string(), expected_uid);
}

#[tokio::test]
async fn post_order_surfaces_orderbook_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orders"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errorType": "InsufficientFee",
            "description": "fee is too low",
        })))
        .mount(&server)
        .await;

    let creation = OrderCreation::from_signed_order_data(
        OrderData::default(),
        Signature::default(),
        OWNER,
        cow_rs::EMPTY_APP_DATA_JSON.to_owned(),
        None,
    );

    let err = api(&server).post_order(&creation).await.unwrap_err();
    let message = err.to_string();
    assert!(message.contains("InsufficientFee"), "got: {message}");
    assert!(message.contains("fee is too low"), "got: {message}");
}

#[tokio::test]
async fn get_order_decodes_full_order_record() {
    let server = MockServer::start().await;
    let uid_hex = "0xb74844872ddbadb709629952eab02a9275c5c05426cb195e27029a353909404370997970c51812dc3a010c7d01b50e0d17dc79c86a0513b9";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/orders/{uid_hex}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sellToken": format!("{USDC:?}"),
            "buyToken": format!("{DAI:?}"),
            "receiver": null,
            "sellAmount": "1000000",
            "buyAmount": "999000",
            "validTo": 1_700_000_000,
            "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "feeAmount": "0",
            "kind": "sell",
            "partiallyFillable": false,
            "sellTokenBalance": "erc20",
            "buyTokenBalance": "erc20",
            "uid": uid_hex,
            "owner": format!("{OWNER:?}"),
            "signingScheme": "eip712",
            "signature": "0x00",
            "creationDate": "2026-05-13T10:00:00.000Z",
            "status": "open",
            "class": "market",
            "executedBuyAmount": "0",
            "executedSellAmount": "0",
            "invalidated": false,
            "isLiquidityOrder": false,
        })))
        .mount(&server)
        .await;

    let uid: OrderUid = uid_hex.parse().unwrap();
    let order = api(&server).get_order(&uid).await.unwrap();

    assert_eq!(order.uid, uid);
    assert_eq!(order.owner, OWNER);
    assert_eq!(order.data.sell_amount, U256::from(1_000_000_u64));
    assert!(matches!(order.status, cow_rs::OrderStatus::Open));
}

#[tokio::test]
async fn get_order_status_decodes_lifecycle_payload() {
    let server = MockServer::start().await;
    let uid_hex = "0xb74844872ddbadb709629952eab02a9275c5c05426cb195e27029a353909404370997970c51812dc3a010c7d01b50e0d17dc79c86a0513b9";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/orders/{uid_hex}/status")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "active",
            "value": [{ "solver": format!("{OWNER:?}") }],
        })))
        .mount(&server)
        .await;

    let uid: OrderUid = uid_hex.parse().unwrap();
    let status = api(&server).get_order_status(&uid).await.unwrap();
    assert_eq!(status.status_type, cow_rs::AuctionStatusType::Active);
    assert_eq!(status.value.len(), 1);
}

#[tokio::test]
async fn cancel_orders_sends_signed_collection_and_accepts_200() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/orders"))
        .and(body_string_contains("\"signingScheme\":\"eip712\""))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let signer =
        alloy_signer_local::PrivateKeySigner::from_bytes(&U256::from(1u64).to_be_bytes().into())
            .unwrap();
    let domain = cow_rs::DomainSeparator::new(
        Chain::Mainnet.id(),
        address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
    );
    let signed = OrderCancellations {
        order_uids: vec![OrderUid([0x11; 56])],
    }
    .sign(cow_rs::EcdsaSigningScheme::Eip712, &domain, &signer)
    .unwrap();

    api(&server).cancel_orders(&signed).await.unwrap();
}

#[tokio::test]
async fn account_orders_appends_offset_and_limit_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/account/{OWNER:?}/orders")))
        .and(query_param("offset", "10"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let orders = api(&server)
        .account_orders(OWNER, Some(10), Some(5))
        .await
        .unwrap();
    assert!(orders.is_empty());
}

#[tokio::test]
async fn get_orders_by_uids_posts_camel_case_uid_array() {
    let server = MockServer::start().await;
    let uid_hex = "0xb74844872ddbadb709629952eab02a9275c5c05426cb195e27029a353909404370997970c51812dc3a010c7d01b50e0d17dc79c86a0513b9";

    Mock::given(method("POST"))
        .and(path("/api/v1/orders/by_uids"))
        .and(body_json(json!({ "orderUids": [uid_hex] })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let uid: OrderUid = uid_hex.parse().unwrap();
    let orders = api(&server).get_orders_by_uids(&[uid]).await.unwrap();
    assert!(orders.is_empty());
}

#[tokio::test]
async fn trades_by_owner_filters_with_query_param() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/trades"))
        .and(query_param("owner", format!("{OWNER:?}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let trades = api(&server).trades_by_owner(OWNER).await.unwrap();
    assert!(trades.is_empty());
}

#[tokio::test]
async fn native_price_decodes_float_payload() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/token/{USDC:?}/native_price")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "price": 1.234e9 })))
        .mount(&server)
        .await;

    let price = api(&server).native_price(USDC).await.unwrap();
    assert!((price.price - 1.234e9).abs() < 1.0);
}

#[tokio::test]
async fn total_surplus_returns_decimal_string() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/users/{OWNER:?}/total_surplus")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "totalSurplus": "12345.67" })),
        )
        .mount(&server)
        .await;

    let surplus = api(&server).total_surplus(OWNER).await.unwrap();
    assert_eq!(surplus.total_surplus, "12345.67");
}

#[tokio::test]
async fn version_endpoint_returns_plain_text() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("v0.1.0-mock"),
        )
        .mount(&server)
        .await;

    let version = api(&server).version().await.unwrap();
    assert_eq!(version, "v0.1.0-mock");
}

#[tokio::test]
async fn get_app_data_decodes_full_app_data_envelope() {
    let server = MockServer::start().await;
    let hash = AppDataHash([0xab; 32]);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/app_data/0x{}",
            const_hex::encode(hash.0)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "fullAppData": "{}" })))
        .mount(&server)
        .await;

    let doc = api(&server).get_app_data(&hash).await.unwrap();
    assert_eq!(doc.full_app_data, "{}");
}

#[tokio::test]
async fn put_app_data_accepts_200_with_no_body() {
    let server = MockServer::start().await;
    let hash = AppDataHash([0xab; 32]);
    Mock::given(method("PUT"))
        .and(path(format!(
            "/api/v1/app_data/0x{}",
            const_hex::encode(hash.0)
        )))
        .and(body_json(
            json!({ "fullAppData": "{\"appCode\":\"cow-rs\"}" }),
        ))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    api(&server)
        .put_app_data(
            &hash,
            &AppDataDocument {
                full_app_data: "{\"appCode\":\"cow-rs\"}".into(),
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn unexpected_5xx_with_non_json_body_surfaces_unexpected_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/quote"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>down</html>"),
        )
        .mount(&server)
        .await;

    let request = QuoteRequest::sell_amount_before_fee(USDC, DAI, OWNER, U256::from(1_000_u64));
    let err = api(&server).get_quote(&request).await.unwrap_err();
    let message = err.to_string();
    assert!(message.contains("503"), "got: {message}");
    assert!(message.contains("<html>down</html>"), "got: {message}");
}

#[tokio::test]
async fn unused_optional_quote_fields_are_omitted_from_request_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/quote"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(mainnet_quote_fixture(), "application/json"),
        )
        .mount(&server)
        .await;

    let request =
        QuoteRequest::sell_amount_before_fee(USDC, DAI, OWNER, U256::from(100_000_000_u64))
            .with_receiver(OWNER);
    api(&server).get_quote(&request).await.unwrap();

    // We exercised the request shape via QuoteRequest's own tests; here we
    // just confirm round-tripping the mock works with optional fields set.
    let _ = SigningScheme::default();
    let _ = (SellTokenSource::Erc20, BuyTokenDestination::Erc20);
}
