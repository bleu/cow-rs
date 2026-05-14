//! End-to-end signed submission of a CoW Protocol order on Sepolia.
//!
//! The example performs the four-step trade flow exposed by `cow-rs`:
//!
//! 1. Ask the Sepolia orderbook for a quote on a small WETH -> COW swap.
//! 2. Apply the documented submission adjustments via
//!    [`cowprotocol::OrderQuoteResponse::to_signed_order_data`].
//! 3. Sign the resulting [`cowprotocol::OrderData`] under the GPv2Settlement
//!    domain with an EIP-712 ECDSA signature.
//! 4. POST the signed body to `/api/v1/orders` and print the assigned UID
//!    together with a CoW Explorer URL.
//!
//! # Environment
//!
//! - `SEPOLIA_PRIVATE_KEY`: hex-encoded 32-byte secp256k1 key, with or
//!   without the `0x` prefix. When the variable is absent the example
//!   prints a short hint and exits successfully so the binary still
//!   compiles and runs cleanly in CI.
//!
//! # Funding
//!
//! Signing a quote and POSTing it to the orderbook does NOT require any
//! on-chain balance: the orderbook accepts the order, it just will not
//! settle until the signer holds enough sell-token (here, Sepolia WETH)
//! and has granted the Vault relayer an allowance. The wallet still
//! needs a small amount of Sepolia ETH for any future on-chain action
//! (wrapping, approvals, cancellation) but not for this submission
//! itself.
//!
//! # Explorer
//!
//! Submitted orders are viewable at
//! `https://explorer.cow.fi/sepolia/orders/<uid>`.
//!
//! # Run
//!
//! ```sh
//! SEPOLIA_PRIVATE_KEY=0x... cargo run --example post_order
//! ```

use {
    alloy_primitives::{Address, U256, address},
    alloy_signer_local::PrivateKeySigner,
    cowprotocol::{
        Chain, DomainSeparator, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON, EcdsaSigningScheme,
        GPV2_SETTLEMENT, OrderBookApi, OrderCreation, QuoteRequest,
    },
    std::str::FromStr,
};

/// Sepolia WETH. Source: `cowprotocol/contracts/networks.json`.
const WETH_SEPOLIA: Address = address!("fFf9976782d46CC05630D1f6eBAb18b2324d6B14");
/// Sepolia COW. Source: `cowprotocol/contracts/networks.json`.
const COW_SEPOLIA: Address = address!("0625aFB445C3B6B7B929342a04A22599fd5dBB59");
/// Sell amount: 0.01 WETH expressed in 18-decimal atomic units. Small
/// enough that the orderbook will quote without bumping into liquidity
/// floors, large enough that the quote response is meaningful.
const SELL_AMOUNT_WEI: u128 = 10_000_000_000_000_000;

#[tokio::main]
async fn main() -> cowprotocol::Result<()> {
    let Ok(raw_key) = std::env::var("SEPOLIA_PRIVATE_KEY") else {
        println!("set SEPOLIA_PRIVATE_KEY=... to run live (skipping)");
        return Ok(());
    };

    // Configuration error: the env-supplied key must be valid hex. We
    // surface this immediately rather than smuggling it through
    // `cowprotocol::Error`, whose variants describe wire-format / signing /
    // orderbook failures, not user-input parsing.
    let signer = PrivateKeySigner::from_str(raw_key.trim())
        .expect("SEPOLIA_PRIVATE_KEY must be a 0x-prefixed 32-byte hex string");
    let owner = signer.address();
    println!("signer:       {owner:?}");

    let api = OrderBookApi::new(Chain::Sepolia);

    // Step 1: quote.
    let request = QuoteRequest::sell_amount_before_fee(
        WETH_SEPOLIA,
        COW_SEPOLIA,
        owner,
        U256::from(SELL_AMOUNT_WEI),
    );
    let quote = api.get_quote(&request).await?;
    println!("quote id:     {}", quote.id);
    println!("buy amount:   {}", quote.quote.buy_amount);
    println!("fee amount:   {}", quote.quote.fee_amount);
    println!("valid to:     {}", quote.quote.valid_to);

    // Step 2: project into the signed payload.
    let order_data = quote.to_signed_order_data(EMPTY_APP_DATA_HASH)?;

    // Step 3: sign under the Sepolia GPv2Settlement domain.
    let domain = DomainSeparator::new(Chain::Sepolia.id(), GPV2_SETTLEMENT);
    let signature = order_data.sign(EcdsaSigningScheme::Eip712, &domain, &signer)?;

    // Step 4: assemble the submission body and POST it.
    let creation = OrderCreation::from_signed_order_data(
        order_data,
        signature,
        owner,
        EMPTY_APP_DATA_JSON.to_owned(),
        Some(quote.id),
    )?;
    let uid = api.post_order(&creation).await?;

    println!("order uid:    {uid}");
    println!("explorer:     https://explorer.cow.fi/sepolia/orders/{uid}");

    Ok(())
}
