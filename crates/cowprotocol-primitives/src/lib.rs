//! Primitive CoW Protocol chain, domain, order, and contract types.

use alloy_primitives::{B256, b256};

pub mod chain;
pub mod composable;
pub mod contracts;
pub mod domain;
pub mod multiplexer;

/// 32-byte keccak256 digest of an app-data document, embedded directly
/// in a signed order's `appData` field.
pub type AppDataHash = B256;

/// `keccak256("{}")`: digest of the canonical empty app-data document.
pub const EMPTY_APP_DATA_HASH: AppDataHash =
    b256!("b48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d");

/// JSON representation of the empty app-data document (`"{}"`).
pub const EMPTY_APP_DATA_JSON: &str = "{}";

pub use self::{
    chain::{Chain, UnsupportedChain},
    composable::{
        COMPOSABLE_COW, CURRENT_BLOCK_TIMESTAMP_FACTORY, ComposableCoW, ConditionalOrderParams,
        EXTENSIBLE_FALLBACK_HANDLER, PayloadStruct, PollOutcome, Proof, TWAP_HANDLER, TwapData,
        TwapDuration, TwapError, TwapStart, TwapStaticInput, forwarder_signature,
        safe_handler_signature,
    },
    contracts::{
        CoWSwapOnchainOrders, ERC20, GPV2_ORDER_TYPE_HASH, GPV2_SETTLEMENT, GPV2_VAULT_RELAYER,
        GPv2OrderData, GPv2Settlement, OnchainSignature, OnchainSigningScheme, WETH9,
    },
    domain::{
        DOMAIN_NAME, DOMAIN_VERSION, DomainSeparator, eip712_message_hash, settlement_domain,
    },
    multiplexer::{Multiplexer, MultiplexerError, conditional_order_leaf, verify_proof},
};
