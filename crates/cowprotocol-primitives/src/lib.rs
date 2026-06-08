//! Primitive CoW Protocol chain, domain, order, and contract types.

pub mod chain;
pub mod composable;
pub mod contracts;
pub mod domain;
pub mod multiplexer;

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
