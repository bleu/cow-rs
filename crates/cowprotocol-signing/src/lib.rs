//! CoW Protocol signing schemes, signatures, and cancellation helpers.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod cancellation;
pub mod order;
pub mod signature;
pub mod signing_scheme;

pub use cowprotocol_primitives::{contracts, domain};

// Re-exported so downstream crates (the orderbook pipeline, integrator
// code) can name the signer bound without a direct alloy-signer
// dependency; this crate already owns the alloy-signer edge for
// `OrderData::sign`.
pub use alloy_signer::SignerSync;

pub mod app_data {
    //! Shared app-data digest primitives used by signed orders.

    pub use cowprotocol_primitives::{AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON};
}

pub use self::{
    cancellation::{
        OrderCancellation, OrderCancellations, SignedOrderCancellation, SignedOrderCancellations,
        cancellation_typed_data,
    },
    order::{
        BUY_ETH_ADDRESS, BuyTokenDestination, OrderClass, OrderData, OrderKind, OrderUid,
        OrderUidParseError, OrderUidParts, SellTokenSource, order_typed_data, parse_order_uid,
    },
    signature::{
        EcdsaSignature, Recovered, Signature, SignatureError, ecdsa_from_components, ecdsa_recover,
        parse_ecdsa, sign_ecdsa, signing_message,
    },
    signing_scheme::{EcdsaSigningScheme, SigningScheme},
};
