//! CoW Protocol signing schemes, signatures, and cancellation helpers.

pub mod cancellation;
pub mod order;
pub mod signature;
pub mod signing_scheme;

pub use cowprotocol_primitives::{contracts, domain};

pub mod app_data {
    //! Shared app-data digest primitives used by signed orders.

    pub use cowprotocol_primitives::{AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON};
}

pub use self::{
    cancellation::{OrderCancellations, SignedOrderCancellation, SignedOrderCancellations},
    order::{
        BUY_ETH_ADDRESS, BuyTokenDestination, Order, OrderClass, OrderData, OrderKind, OrderStatus,
        OrderUid, OrderUidParseError, OrderUidParts, SellTokenSource, order_typed_data,
        parse_order_uid,
    },
    signature::{
        EcdsaSignature, Recovered, Signature, SignatureError, ecdsa_from_components, ecdsa_recover,
        parse_ecdsa, sign_ecdsa,
    },
    signing_scheme::{EcdsaSigningScheme, SigningScheme},
};
