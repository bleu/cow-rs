//! CoW Protocol orderbook DTOs, quote builders, and HTTP client.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use cowprotocol_appdata::{
    AppDataDoc, AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON, app_data,
};
pub use cowprotocol_primitives::{Chain, chain, contracts, domain};
pub use cowprotocol_signing::{
    BUY_ETH_ADDRESS, BuyTokenDestination, EcdsaSignature, EcdsaSigningScheme, OrderCancellations,
    OrderClass, OrderData, OrderKind, OrderUid, OrderUidParseError, OrderUidParts, Recovered,
    SellTokenSource, Signature, SignatureError, SignedOrderCancellation, SignedOrderCancellations,
    SignerSync, SigningScheme, cancellation, ecdsa_from_components, ecdsa_recover, order,
    order_typed_data, parse_ecdsa, parse_order_uid, sign_ecdsa, signature, signing_scheme,
};

pub mod error;
pub mod eth_flow;
pub mod order_book;
pub mod quote_amounts;
#[cfg(feature = "subgraph")]
pub mod subgraph;
pub mod transport;

pub use self::{
    error::{ApiError, Error, OrderPostErrorKind, Result},
    eth_flow::{ETH_FLOW_PRODUCTION, ETH_FLOW_STAGING, EthFlowOrder},
    order_book::{
        AppDataDocument, Auction, AuctionStatus, AuctionStatusType, NativePrice, Order,
        OrderBookApi, OrderCreation, OrderQuote, OrderQuoteResponse, OrderStatus, OrderSubmission,
        PriceQuality, QuoteAppData, QuoteRequest, QuoteRequestBuilder, QuotedOrder, TokenMetadata,
        TotalSurplus, Trade,
    },
    quote_amounts::{
        Amounts as QuoteAmounts, DEFAULT_SLIPPAGE_BPS, OrderCosts, ProtocolFeeBps,
        QuoteAmountsAndCosts, QuoteAmountsParams, QuoteCosts,
    },
    transport::{HttpMethod, HttpRequest, HttpResponse, HttpTransport},
};

#[cfg(all(feature = "http-client", target_arch = "wasm32"))]
pub use self::transport::FetchTransport;
#[cfg(all(feature = "http-client", not(target_arch = "wasm32")))]
pub use self::transport::ReqwestTransport;
#[cfg(feature = "http-client")]
pub use self::{order_book::OrderBookApiBuilder, transport::DefaultTransport};

#[cfg(feature = "subgraph")]
pub use self::subgraph::{
    ChainSubgraphUnavailable, DailyTotal, GraphQlError, HourlyTotal, SubgraphClient, SubgraphError,
    Totals,
};
