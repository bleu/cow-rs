//! CoW Protocol orderbook DTOs, quote builders, and HTTP client.

pub use cowprotocol_appdata::{
    AppDataDoc, AppDataHash, EMPTY_APP_DATA_HASH, EMPTY_APP_DATA_JSON, app_data,
};
pub use cowprotocol_primitives::{Chain, chain, contracts, domain};
pub use cowprotocol_signing::{
    BUY_ETH_ADDRESS, BuyTokenDestination, EcdsaSignature, EcdsaSigningScheme, Order,
    OrderCancellations, OrderClass, OrderData, OrderKind, OrderStatus, OrderUid,
    OrderUidParseError, OrderUidParts, Recovered, SellTokenSource, Signature, SignatureError,
    SignedOrderCancellation, SignedOrderCancellations, SigningScheme, cancellation,
    ecdsa_from_components, ecdsa_recover, order, order_typed_data, parse_ecdsa, parse_order_uid,
    sign_ecdsa, signature, signing_scheme,
};

pub mod error;
pub mod order_book;
pub mod quote_amounts;
#[cfg(feature = "subgraph")]
pub mod subgraph;
#[cfg(feature = "http-client")]
pub mod trading;

pub use self::{
    error::{ApiError, Error, Result},
    order_book::{
        AppDataDocument, Auction, AuctionStatus, AuctionStatusType, NativePrice, OrderCreation,
        OrderQuote, OrderQuoteResponse, PriceQuality, QuoteAppData, QuoteRequest,
        QuoteRequestBuilder, TokenMetadata, TotalSurplus, Trade,
    },
    quote_amounts::{
        Amounts as QuoteAmounts, QuoteAmountsAndCosts, QuoteAmountsParams, QuoteCosts,
    },
};

#[cfg(feature = "http-client")]
pub use self::{
    order_book::{
        OrderBookApi, OrderBookApiBuilder, OrderBookQuoteBuilder, QuotedOrder,
        SignedOrderSubmission,
    },
    trading::{PostedSwapOrder, SwapOrder, TradingClient},
};

#[cfg(feature = "subgraph")]
pub use self::subgraph::{
    ChainSubgraphUnavailable, DailyTotal, GraphQlError, HourlyTotal, SubgraphClient, SubgraphError,
    Totals,
};
