//! The EthFlow periphery contract, the canonical path for users to sell a
//! chain's native gas token (ETH on mainnet, xDAI on Gnosis Chain, and so on)
//! through CoW Protocol without first wrapping it themselves.
//!
//! A user calls `createOrder(EthFlowOrder.Data)` on the EthFlow contract with
//! `msg.value = sellAmount + feeAmount`. The contract wraps the native token
//! into its ERC-20 counterpart (e.g. WETH) and stands in as an ERC-1271
//! "contract intent" signer for an otherwise standard CoW order with
//! `kind = sell`, `validTo = u32::MAX` and an empty (`0x`) signature payload.
//! Only sells are supported — to buy native ETH, sell to WETH and unwrap
//! client-side.
//!
//! This module exposes the two deployed addresses and the on-chain order
//! struct ([`EthFlowOrder`]), plus a helper to project it into the canonical
//! [`OrderData`] payload that flows through the rest of the SDK. ABI
//! bindings for `createOrder` / `invalidateOrder` are intentionally deferred
//! to a follow-up commit so this addition can be reviewed in isolation.
//!
//! Source: `cowprotocol/ethflowcontract/src/libraries/EthFlowOrder.sol` and
//! cow-docs §7 "ETH-flow".

use {
    crate::{
        app_data::AppDataHash,
        order::{BuyTokenDestination, OrderData, OrderKind, SellTokenSource},
    },
    alloy_primitives::{Address, U256, address},
};

/// Production EthFlow deployment, identical on every chain CoW Protocol
/// supports.
///
/// Source: `cowprotocol/ethflowcontract/networks.prod.json`.
pub const ETH_FLOW_PRODUCTION: Address = address!("bA3cB449bD2B4ADddBc894D8697F5170800EAdeC");

/// Staging ("barn") EthFlow deployment, identical on every chain.
///
/// Source: `cowprotocol/ethflowcontract/networks.barn.json`.
pub const ETH_FLOW_STAGING: Address = address!("04501b9b1D52e67f6862d157E00D13419D2D6E95");

/// The on-chain `EthFlowOrder.Data` struct passed to `createOrder`.
///
/// Mirrors the Solidity tuple in
/// [`EthFlowOrder.sol`](https://github.com/cowprotocol/ethflowcontract/blob/main/src/libraries/EthFlowOrder.sol):
///
/// ```solidity
/// struct Data {
///     IERC20 buyToken;
///     address receiver;
///     uint256 sellAmount;
///     uint256 buyAmount;
///     bytes32 appData;
///     uint256 feeAmount;
///     uint32 validTo;
///     bool partiallyFillable;
///     int64 quoteId;
/// }
/// ```
///
/// The sell-token slot is not part of this struct because EthFlow always
/// sells the chain's wrapped-native token; the caller passes that address
/// in to [`EthFlowOrder::to_order_data`].
///
/// `receiver` is modelled as `Option<Address>` to match
/// [`OrderData::receiver`] semantics: `None` means the order owner receives
/// the buy token, which the EthFlow contract encodes as the zero address.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EthFlowOrder {
    /// Token the user wishes to buy with their native ETH.
    pub buy_token: Address,
    /// Optional recipient of the buy token. `None` defers to the order owner
    /// (i.e. the EthFlow contract's view of the original native-token sender).
    pub receiver: Option<Address>,
    /// Amount of native ETH being sold, in wei. Must equal
    /// `msg.value - fee_amount` when `createOrder` is invoked.
    pub sell_amount: U256,
    /// Minimum amount of `buy_token` the user expects.
    pub buy_amount: U256,
    /// 32-byte digest of the canonical app-data JSON.
    pub app_data: AppDataHash,
    /// Protocol fee, paid in the wrapped-native sell token.
    pub fee_amount: U256,
    /// Order expiry as a unix timestamp in seconds. Note that the
    /// CoW-side order produced by [`EthFlowOrder::to_order_data`] always
    /// uses `validTo = u32::MAX`; this field stores the *user-facing*
    /// expiry recorded on the EthFlow contract.
    pub valid_to: u32,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Identifier of the off-chain quote backing this order.
    pub quote_id: i64,
}

impl EthFlowOrder {
    /// Project this EthFlow order into the canonical [`OrderData`] payload
    /// that the settlement contract verifies.
    ///
    /// `wrapped_native_token` is the ERC-20 the EthFlow contract wraps the
    /// native gas token into — WETH on Ethereum mainnet, WXDAI on Gnosis
    /// Chain, and so on. The result is a sell order with `validTo` pinned to
    /// `u32::MAX` (the EthFlow contract enforces the user-facing expiry
    /// separately) and an empty receiver folded into `Some(receiver)` when
    /// set.
    ///
    /// Signing is implicit: the EthFlow contract is the order owner and
    /// signs via ERC-1271 ([`crate::signing_scheme::SigningScheme::Eip1271`])
    /// with an empty (`0x`) signature payload. The SDK's native-sell
    /// sentinel `0xEeee…EEeE` is *not* used here — it is a quote-time
    /// convenience for `OrderBookApi`; the on-chain order produced by this
    /// helper always sets `sell_token = wrapped_native_token`.
    pub const fn to_order_data(&self, wrapped_native_token: Address) -> OrderData {
        OrderData {
            sell_token: wrapped_native_token,
            buy_token: self.buy_token,
            receiver: self.receiver,
            sell_amount: self.sell_amount,
            buy_amount: self.buy_amount,
            valid_to: u32::MAX,
            app_data: self.app_data,
            fee_amount: self.fee_amount,
            kind: OrderKind::Sell,
            partially_fillable: self.partially_fillable,
            sell_token_balance: SellTokenSource::Erc20,
            buy_token_balance: BuyTokenDestination::Erc20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical WETH address on Ethereum mainnet — the wrapped-native token
    /// the production EthFlow deployment hands over to the settlement
    /// contract when sourced on mainnet.
    const WETH_MAINNET: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");

    /// A non-zero, easy-to-eyeball receiver address reused across tests.
    const SAMPLE_RECEIVER: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

    /// The two EthFlow deployment addresses parse as valid 20-byte
    /// addresses, are not the zero address, and are distinct from each
    /// other. The `address!` macro already enforces well-formed hex at
    /// compile time, so this guards against accidental copy-paste
    /// regressions (e.g. the staging address overwriting production).
    #[test]
    fn deployment_addresses_are_distinct_and_non_zero() {
        assert_ne!(ETH_FLOW_PRODUCTION, Address::ZERO);
        assert_ne!(ETH_FLOW_STAGING, Address::ZERO);
        assert_ne!(ETH_FLOW_PRODUCTION, ETH_FLOW_STAGING);
        assert_eq!(
            ETH_FLOW_PRODUCTION,
            address!("bA3cB449bD2B4ADddBc894D8697F5170800EAdeC")
        );
        assert_eq!(
            ETH_FLOW_STAGING,
            address!("04501b9b1D52e67f6862d157E00D13419D2D6E95")
        );
    }

    /// `to_order_data` should pin `sell_token` to the supplied wrapped-native
    /// token, propagate the receiver, force `valid_to = u32::MAX` and
    /// `kind = Sell`, and leave the user-supplied amounts untouched.
    #[test]
    fn to_order_data_projects_canonical_sell_order() {
        let eth_flow = EthFlowOrder {
            buy_token: address!("6B175474E89094C44Da98b954EedeAC495271d0F"), // DAI
            receiver: Some(SAMPLE_RECEIVER),
            sell_amount: U256::from(1_000_000_000_000_000_000_u128), // 1 ETH
            buy_amount: U256::from(3_500_000_000_000_000_000_000_u128), // 3,500 DAI
            app_data: AppDataHash([0xab; 32]),
            fee_amount: U256::from(1_500_000_000_000_000_u128), // 0.0015 ETH
            // The user-facing expiry on EthFlow is unrelated to the
            // settlement `validTo`, which must always be `u32::MAX`.
            valid_to: 1_700_000_000,
            partially_fillable: false,
            quote_id: 42,
        };

        let order = eth_flow.to_order_data(WETH_MAINNET);

        assert_eq!(order.sell_token, WETH_MAINNET);
        assert_eq!(order.buy_token, eth_flow.buy_token);
        assert_eq!(order.receiver, Some(SAMPLE_RECEIVER));
        assert_eq!(order.sell_amount, eth_flow.sell_amount);
        assert_eq!(order.buy_amount, eth_flow.buy_amount);
        assert_eq!(order.fee_amount, eth_flow.fee_amount);
        assert_eq!(order.app_data, eth_flow.app_data);
        assert_eq!(order.valid_to, u32::MAX);
        assert_eq!(order.kind, OrderKind::Sell);
        assert!(!order.partially_fillable);
        assert_eq!(order.sell_token_balance, SellTokenSource::Erc20);
        assert_eq!(order.buy_token_balance, BuyTokenDestination::Erc20);
    }

    /// A `None` receiver on the EthFlow side projects through unchanged so
    /// that downstream EIP-712 hashing treats it as the zero address (matching
    /// the EthFlow contract's behaviour of leaving the receiver slot empty).
    #[test]
    fn to_order_data_preserves_absent_receiver() {
        let eth_flow = EthFlowOrder {
            buy_token: address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
            receiver: None,
            sell_amount: U256::from(1_u8),
            buy_amount: U256::from(1_u8),
            app_data: AppDataHash::default(),
            fee_amount: U256::ZERO,
            valid_to: 0,
            partially_fillable: true,
            quote_id: 0,
        };

        let order = eth_flow.to_order_data(WETH_MAINNET);
        assert_eq!(order.receiver, None);
        assert_eq!(order.valid_to, u32::MAX);
        assert!(order.partially_fillable);
    }
}
