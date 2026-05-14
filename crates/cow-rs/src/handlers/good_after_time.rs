//! Good After Time (GAT): place an order that only becomes tradeable
//! after `startTime`, with an optional Milkman price-checker constraint
//! on `buyAmount`.
//!
//! The actual `buyAmount` of the discrete order is supplied by the
//! watch tower's `offchainInput`; the price checker (if configured)
//! validates that the proposed `buyAmount` is within `allowedSlippage`
//! of the expected output. A `minSellBalance` is enforced before each
//! quote so the order does not refill once it has been settled.
//!
//! Adapted from
//! [`composable-cow/src/types/GoodAfterTime.sol`][src].
//!
//! [src]: https://github.com/nullislabs/composable-cow/blob/main/src/types/GoodAfterTime.sol

use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

sol! {
    /// `staticInput` payload for the GoodAfterTime handler.
    ///
    /// Mirrors `GoodAfterTime.Data`:
    ///
    /// ```solidity
    /// struct Data {
    ///     IERC20 sellToken;
    ///     IERC20 buyToken;
    ///     address receiver;
    ///     uint256 sellAmount;
    ///     uint256 minSellBalance;
    ///     uint256 startTime;
    ///     uint256 endTime;
    ///     bool allowPartialFill;
    ///     bytes priceCheckerPayload;
    ///     bytes32 appData;
    /// }
    /// ```
    ///
    /// `priceCheckerPayload` is opaque bytes here; when non-empty it
    /// must decode on chain to a `PriceCheckerPayload` whose Solidity
    /// shape is `(IExpectedOutCalculator checker, bytes payload,
    /// uint256 allowedSlippage)`. Callers that want the nested view
    /// should ABI-encode that tuple themselves.
    #[derive(Debug)]
    struct Data {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 minSellBalance;
        uint256 startTime;
        uint256 endTime;
        bool allowPartialFill;
        bytes priceCheckerPayload;
        bytes32 appData;
    }
}

/// Canonical CREATE2 address of the `GoodAfterTime` handler contract.
///
/// Identical on Mainnet, Gnosis Chain, Sepolia and Arbitrum One.
pub const GOOD_AFTER_TIME_HANDLER: Address =
    address!("0xd3338f21c89745E46AF56Aeaf553cF96ba9BC66f");

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, Bytes, U256, hex};
    use alloy_sol_types::SolValue;

    use super::*;

    #[test]
    fn good_after_time_data_round_trips_via_abi() {
        let data = Data {
            sellToken: address!("0101010101010101010101010101010101010101"),
            buyToken: address!("0202020202020202020202020202020202020202"),
            receiver: address!("0303030303030303030303030303030303030303"),
            sellAmount: U256::from(1_000_000_000_000_000_000_u128),
            minSellBalance: U256::from(2_000_000_000_000_000_000_u128),
            startTime: U256::from(1_700_000_000_u64),
            endTime: U256::from(1_800_000_000_u64),
            allowPartialFill: true,
            priceCheckerPayload: Bytes::from_static(&hex!("c0ffee")),
            appData: B256::ZERO,
        };
        let encoded = data.abi_encode();
        let decoded = Data::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.sellToken, data.sellToken);
        assert_eq!(decoded.buyToken, data.buyToken);
        assert_eq!(decoded.receiver, data.receiver);
        assert_eq!(decoded.sellAmount, data.sellAmount);
        assert_eq!(decoded.minSellBalance, data.minSellBalance);
        assert_eq!(decoded.startTime, data.startTime);
        assert_eq!(decoded.endTime, data.endTime);
        assert_eq!(decoded.allowPartialFill, data.allowPartialFill);
        assert_eq!(decoded.priceCheckerPayload, data.priceCheckerPayload);
        assert_eq!(decoded.appData, data.appData);
    }

    #[test]
    fn handler_address_is_canonical() {
        assert_eq!(
            GOOD_AFTER_TIME_HANDLER,
            address!("0xd3338f21c89745E46AF56Aeaf553cF96ba9BC66f")
        );
    }
}
