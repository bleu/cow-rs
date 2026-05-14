//! Stop-loss: trigger an order when a Chainlink-style oracle pair
//! crosses a strike price.
//!
//! Two oracles (sell-token and buy-token) must be denominated in the
//! same numeraire. When `sellTokenPrice / buyTokenPrice <= strike`, the
//! handler emits a discrete order at the configured amounts. Stale
//! oracle data (older than `maxTimeSinceLastOracleUpdate`) yields
//! `PollTryNextBlock("oracle stale price")`.
//!
//! Adapted from [`composable-cow/src/types/StopLoss.sol`][src].
//!
//! [src]: https://github.com/nullislabs/composable-cow/blob/main/src/types/StopLoss.sol

use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

sol! {
    /// `staticInput` payload for the StopLoss handler.
    ///
    /// Mirrors `StopLoss.Data`:
    ///
    /// ```solidity
    /// struct Data {
    ///     IERC20 sellToken;
    ///     IERC20 buyToken;
    ///     uint256 sellAmount;
    ///     uint256 buyAmount;
    ///     bytes32 appData;
    ///     address receiver;
    ///     bool isSellOrder;
    ///     bool isPartiallyFillable;
    ///     uint32 validityBucketSeconds;
    ///     IAggregatorV3Interface sellTokenPriceOracle;
    ///     IAggregatorV3Interface buyTokenPriceOracle;
    ///     int256 strike;
    ///     uint256 maxTimeSinceLastOracleUpdate;
    /// }
    /// ```
    ///
    /// `strike` is denominated in sellToken/buyToken with 18 decimals
    /// after the handler normalises the two oracle reads to a shared
    /// 18-decimal numeraire. Both oracles must share their quote
    /// currency (e.g. both denominated in USD or both in ETH).
    #[derive(Debug)]
    struct Data {
        address sellToken;
        address buyToken;
        uint256 sellAmount;
        uint256 buyAmount;
        bytes32 appData;
        address receiver;
        bool isSellOrder;
        bool isPartiallyFillable;
        uint32 validityBucketSeconds;
        address sellTokenPriceOracle;
        address buyTokenPriceOracle;
        int256 strike;
        uint256 maxTimeSinceLastOracleUpdate;
    }
}

/// Canonical CREATE2 address of the `StopLoss` handler contract.
///
/// Identical on Mainnet, Gnosis Chain, Sepolia and Arbitrum One.
pub const STOP_LOSS_HANDLER: Address = address!("0xE8212F30C28B4AAB467DF3725C14d6e89C2eB967");

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, I256, U256, hex};
    use alloy_sol_types::SolValue;

    use super::*;

    #[test]
    fn stop_loss_data_round_trips_via_abi() {
        let data = Data {
            sellToken: address!("0101010101010101010101010101010101010101"),
            buyToken: address!("0202020202020202020202020202020202020202"),
            sellAmount: U256::from(1_000_000_000_000_000_000_u128),
            buyAmount: U256::from(800_000_000_000_000_000_u128),
            appData: B256::from(hex!(
                "b48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d"
            )),
            receiver: address!("0303030303030303030303030303030303030303"),
            isSellOrder: true,
            isPartiallyFillable: false,
            validityBucketSeconds: 900,
            sellTokenPriceOracle: address!("0404040404040404040404040404040404040404"),
            buyTokenPriceOracle: address!("0505050505050505050505050505050505050505"),
            strike: I256::try_from(950_000_000_000_000_000_i128).unwrap(),
            maxTimeSinceLastOracleUpdate: U256::from(3600_u64),
        };
        let encoded = data.abi_encode();
        let decoded = Data::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.sellToken, data.sellToken);
        assert_eq!(decoded.buyToken, data.buyToken);
        assert_eq!(decoded.sellAmount, data.sellAmount);
        assert_eq!(decoded.buyAmount, data.buyAmount);
        assert_eq!(decoded.appData, data.appData);
        assert_eq!(decoded.receiver, data.receiver);
        assert_eq!(decoded.isSellOrder, data.isSellOrder);
        assert_eq!(decoded.isPartiallyFillable, data.isPartiallyFillable);
        assert_eq!(decoded.validityBucketSeconds, data.validityBucketSeconds);
        assert_eq!(decoded.sellTokenPriceOracle, data.sellTokenPriceOracle);
        assert_eq!(decoded.buyTokenPriceOracle, data.buyTokenPriceOracle);
        assert_eq!(decoded.strike, data.strike);
        assert_eq!(
            decoded.maxTimeSinceLastOracleUpdate,
            data.maxTimeSinceLastOracleUpdate
        );
    }

    #[test]
    fn handler_address_is_canonical() {
        assert_eq!(
            STOP_LOSS_HANDLER,
            address!("0xE8212F30C28B4AAB467DF3725C14d6e89C2eB967")
        );
    }
}
