//! Perpetual stable-swap: stand permanently ready to trade between
//! `tokenA` and `tokenB` at parity (1:1, decimals-adjusted) with a
//! configurable spread.
//!
//! The handler picks the direction on each poll: it always sells the
//! token the owner currently has more of, sized at the owner's full
//! balance, and quotes the counter-amount at `parity * (1 +
//! halfSpreadBps / 10_000)`.
//!
//! Adapted from
//! [`composable-cow/src/types/PerpetualStableSwap.sol`][src].
//!
//! [src]: https://github.com/nullislabs/composable-cow/blob/main/src/types/PerpetualStableSwap.sol

use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

sol! {
    /// `staticInput` payload for the PerpetualStableSwap handler.
    ///
    /// Mirrors `PerpetualStableSwap.Data`:
    ///
    /// ```solidity
    /// struct Data {
    ///     IERC20 tokenA;
    ///     IERC20 tokenB;
    ///     uint32 validityBucketSeconds;
    ///     uint256 halfSpreadBps;
    ///     bytes32 appData;
    /// }
    /// ```
    ///
    /// The receiver is always the order owner; the handler ignores any
    /// caller-supplied receiver.
    #[derive(Debug)]
    struct Data {
        address tokenA;
        address tokenB;
        uint32 validityBucketSeconds;
        uint256 halfSpreadBps;
        bytes32 appData;
    }
}

/// Canonical CREATE2 address of the `PerpetualStableSwap` handler
/// contract.
///
/// Identical on Mainnet, Gnosis Chain, Sepolia and Arbitrum One.
pub const PERPETUAL_STABLE_SWAP_HANDLER: Address =
    address!("0x519BA24e959E33b3B6220CA98bd353d8c2D89920");

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, U256, hex};
    use alloy_sol_types::SolValue;

    use super::*;

    #[test]
    fn perpetual_stable_swap_data_round_trips_via_abi() {
        let data = Data {
            tokenA: address!("0101010101010101010101010101010101010101"),
            tokenB: address!("0202020202020202020202020202020202020202"),
            validityBucketSeconds: 1_209_600, // two weeks
            halfSpreadBps: U256::from(50_u64),
            appData: B256::from(hex!(
                "b48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d"
            )),
        };
        let encoded = data.abi_encode();
        let decoded = Data::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.tokenA, data.tokenA);
        assert_eq!(decoded.tokenB, data.tokenB);
        assert_eq!(decoded.validityBucketSeconds, data.validityBucketSeconds);
        assert_eq!(decoded.halfSpreadBps, data.halfSpreadBps);
        assert_eq!(decoded.appData, data.appData);
    }

    #[test]
    fn handler_address_is_canonical() {
        assert_eq!(
            PERPETUAL_STABLE_SWAP_HANDLER,
            address!("0x519BA24e959E33b3B6220CA98bd353d8c2D89920")
        );
    }
}
