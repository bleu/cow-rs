//! TWAP: time-weighted average order handler.
//!
//! A TWAP order is split into `n` equally-sized parts, each part valid
//! for `span` seconds within a window of `t` seconds. The watch tower
//! polls the handler every block; on each part-window opening the
//! handler returns a discrete [`GPv2Order`] sized to `partSellAmount`
//! tokens. Once `validTo` of the active part passes the handler reverts
//! `OrderNotValid("not within span")`.
//!
//! Adapted from
//! [`composable-cow/src/types/twap/libraries/TWAPOrder.sol`][src].
//!
//! [`GPv2Order`]: crate::contracts::GPv2OrderData
//! [src]: https://github.com/nullislabs/composable-cow/blob/main/src/types/twap/libraries/TWAPOrder.sol

use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

sol! {
    /// `staticInput` payload for the TWAP handler.
    ///
    /// Mirrors `TWAPOrder.Data` from
    /// [`TWAPOrder.sol`](https://github.com/nullislabs/composable-cow/blob/main/src/types/twap/libraries/TWAPOrder.sol):
    ///
    /// ```solidity
    /// struct Data {
    ///     IERC20 sellToken;
    ///     IERC20 buyToken;
    ///     address receiver;
    ///     uint256 partSellAmount;
    ///     uint256 minPartLimit;
    ///     uint256 t0;
    ///     uint256 n;
    ///     uint256 t;
    ///     uint256 span;
    ///     bytes32 appData;
    /// }
    /// ```
    ///
    /// Validation rules enforced by the handler (`TWAPOrder.validate`):
    ///
    /// - `sellToken != buyToken`
    /// - `sellToken != 0 && buyToken != 0`
    /// - `partSellAmount > 0`
    /// - `minPartLimit > 0`
    /// - `t0 < type(uint32).max`
    /// - `1 < n <= type(uint32).max`
    /// - `0 < t <= 365 days`
    /// - `span <= t`
    #[derive(Debug)]
    struct Data {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 partSellAmount;
        uint256 minPartLimit;
        uint256 t0;
        uint256 n;
        uint256 t;
        uint256 span;
        bytes32 appData;
    }
}

/// Canonical CREATE2 address of the `TWAP` handler contract.
///
/// Identical on Ethereum mainnet, Gnosis Chain, Sepolia and Arbitrum
/// One. Source: `nullislabs/composable-cow` README.
pub const TWAP_HANDLER: Address = address!("0x6cF1e9cA41f7611dEf408122793c358a3d11E5a5");

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, U256, hex};
    use alloy_sol_types::SolValue;

    use super::*;

    /// `Data` round-trips byte-for-byte through `abi_encode`/`abi_decode`,
    /// so a Rust-side caller can hash the same bytes the on-chain
    /// `abi.decode(staticInput, (Data))` resolves to.
    #[test]
    fn twap_data_round_trips_via_abi() {
        let data = Data {
            sellToken: address!("0101010101010101010101010101010101010101"),
            buyToken: address!("0202020202020202020202020202020202020202"),
            receiver: address!("0303030303030303030303030303030303030303"),
            partSellAmount: U256::from(1_000_000_000_000_000_000_u128),
            minPartLimit: U256::from(900_000_000_000_000_000_u128),
            t0: U256::from(1_700_000_000_u64),
            n: U256::from(12_u64),
            t: U256::from(3600_u64),
            span: U256::from(600_u64),
            appData: B256::from(hex!(
                "b48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d"
            )),
        };
        let encoded = data.abi_encode();
        let decoded = Data::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.sellToken, data.sellToken);
        assert_eq!(decoded.buyToken, data.buyToken);
        assert_eq!(decoded.receiver, data.receiver);
        assert_eq!(decoded.partSellAmount, data.partSellAmount);
        assert_eq!(decoded.minPartLimit, data.minPartLimit);
        assert_eq!(decoded.t0, data.t0);
        assert_eq!(decoded.n, data.n);
        assert_eq!(decoded.t, data.t);
        assert_eq!(decoded.span, data.span);
        assert_eq!(decoded.appData, data.appData);
    }

    #[test]
    fn twap_handler_address_is_canonical() {
        assert_eq!(
            TWAP_HANDLER,
            address!("0x6cF1e9cA41f7611dEf408122793c358a3d11E5a5")
        );
    }
}
