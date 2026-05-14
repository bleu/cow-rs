//! ComposableCoW conditional orders.
//!
//! `ComposableCoW` is mfw78's CoW Protocol extension that turns the
//! `GPv2Order` primitive into a discrete instantiation of a longer-lived
//! conditional order. A registered order is identified by a 3-tuple
//! `(handler, salt, staticInput)` ([`ConditionalOrderParams`]); a watch
//! tower polls the handler on every block and either gets back a
//! discrete `GPv2Order` to submit or one of the custom-error signals
//! captured by [`PollOutcome`].
//!
//! Three layers live here:
//!
//! - [`ConditionalOrderParams`]: the 3-tuple ABI-encoded the same way as
//!   the Solidity counterpart, suitable for `ComposableCoW.create` and
//!   for hashing into the single-order or merkle-root index.
//! - [`Proof`]: the `(location, data)` pointer the contract stores
//!   alongside a merkle root in `ComposableCoW.setRoot`.
//! - [`PollOutcome`]: typed mapping of the five custom errors
//!   `IConditionalOrder.verify` reverts with.
//!
//! Handler-specific `staticInput` payloads (TWAP, GoodAfterTime, etc.)
//! land in follow-up modules. The canonical Solidity sources live in
//! [`nullislabs/composable-cow`][cc].
//!
//! [cc]: https://github.com/nullislabs/composable-cow

use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

use crate::chain::Chain;

sol! {
    /// 3-tuple uniquely identifying a conditional order for an owner.
    ///
    /// `keccak256(abi.encode(ConditionalOrderParams))` must be unique per
    /// owner; that hash is the `singleOrders` key (when no merkle root is
    /// used) and the `ctx` watch-towers pass back through
    /// `IConditionalOrder.verify`.
    #[derive(Debug, Eq, Hash, PartialEq)]
    struct ConditionalOrderParams {
        address handler;
        bytes32 salt;
        bytes staticInput;
    }

    /// Pointer to off-chain merkle proofs, recorded by
    /// `ComposableCoW.setRoot` so watch-towers know where to fetch the
    /// leaf proofs from.
    #[derive(Debug, Eq, Hash, PartialEq)]
    struct Proof {
        uint256 location;
        bytes data;
    }
}

/// Outcome of a single watch-tower poll, mapped from the custom errors
/// `IConditionalOrder.verify` reverts with.
///
/// See `composable-cow/src/interfaces/IConditionalOrder.sol`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    /// `OrderNotValid(string)`: the order condition is permanently not
    /// met. Watch tower should drop the order.
    OrderNotValid(String),
    /// `PollTryNextBlock(string)`: try again on the next block.
    TryNextBlock(String),
    /// `PollTryAtBlock(uint256, string)`: try again at or after a
    /// specific block number.
    TryAtBlock {
        /// Earliest block at which the order may become tradeable.
        block: u64,
        /// Reason carried alongside the revert.
        reason: String,
    },
    /// `PollTryAtEpoch(uint256, string)`: try again at or after a
    /// specific Unix timestamp (seconds).
    TryAtEpoch {
        /// Earliest timestamp at which the order may become tradeable.
        timestamp: u64,
        /// Reason carried alongside the revert.
        reason: String,
    },
    /// `PollNever(string)`: the conditional order is dead; do not poll
    /// it again.
    Never(String),
}

/// Canonical CREATE2 address of the `ComposableCoW` contract.
///
/// Identical on Ethereum mainnet, Gnosis Chain, Sepolia and Arbitrum
/// One. Source: `nullislabs/composable-cow` README deployment table.
pub const COMPOSABLE_COW: Address = address!("0xfdaFc9d1902f4e0b84f65F49f244b32b31013b74");

/// Canonical CREATE2 address of the `ExtensibleFallbackHandler` Safe
/// fallback handler the ComposableCoW signing flow plugs into.
pub const EXTENSIBLE_FALLBACK_HANDLER: Address =
    address!("0x2f55e8b20D0B9FEFA187AA7d00B6Cbe563605bF5");

/// Canonical CREATE2 address of the `CurrentBlockTimestampFactory` value
/// factory used by handlers that anchor their schedule to the block
/// timestamp at registration time.
pub const CURRENT_BLOCK_TIMESTAMP_FACTORY: Address =
    address!("0x52eD56Da04309Aca4c3FECC595298d80C2f16BAc");

impl Chain {
    /// `ComposableCoW` deployment address on this chain, or `None` when
    /// the contract is not deployed there.
    pub const fn composable_cow_address(self) -> Option<Address> {
        match self {
            Self::Mainnet | Self::Gnosis | Self::Sepolia | Self::ArbitrumOne => {
                Some(COMPOSABLE_COW)
            }
            _ => None,
        }
    }

    /// `ExtensibleFallbackHandler` deployment address on this chain, or
    /// `None` when the contract is not deployed there.
    pub const fn extensible_fallback_handler_address(self) -> Option<Address> {
        match self {
            Self::Mainnet | Self::Gnosis | Self::Sepolia | Self::ArbitrumOne => {
                Some(EXTENSIBLE_FALLBACK_HANDLER)
            }
            _ => None,
        }
    }

    /// `CurrentBlockTimestampFactory` deployment address on this chain,
    /// or `None` when the contract is not deployed there.
    pub const fn current_block_timestamp_factory_address(self) -> Option<Address> {
        match self {
            Self::Mainnet | Self::Gnosis | Self::Sepolia | Self::ArbitrumOne => {
                Some(CURRENT_BLOCK_TIMESTAMP_FACTORY)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, Bytes, U256, hex};
    use alloy_sol_types::SolValue;

    use super::*;

    #[test]
    fn conditional_order_params_round_trips_via_abi() {
        let params = ConditionalOrderParams {
            handler: COMPOSABLE_COW,
            salt: B256::from(hex!(
                "0101010101010101010101010101010101010101010101010101010101010101"
            )),
            staticInput: Bytes::from_static(&hex!("deadbeef")),
        };
        let encoded = params.abi_encode();
        let decoded = ConditionalOrderParams::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.handler, params.handler);
        assert_eq!(decoded.salt, params.salt);
        assert_eq!(decoded.staticInput, params.staticInput);
    }

    #[test]
    fn proof_round_trips_via_abi() {
        let proof = Proof {
            location: U256::from(0_u64),
            data: Bytes::from_static(b"hello"),
        };
        let encoded = proof.abi_encode();
        let decoded = Proof::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.location, proof.location);
        assert_eq!(decoded.data, proof.data);
    }

    #[test]
    fn poll_outcome_variants_construct() {
        let _ = PollOutcome::OrderNotValid("bad token".into());
        let _ = PollOutcome::TryNextBlock("retry".into());
        let _ = PollOutcome::TryAtBlock {
            block: 100,
            reason: "later".into(),
        };
        let _ = PollOutcome::TryAtEpoch {
            timestamp: 1_700_000_000,
            reason: "wait".into(),
        };
        let _ = PollOutcome::Never("dead".into());
    }

    #[test]
    fn composable_cow_deployed_on_supported_chains() {
        for chain in [
            Chain::Mainnet,
            Chain::Gnosis,
            Chain::Sepolia,
            Chain::ArbitrumOne,
        ] {
            assert_eq!(chain.composable_cow_address(), Some(COMPOSABLE_COW));
            assert_eq!(
                chain.extensible_fallback_handler_address(),
                Some(EXTENSIBLE_FALLBACK_HANDLER)
            );
            assert_eq!(
                chain.current_block_timestamp_factory_address(),
                Some(CURRENT_BLOCK_TIMESTAMP_FACTORY)
            );
        }
    }

    #[test]
    fn composable_cow_absent_on_unsupported_chains() {
        for chain in [
            Chain::Bnb,
            Chain::Polygon,
            Chain::Base,
            Chain::Plasma,
            Chain::Avalanche,
            Chain::Ink,
            Chain::Linea,
        ] {
            assert!(chain.composable_cow_address().is_none());
            assert!(chain.extensible_fallback_handler_address().is_none());
            assert!(chain.current_block_timestamp_factory_address().is_none());
        }
    }
}
