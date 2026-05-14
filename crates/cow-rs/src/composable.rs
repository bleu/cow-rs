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

    /// Events emitted by the [`ComposableCoW`] singleton.
    ///
    /// Source:
    /// [`ComposableCoW.sol`](https://github.com/nullislabs/composable-cow/blob/main/src/ComposableCoW.sol).
    /// Off-chain indexers and watch-towers match on the three topic
    /// hashes here to track owner registrations, merkle-root updates and
    /// swap-guard toggles.
    #[derive(Debug)]
    interface ComposableCoW {
        /// Emitted by `setRoot` / `setRootWithContext` whenever an
        /// owner publishes a new merkle root committing to a batch of
        /// conditional orders.
        event MerkleRootSet(address indexed owner, bytes32 root, Proof proof);

        /// Emitted by `create` / `createWithContext` when an owner
        /// authorises a single conditional order. Watch-towers index
        /// `params` to know the handler / salt / staticInput they will
        /// poll on subsequent blocks.
        event ConditionalOrderCreated(
            address indexed owner,
            ConditionalOrderParams params
        );

        /// Emitted by `setSwapGuard` when an owner installs (or
        /// removes, with `address(0)`) a guard contract that may veto
        /// otherwise-valid orders before settlement.
        event SwapGuardSet(address indexed owner, address swapGuard);
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
    use alloy_primitives::{B256, Bytes, U256, hex, keccak256};
    use alloy_sol_types::{SolEvent, SolValue};

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

    /// Pin the `ComposableCoW` deployment hex literals so a copy-paste
    /// regression on the constants breaks the build, and confirm the
    /// supported / unsupported chain split documented in
    /// `nullislabs/composable-cow/networks.json`.
    #[test]
    fn composable_cow_addresses_match_canonical_deployment() {
        assert_eq!(
            COMPOSABLE_COW,
            address!("fdaFc9d1902f4e0b84f65F49f244b32b31013b74")
        );
        assert_eq!(
            EXTENSIBLE_FALLBACK_HANDLER,
            address!("2f55e8b20D0B9FEFA187AA7d00B6Cbe563605bF5")
        );
        assert_eq!(
            CURRENT_BLOCK_TIMESTAMP_FACTORY,
            address!("52eD56Da04309Aca4c3FECC595298d80C2f16BAc")
        );

        for chain in [
            Chain::Mainnet,
            Chain::Gnosis,
            Chain::Sepolia,
            Chain::ArbitrumOne,
        ] {
            assert_eq!(chain.composable_cow_address(), Some(COMPOSABLE_COW));
        }
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
        }
    }

    /// `ComposableCoW` event topic hashes must match the canonical
    /// `keccak256(signature)` values so off-chain indexers matching
    /// `log.topics[0]` against these Rust constants pick up every
    /// emitted event.
    #[test]
    fn composable_cow_event_topic_hashes_match_keccak() {
        // MerkleRootSet(address,bytes32,(uint256,bytes))
        assert_eq!(
            ComposableCoW::MerkleRootSet::SIGNATURE_HASH,
            keccak256("MerkleRootSet(address,bytes32,(uint256,bytes))")
        );
        // ConditionalOrderCreated(address,(address,bytes32,bytes))
        assert_eq!(
            ComposableCoW::ConditionalOrderCreated::SIGNATURE_HASH,
            keccak256("ConditionalOrderCreated(address,(address,bytes32,bytes))")
        );
        // SwapGuardSet(address,address)
        assert_eq!(
            ComposableCoW::SwapGuardSet::SIGNATURE_HASH,
            keccak256("SwapGuardSet(address,address)")
        );
    }

    /// `ConditionalOrderCreated` log round-trips: encode the data
    /// segment carrying the embedded `ConditionalOrderParams` tuple,
    /// decode it back, and verify the params survive.
    #[test]
    fn conditional_order_created_event_data_round_trips() {
        let params = ConditionalOrderParams {
            handler: COMPOSABLE_COW,
            salt: B256::from(hex!(
                "0202020202020202020202020202020202020202020202020202020202020202"
            )),
            staticInput: Bytes::from_static(b"static-payload"),
        };
        let event = ComposableCoW::ConditionalOrderCreated {
            owner: alloy_primitives::address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            params: params.clone(),
        };
        let data = event.encode_data();
        let decoded = ComposableCoW::ConditionalOrderCreated::abi_decode_data(&data).unwrap();
        // The non-indexed field is just `params`; abi_decode_data returns
        // a 1-tuple for a single non-indexed argument.
        assert_eq!(decoded.0, params);
    }
}
