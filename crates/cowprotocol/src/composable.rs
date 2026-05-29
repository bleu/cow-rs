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
//! [`cowprotocol/composable-cow`][cc].
//!
//! [cc]: https://github.com/cowprotocol/composable-cow

use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};

use crate::chain::Chain;
use crate::contracts::{GPV2_ORDER_TYPE_HASH, GPv2OrderData};

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

    /// Per-part static input for the canonical `TWAP` handler.
    ///
    /// Mirrors `TWAPOrder.Data` in
    /// [`composable-cow/src/types/twap/libraries/TWAPOrder.sol`][src].
    /// All ten fields are static, so ABI-encoding the struct produces
    /// `10 * 32 = 320` bytes that match
    /// `eth_abi.encode(["(address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,bytes32)"], [[...]])`
    /// byte for byte (cow-py's `Twap.encode_static_input`).
    ///
    /// [src]: https://github.com/cowprotocol/composable-cow/blob/main/src/types/twap/libraries/TWAPOrder.sol
    #[derive(Debug, Eq, Hash, PartialEq)]
    struct TwapStaticInput {
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

    /// Pointer to off-chain merkle proofs, recorded by
    /// `ComposableCoW.setRoot` so watch-towers know where to fetch the
    /// leaf proofs from. `location` is declared as a plain `uint256`
    /// upstream (`ComposableCoW.sol`); callers pass a `ProofLocation`
    /// enum value widened to `uint256`. Typing it as `U256` here is what
    /// makes the `setRoot` / `setRootWithContext` selectors and
    /// [`MerkleRootSet::SIGNATURE_HASH`] hash `(uint256,bytes)`, the form
    /// the contract decodes against and emits.
    #[derive(Debug, Eq, Hash, PartialEq)]
    struct Proof {
        uint256 location;
        bytes data;
    }

    /// Off-chain payload that accompanies one tradeable order pulled out
    /// of a merkle-rooted registration. Mirrors
    /// `ComposableCoW.PayloadStruct` (`ComposableCoW.sol`):
    /// `proof` is the merkle proof (sibling hashes) for the order's leaf,
    /// `params` the 3-tuple identifying it, and `offchainInput` the
    /// dynamic input the handler reads at poll time. Field order matches
    /// the Solidity struct so [`SolValue::abi_encode`] is byte-equal to
    /// `abi.encode(PayloadStruct(...))`.
    #[derive(Debug, Eq, Hash, PartialEq)]
    struct PayloadStruct {
        bytes32[] proof;
        ConditionalOrderParams params;
        bytes offchainInput;
    }

    /// Events and function signatures of the [`ComposableCoW`] singleton.
    ///
    /// Source:
    /// [`ComposableCoW.sol`](https://github.com/cowprotocol/composable-cow/blob/main/src/ComposableCoW.sol).
    /// Off-chain indexers and watch-towers match on the three topic
    /// hashes here to track owner registrations, merkle-root updates and
    /// swap-guard toggles; integrators use the `*Call` types generated
    /// by [`alloy_sol_types::sol`] to assemble transactions against the
    /// contract.
    ///
    /// `getTradeableOrderWithSignature` is deliberately omitted as a
    /// `sol!` function: its return type references `GPv2Order.Data` from
    /// `GPv2Order.sol`, already declared in [`crate::contracts`], and a
    /// second copy here would be ABI-equivalent dead weight. The
    /// off-chain half of that flow, assembling the EIP-1271 `signature`
    /// blob, is provided instead by [`safe_handler_signature`] and
    /// [`forwarder_signature`], which bridge the two `sol!` blocks.
    #[derive(Debug)]
    interface ComposableCoW {
        // --- events ---

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

        // --- writes ---

        /// Register a single conditional order. When `dispatch` is
        /// true the contract additionally emits the
        /// [`ConditionalOrderCreated`] event so off-chain watch towers
        /// pick the order up immediately; integrators that index the
        /// event themselves can pass `false` to save the log gas.
        function create(ConditionalOrderParams params, bool dispatch) external;

        /// Same as [`create`] but additionally writes a per-owner
        /// cabinet value via `factory`. Handlers that anchor their
        /// schedule to e.g. the block timestamp at registration time
        /// (TWAP with [`TwapStart::AtMiningTime`]) need this variant;
        /// for plain registrations [`create`] is the right entry point.
        function createWithContext(
            ConditionalOrderParams params,
            address factory,
            bytes data,
            bool dispatch
        ) external;

        /// Cancel a previously-registered single conditional order.
        /// `singleOrderHash` is `keccak256(abi.encode(params))`, equal
        /// to [`ComposableCoW::hash`].
        function remove(bytes32 singleOrderHash) external;

        /// Publish a 32-byte merkle root committing to a batch of
        /// conditional orders. `proof` is the `(location, data)`
        /// pointer watch towers use to fetch the leaf proofs from
        /// off-chain storage; the location codes are documented under
        /// [`Proof`].
        function setRoot(bytes32 root, Proof proof) external;

        /// Same as [`setRoot`] but additionally writes a per-owner
        /// cabinet value via `factory`.
        function setRootWithContext(
            bytes32 root,
            Proof proof,
            address factory,
            bytes data
        ) external;

        /// Install (or remove, with `address(0)`) a guard contract
        /// that may veto otherwise-valid orders before settlement.
        function setSwapGuard(address swapGuard) external;

        // --- views ---

        /// `true` when the caller has authorised the single
        /// conditional order keyed by `singleOrderHash`. Mirrors the
        /// `singleOrders` mapping written by [`create`].
        function singleOrders(address owner, bytes32 singleOrderHash) external view returns (bool);

        /// Owner's current published merkle root, or `bytes32(0)` when
        /// none has been set. Mirrors the `roots` mapping.
        function roots(address owner) external view returns (bytes32);

        /// Owner's installed swap-guard contract, or `address(0)` when
        /// none. Mirrors the `swapGuards` mapping.
        function swapGuards(address owner) external view returns (address);

        /// Per-owner key/value storage written by
        /// [`createWithContext`] / [`setRootWithContext`]. Handlers
        /// read values back through their `valueFactory` argument; the
        /// canonical example is the block-timestamp anchor used by
        /// TWAP orders started [`TwapStart::AtMiningTime`].
        function cabinet(address owner, bytes32 ctx) external view returns (bytes32);

        /// Contract-derived hash of a `ConditionalOrderParams` triple.
        /// Equal to `keccak256(abi.encode(params))`; matches the inner
        /// keccak in [`crate::multiplexer::conditional_order_leaf`], so
        /// callers can verify their off-chain leaf matches what the
        /// contract stores.
        function hash(ConditionalOrderParams params) external pure returns (bytes32);
    }
}

sol! {
    /// `SafeSigUtils.safeSignature`, the entry point the
    /// `ExtensibleFallbackHandler` dispatches an EIP-1271 verification
    /// to. We never call it directly; the generated `*Call` type just
    /// gives us the `safeSignature(bytes32,bytes32,bytes,bytes)` selector
    /// and argument encoding `getTradeableOrderWithSignature` prepends
    /// for the handler path.
    function safeSignature(
        bytes32 domainSeparator,
        bytes32 typeHash,
        bytes encodeData,
        bytes payload
    ) external view returns (bytes4);
}

/// Assemble the EIP-1271 `signature` blob for an owner whose
/// ComposableCoW setup routes through the `ExtensibleFallbackHandler`.
///
/// Reproduces the handler branch of
/// `ComposableCoW.getTradeableOrderWithSignature` (`ComposableCoW.sol`):
///
/// ```solidity
/// abi.encodeWithSignature(
///     "safeSignature(bytes32,bytes32,bytes,bytes)",
///     domainSeparator, GPv2Order.TYPE_HASH, abi.encode(order), abi.encode(payload)
/// )
/// ```
///
/// `order` is the discrete [`GPv2OrderData`] the handler produced;
/// `domain_separator` is the settlement domain for the target chain
/// ([`crate::DomainSeparator`]). The order type hash is the constant
/// [`GPV2_ORDER_TYPE_HASH`].
pub fn safe_handler_signature(
    domain_separator: B256,
    order: &GPv2OrderData,
    payload: &PayloadStruct,
) -> Vec<u8> {
    safeSignatureCall {
        domainSeparator: domain_separator,
        typeHash: GPV2_ORDER_TYPE_HASH,
        encodeData: order.abi_encode().into(),
        payload: payload.abi_encode().into(),
    }
    .abi_encode()
}

/// Assemble the EIP-1271 `signature` blob for an owner whose
/// ComposableCoW setup uses the standalone EIP-1271 forwarder rather
/// than the Safe fallback handler.
///
/// Reproduces the forwarder branch of
/// `ComposableCoW.getTradeableOrderWithSignature`: `abi.encode(order,
/// payload)`, the two values [`GPv2OrderData`] and [`PayloadStruct`]
/// encoded as a parameter list (hence `abi_encode_params`, which matches
/// Solidity's two-argument `abi.encode`).
pub fn forwarder_signature(order: &GPv2OrderData, payload: &PayloadStruct) -> Vec<u8> {
    (order.clone(), payload.clone()).abi_encode_params()
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
/// Identical on every chain where the suite is deployed (see
/// [`Chain::supports_composable_cow`]). Source:
/// `cowprotocol/composable-cow/networks.json`.
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
    /// Whether the ComposableCoW contract suite (ComposableCoW,
    /// ExtensibleFallbackHandler, CurrentBlockTimestampFactory, TWAP
    /// handler) is deployed on this chain.
    ///
    /// The suite shares a single deployment manifest, so the per-address
    /// helpers below all gate on this predicate. The supported set
    /// mirrors `cowprotocol/composable-cow/networks.json` for the chains
    /// this crate enumerates; Lens (chain id 232) is in upstream but not
    /// yet in [`Chain`], so it is deferred.
    pub const fn supports_composable_cow(self) -> bool {
        matches!(
            self,
            Self::Mainnet
                | Self::Bnb
                | Self::Gnosis
                | Self::Sepolia
                | Self::ArbitrumOne
                | Self::Linea
                | Self::Plasma
        )
    }

    /// `ComposableCoW` deployment address on this chain, or `None` when
    /// the contract is not deployed there.
    pub const fn composable_cow_address(self) -> Option<Address> {
        if self.supports_composable_cow() {
            Some(COMPOSABLE_COW)
        } else {
            None
        }
    }

    /// `ExtensibleFallbackHandler` deployment address on this chain, or
    /// `None` when the contract is not deployed there.
    pub const fn extensible_fallback_handler_address(self) -> Option<Address> {
        if self.supports_composable_cow() {
            Some(EXTENSIBLE_FALLBACK_HANDLER)
        } else {
            None
        }
    }

    /// `CurrentBlockTimestampFactory` deployment address on this chain,
    /// or `None` when the contract is not deployed there.
    pub const fn current_block_timestamp_factory_address(self) -> Option<Address> {
        if self.supports_composable_cow() {
            Some(CURRENT_BLOCK_TIMESTAMP_FACTORY)
        } else {
            None
        }
    }
}

/// Canonical CREATE2 address of the `TWAP` handler, identical on every
/// chain where the ComposableCoW suite is deployed.
///
/// Source: `composable-cow/networks.json` and cow-py's
/// `TWAP_ADDRESS` (`cowdao_cowpy/composable/order_types/twap.py:24`).
pub const TWAP_HANDLER: Address = address!("0x6cF1e9cA41f7611dEf408122793c358a3d11E5a5");

/// When a TWAP becomes active.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TwapStart {
    /// Start at the block timestamp the registration is mined in. The
    /// watch tower reads the timestamp through the
    /// [`CURRENT_BLOCK_TIMESTAMP_FACTORY`].
    AtMiningTime,
    /// Start at a specific Unix timestamp (seconds). Must be in
    /// `1..u32::MAX`: `t0 = 0` is the on-chain sentinel for
    /// [`TwapStart::AtMiningTime`] and `u32::MAX` fails the handler's
    /// `t0 < type(uint32).max` guard, so [`TwapData::static_input`]
    /// rejects both with [`TwapError::InvalidEpoch`].
    AtEpoch(u32),
}

/// How long each TWAP part is fillable for, within its slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TwapDuration {
    /// Part is fillable for the full slot (`span = 0`).
    Auto,
    /// Part is fillable for the first `seconds` of its slot only; must
    /// be `<= time_between_parts` (the TWAP handler reverts otherwise).
    LimitDuration(u32),
}

/// User-facing TWAP order parameters. Mirrors `TwapData` in
/// `cowdao_cowpy/composable/order_types/twap.py`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TwapData {
    /// Token the owner sells.
    pub sell_token: Address,
    /// Token the owner buys.
    pub buy_token: Address,
    /// Receiver of the buy token. Set to the owner address for self-fills.
    pub receiver: Address,
    /// Total sell amount across every part, in atomic units. The handler
    /// is given `sell_amount / number_of_parts` per part.
    pub sell_amount: U256,
    /// Total minimum buy amount across every part, in atomic units. The
    /// handler enforces `buy_amount / number_of_parts` per part.
    pub buy_amount: U256,
    /// Seconds between part start timestamps. Must be > 0 and
    /// <= 365 days (the handler reverts outside that range).
    pub time_between_parts: u32,
    /// Number of parts. Must be > 1 (the handler reverts otherwise).
    pub number_of_parts: u32,
    /// When the TWAP becomes active.
    pub start: TwapStart,
    /// How long each part is fillable for.
    pub duration: TwapDuration,
    /// 32-byte app-data digest applied to every discrete part.
    pub app_data: B256,
}

/// Failures returned by [`TwapData::static_input`] /
/// [`TwapData::encode_static_input`] / [`TwapData::leaf_id`].
///
/// Mirrors the `OrderNotValid(string)` reverts raised by `TWAPOrder.validate`
/// in composable-cow; client-side validation lets callers reject malformed
/// TWAPs without paying the on-chain revert cost.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum TwapError {
    /// `sell_token == buy_token`.
    #[error("TWAP sell_token equals buy_token")]
    SameToken,
    /// One of the tokens is the zero address.
    #[error("TWAP token is the zero address")]
    InvalidToken,
    /// `sell_amount == 0` or doesn't divide cleanly into a non-zero
    /// per-part amount.
    #[error("TWAP sell amount is zero or does not divide cleanly across number_of_parts")]
    InvalidSellAmount,
    /// `buy_amount == 0` or doesn't divide cleanly into a non-zero
    /// per-part amount.
    #[error("TWAP buy amount is zero or does not divide cleanly across number_of_parts")]
    InvalidBuyAmount,
    /// `number_of_parts <= 1`.
    #[error("TWAP number_of_parts must be > 1")]
    InvalidNumParts,
    /// `time_between_parts == 0` or `> 365 days`.
    #[error("TWAP time_between_parts must be > 0 and <= 365 days")]
    InvalidFrequency,
    /// `LimitDuration(span)` with `span > time_between_parts`.
    #[error("TWAP LimitDuration span must be <= time_between_parts")]
    InvalidSpan,
    /// `TwapStart::AtEpoch` with a reserved value. `0` collides with the
    /// `t0 = 0` sentinel the handler uses for `AtMiningTime`; `u32::MAX`
    /// is rejected on-chain (`TWAPOrder.validate` requires
    /// `t0 < type(uint32).max`). Use a Unix timestamp in `1..u32::MAX` or
    /// switch to `TwapStart::AtMiningTime`.
    #[error("TWAP AtEpoch must be in 1..u32::MAX (0 and u32::MAX are reserved)")]
    InvalidEpoch,
}

const TWAP_MAX_FREQUENCY_SECONDS: u32 = 365 * 24 * 60 * 60;

impl TwapData {
    /// Validate the parameters and lower to the canonical
    /// [`TwapStaticInput`] the handler sees, splitting the total amounts
    /// across `number_of_parts`.
    pub fn static_input(&self) -> Result<TwapStaticInput, TwapError> {
        if self.sell_token == self.buy_token {
            return Err(TwapError::SameToken);
        }
        if self.sell_token == Address::ZERO || self.buy_token == Address::ZERO {
            return Err(TwapError::InvalidToken);
        }
        if self.number_of_parts <= 1 {
            return Err(TwapError::InvalidNumParts);
        }
        if self.time_between_parts == 0 || self.time_between_parts > TWAP_MAX_FREQUENCY_SECONDS {
            return Err(TwapError::InvalidFrequency);
        }
        let span = match self.duration {
            TwapDuration::Auto => 0,
            TwapDuration::LimitDuration(s) => {
                if s > self.time_between_parts {
                    return Err(TwapError::InvalidSpan);
                }
                s
            }
        };
        let t0 = match self.start {
            TwapStart::AtMiningTime => 0,
            // `0` collides with the AtMiningTime sentinel; `u32::MAX` is
            // rejected by the on-chain `t0 < type(uint32).max` guard.
            TwapStart::AtEpoch(0 | u32::MAX) => return Err(TwapError::InvalidEpoch),
            TwapStart::AtEpoch(s) => s,
        };
        let n = U256::from(self.number_of_parts);
        // Floor-division would silently discard the remainder and let
        // the aggregate min-buy / max-sell drift below user intent
        // (e.g. `buy_amount = 101, n = 10` ⇒ `minPartLimit = 10`,
        // aggregate floor 100). Reject indivisible totals so the
        // signed leaf matches the user's stated amounts exactly.
        let part_sell_amount = self.sell_amount / n;
        let min_part_limit = self.buy_amount / n;
        if part_sell_amount.is_zero() || self.sell_amount % n != U256::ZERO {
            return Err(TwapError::InvalidSellAmount);
        }
        if min_part_limit.is_zero() || self.buy_amount % n != U256::ZERO {
            return Err(TwapError::InvalidBuyAmount);
        }
        Ok(TwapStaticInput {
            sellToken: self.sell_token,
            buyToken: self.buy_token,
            receiver: self.receiver,
            partSellAmount: part_sell_amount,
            minPartLimit: min_part_limit,
            t0: U256::from(t0),
            n,
            t: U256::from(self.time_between_parts),
            span: U256::from(span),
            appData: self.app_data,
        })
    }

    /// Validate the parameters and ABI-encode the canonical static input.
    /// Locked byte-exact against cow-py via the
    /// `twap_leaf_id_matches_cow_py_vector` test.
    pub fn encode_static_input(&self) -> Result<Vec<u8>, TwapError> {
        Ok(self.static_input()?.abi_encode())
    }

    /// Wrap into a [`ConditionalOrderParams`] with the canonical
    /// [`TWAP_HANDLER`] address. Allocates owned bytes from a `&self`
    /// view, hence the `to_` prefix per Rust API conventions.
    pub fn to_params(&self, salt: B256) -> Result<ConditionalOrderParams, TwapError> {
        Ok(ConditionalOrderParams {
            handler: TWAP_HANDLER,
            salt,
            staticInput: Bytes::from(self.encode_static_input()?),
        })
    }

    /// Compute the canonical leaf id
    /// `keccak256(abi.encode(ConditionalOrderParams))` for this TWAP and
    /// salt. Matches `ConditionalOrder.id` in cow-py.
    pub fn leaf_id(&self, salt: B256) -> Result<B256, TwapError> {
        Ok(keccak256(self.to_params(salt)?.abi_encode()))
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, Bytes, U256, hex, keccak256};
    use alloy_sol_types::{SolCall, SolEvent, SolValue};

    use super::*;

    /// Locks `keccak256(abi.encode(ConditionalOrderParams))` against the
    /// `ConditionalOrder.id` vector lifted from
    /// `cowdao-grants/cow-py::tests/composable/test_conditional_order.py:119`.
    /// This is the canonical single-order leaf-id derivation; if our ABI
    /// encoding ever drifts from cow-py / Solidity, the id mismatches.
    #[test]
    fn conditional_order_leaf_id_matches_cow_py_vector() {
        let params = ConditionalOrderParams {
            handler: address!("910d00a310f7Dc5B29FE73458F47f519be547D3d"),
            salt: B256::from(hex!(
                "9379a0bf532ff9a66ffde940f94b1a025d6f18803054c1aef52dc94b15255bbe"
            )),
            staticInput: Bytes::new(),
        };
        let id = keccak256(params.abi_encode());
        assert_eq!(
            id.0,
            hex!("88ca0698d8c5500b31015d84fa0166272e1812320d9af8b60e29ae00153363b3"),
        );
    }

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
            location: U256::ZERO,
            data: Bytes::from_static(b"hello"),
        };
        let encoded = proof.abi_encode();
        let decoded = Proof::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.location, proof.location);
        assert_eq!(decoded.data, proof.data);
    }

    fn sample_order_and_payload() -> (GPv2OrderData, PayloadStruct) {
        let order = GPv2OrderData {
            sellToken: address!("6810e776880C02933D47DB1b9fc05908e5386b96"),
            buyToken: address!("DAE5F1590db13E3B40423B5b5c5fbf175515910b"),
            receiver: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            sellAmount: U256::from(1_000_u64),
            buyAmount: U256::from(2_000_u64),
            validTo: 1_700_000_000,
            appData: B256::repeat_byte(0xaa),
            feeAmount: U256::ZERO,
            kind: B256::repeat_byte(0xbb),
            partiallyFillable: false,
            sellTokenBalance: B256::repeat_byte(0xcc),
            buyTokenBalance: B256::repeat_byte(0xdd),
        };
        let payload = PayloadStruct {
            proof: vec![B256::repeat_byte(0x22), B256::repeat_byte(0x33)],
            params: ConditionalOrderParams {
                handler: TWAP_HANDLER,
                salt: B256::repeat_byte(0x11),
                staticInput: Bytes::from_static(&hex!("c0ffee")),
            },
            offchainInput: Bytes::from_static(b"offchain"),
        };
        (order, payload)
    }

    /// The ExtensibleFallbackHandler blob must be
    /// `safeSignature` selector + `abi.encode(domain, TYPE_HASH,
    /// abi.encode(order), abi.encode(payload))`, matching
    /// `ComposableCoW.getTradeableOrderWithSignature`.
    #[test]
    fn safe_handler_signature_matches_encode_with_signature() {
        let (order, payload) = sample_order_and_payload();
        let domain = B256::repeat_byte(0x44);
        let blob = safe_handler_signature(domain, &order, &payload);

        assert_eq!(&blob[..4], &safeSignatureCall::SELECTOR);
        let decoded = safeSignatureCall::abi_decode(&blob).unwrap();
        assert_eq!(decoded.domainSeparator, domain);
        assert_eq!(decoded.typeHash, GPV2_ORDER_TYPE_HASH);
        assert_eq!(decoded.encodeData.as_ref(), order.abi_encode().as_slice());
        assert_eq!(decoded.payload.as_ref(), payload.abi_encode().as_slice());
    }

    /// The forwarder blob must be `abi.encode(order, payload)`: the two
    /// values decode back as a parameter list.
    #[test]
    fn forwarder_signature_round_trips_order_and_payload() {
        let (order, payload) = sample_order_and_payload();
        let blob = forwarder_signature(&order, &payload);

        let (decoded_order, decoded_payload) =
            <(GPv2OrderData, PayloadStruct)>::abi_decode_params(&blob).unwrap();
        assert_eq!(decoded_order.sellToken, order.sellToken);
        assert_eq!(decoded_order.buyTokenBalance, order.buyTokenBalance);
        assert_eq!(decoded_payload, payload);
    }

    /// Function selectors must equal the `keccak256(signature)[..4]` the
    /// `ComposableCoW` contract decodes against. The signatures hard-coded
    /// here are the canonical strings cow-py and the
    /// `cowprotocol/composable-cow` test suite use; a typo in any `sol!`
    /// field name or order would break this lock.
    #[test]
    fn composable_cow_selectors_match_keccak() {
        let cases: &[(&[u8; 4], &[u8])] = &[
            (
                &ComposableCoW::createCall::SELECTOR,
                b"create((address,bytes32,bytes),bool)",
            ),
            (
                &ComposableCoW::createWithContextCall::SELECTOR,
                b"createWithContext((address,bytes32,bytes),address,bytes,bool)",
            ),
            (&ComposableCoW::removeCall::SELECTOR, b"remove(bytes32)"),
            (
                &ComposableCoW::setRootCall::SELECTOR,
                b"setRoot(bytes32,(uint256,bytes))",
            ),
            (
                &ComposableCoW::setRootWithContextCall::SELECTOR,
                b"setRootWithContext(bytes32,(uint256,bytes),address,bytes)",
            ),
            (
                &ComposableCoW::setSwapGuardCall::SELECTOR,
                b"setSwapGuard(address)",
            ),
            (
                &ComposableCoW::singleOrdersCall::SELECTOR,
                b"singleOrders(address,bytes32)",
            ),
            (&ComposableCoW::rootsCall::SELECTOR, b"roots(address)"),
            (
                &ComposableCoW::swapGuardsCall::SELECTOR,
                b"swapGuards(address)",
            ),
            (
                &ComposableCoW::cabinetCall::SELECTOR,
                b"cabinet(address,bytes32)",
            ),
            (
                &ComposableCoW::hashCall::SELECTOR,
                b"hash((address,bytes32,bytes))",
            ),
        ];
        for (selector, signature) in cases {
            let expected = &keccak256(signature)[..4];
            assert_eq!(
                selector.as_slice(),
                expected,
                "selector for {} does not match keccak256(signature)",
                std::str::from_utf8(signature).unwrap(),
            );
        }
    }

    /// `setRoot(root, (location, data))` must round-trip back to the
    /// same fields and start with the canonical selector. Locks the
    /// publish-merkle-root path the multiplexer flow depends on.
    #[test]
    fn set_root_call_round_trips() {
        let root = B256::from(hex!(
            "abababababababababababababababababababababababababababababababab"
        ));
        let proof = Proof {
            location: U256::from(1),
            data: Bytes::from_static(b"ipfs://bafy"),
        };
        let call = ComposableCoW::setRootCall {
            root,
            proof: proof.clone(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], &ComposableCoW::setRootCall::SELECTOR);
        let decoded = ComposableCoW::setRootCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.root, root);
        assert_eq!(decoded.proof.location, proof.location);
        assert_eq!(decoded.proof.data, proof.data);
    }

    /// `create((handler, salt, staticInput), dispatch)` round-trips and
    /// keeps the selector. Locks the single-order registration call,
    /// the most common write integrators issue.
    #[test]
    fn create_call_round_trips() {
        let params = ConditionalOrderParams {
            handler: TWAP_HANDLER,
            salt: B256::from(hex!(
                "0202020202020202020202020202020202020202020202020202020202020202"
            )),
            staticInput: Bytes::from_static(&hex!("c0ffee")),
        };
        let call = ComposableCoW::createCall {
            params: params.clone(),
            dispatch: true,
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], &ComposableCoW::createCall::SELECTOR);
        let decoded = ComposableCoW::createCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.params.handler, params.handler);
        assert_eq!(decoded.params.salt, params.salt);
        assert_eq!(decoded.params.staticInput, params.staticInput);
        assert!(decoded.dispatch);
    }

    /// `hash(params)` is a view: its selector must match
    /// `crate::multiplexer::conditional_order_leaf` only after the
    /// outer keccak. Locks that the function signature the contract
    /// dispatches against agrees with the inner half of the leaf
    /// derivation.
    #[test]
    fn hash_call_selector_matches_inner_leaf_derivation() {
        let inner_signature = b"hash((address,bytes32,bytes))";
        assert_eq!(
            &ComposableCoW::hashCall::SELECTOR,
            &keccak256(inner_signature)[..4]
        );
    }

    /// Pin the `ComposableCoW` deployment hex literals so a copy-paste
    /// regression on the constants breaks the build, and confirm the
    /// supported / unsupported chain split documented in
    /// `cowprotocol/composable-cow/networks.json`.
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
        assert_eq!(
            TWAP_HANDLER,
            address!("6cF1e9cA41f7611dEf408122793c358a3d11E5a5")
        );

        // Every supported chain shares the canonical singleton addresses
        // (CREATE2, same salt + bytecode), including the TWAP handler.
        for chain in [
            Chain::Mainnet,
            Chain::Bnb,
            Chain::Gnosis,
            Chain::Sepolia,
            Chain::ArbitrumOne,
            Chain::Linea,
            Chain::Plasma,
        ] {
            assert!(chain.supports_composable_cow());
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
        for chain in [Chain::Polygon, Chain::Base, Chain::Avalanche, Chain::Ink] {
            assert!(chain.composable_cow_address().is_none());
        }
    }

    /// `ComposableCoW` event topic hashes must match the canonical
    /// `keccak256(signature)` values so off-chain indexers matching
    /// `log.topics[0]` against these Rust constants pick up every
    /// emitted event.
    #[test]
    fn composable_cow_event_topic_hashes_match_keccak() {
        // MerkleRootSet(address,bytes32,(uint256,bytes)). `Proof.location`
        // is a plain `uint256` upstream, so the tuple hashes as
        // `(uint256,bytes)`; this is the topic the contract emits.
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

    /// Locks the TWAP leaf-id derivation against cow-py's canonical
    /// vector at `cow-py::tests/composable/order_types/test_twap.py:23`.
    /// If `TwapStaticInput::abi_encode` ever drifts from
    /// `eth_abi.encode("(address,...,bytes32)", ...)`, the id mismatches
    /// and the watch tower can't find the order.
    #[test]
    fn twap_leaf_id_matches_cow_py_vector() {
        let twap = TwapData {
            sell_token: address!("6810e776880C02933D47DB1b9fc05908e5386b96"),
            buy_token: address!("DAE5F1590db13E3B40423B5b5c5fbf175515910b"),
            receiver: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            sell_amount: U256::from(1_000_000_000_000_000_000_u128),
            buy_amount: U256::from(1_000_000_000_000_000_000_u128),
            time_between_parts: 3600,
            number_of_parts: 10,
            start: TwapStart::AtMiningTime,
            duration: TwapDuration::Auto,
            app_data: B256::from(hex!(
                "d51f28edffcaaa76be4a22f6375ad289272c037f3cc072345676e88d92ced8b5"
            )),
        };
        let salt = B256::from(hex!(
            "d98a87ed4e45bfeae3f779e1ac09ceacdfb57da214c7fffa6434aeb969f396c0"
        ));
        let id = twap.leaf_id(salt).unwrap();
        assert_eq!(
            id.0,
            hex!("d8a6889486a47d8ca8f4189f11573b39dbc04f605719ebf4050e44ae53c1bedf"),
        );

        // Second cow-py vector with a different salt; same TwapData
        // produces a different id, confirming the salt path.
        let salt2 = B256::from(hex!(
            "d98a87ed4e45bfeae3f779e1ac09ceacdfb57da214c7fffa6434aeb969f396c1"
        ));
        let id2 = twap.leaf_id(salt2).unwrap();
        assert_eq!(
            id2.0,
            hex!("8ddb7e8e1cd6a06d5bb6f91af21a2b26a433a5d8402ccddb00a72e4006c46994"),
        );
    }

    /// Validation must reject parameter combinations the on-chain
    /// `TWAPOrder.validate` reverts on.
    #[test]
    fn twap_validation_rejects_invalid_parameters() {
        let base = TwapData {
            sell_token: address!("6810e776880C02933D47DB1b9fc05908e5386b96"),
            buy_token: address!("DAE5F1590db13E3B40423B5b5c5fbf175515910b"),
            receiver: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            sell_amount: U256::from(1_000_000_000_000_000_000_u128),
            buy_amount: U256::from(1_000_000_000_000_000_000_u128),
            time_between_parts: 3600,
            number_of_parts: 10,
            start: TwapStart::AtMiningTime,
            duration: TwapDuration::Auto,
            app_data: B256::ZERO,
        };
        assert!(base.static_input().is_ok());

        let mut same_token = base;
        same_token.buy_token = base.sell_token;
        assert_eq!(same_token.static_input().unwrap_err(), TwapError::SameToken);

        let mut zero_sell = base;
        zero_sell.sell_token = alloy_primitives::Address::ZERO;
        assert_eq!(
            zero_sell.static_input().unwrap_err(),
            TwapError::InvalidToken
        );

        let mut one_part = base;
        one_part.number_of_parts = 1;
        assert_eq!(
            one_part.static_input().unwrap_err(),
            TwapError::InvalidNumParts
        );

        let mut zero_freq = base;
        zero_freq.time_between_parts = 0;
        assert_eq!(
            zero_freq.static_input().unwrap_err(),
            TwapError::InvalidFrequency
        );

        let mut excess_span = base;
        excess_span.duration = TwapDuration::LimitDuration(7200);
        assert_eq!(
            excess_span.static_input().unwrap_err(),
            TwapError::InvalidSpan
        );

        let mut tiny_sell = base;
        tiny_sell.sell_amount = U256::from(5_u64); // 5 / 10 = 0
        assert_eq!(
            tiny_sell.static_input().unwrap_err(),
            TwapError::InvalidSellAmount
        );

        // Indivisible totals must be rejected so the signed leaf
        // matches user intent: 101 / 10 floors to a per-part 10 and
        // an aggregate min-buy of 100, one unit below what the user
        // asked for.
        let mut indivisible_sell = base;
        indivisible_sell.sell_amount = U256::from(101_u64);
        assert_eq!(
            indivisible_sell.static_input().unwrap_err(),
            TwapError::InvalidSellAmount
        );
        let mut indivisible_buy = base;
        indivisible_buy.buy_amount = U256::from(101_u64);
        assert_eq!(
            indivisible_buy.static_input().unwrap_err(),
            TwapError::InvalidBuyAmount
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

    /// `TwapStart::AtEpoch(0)` collides with the `t0 = 0` sentinel the
    /// on-chain handler reserves for `AtMiningTime`. Reject it so the
    /// leaf id and registered order match caller intent.
    #[test]
    fn twap_at_epoch_zero_rejected() {
        let twap = TwapData {
            sell_token: address!("6810e776880C02933D47DB1b9fc05908e5386b96"),
            buy_token: address!("DAE5F1590db13E3B40423B5b5c5fbf175515910b"),
            receiver: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            sell_amount: U256::from(1_000_000_000_000_000_000_u128),
            buy_amount: U256::from(1_000_000_000_000_000_000_u128),
            time_between_parts: 3600,
            number_of_parts: 10,
            start: TwapStart::AtEpoch(0),
            duration: TwapDuration::Auto,
            app_data: B256::ZERO,
        };
        assert_eq!(twap.static_input().unwrap_err(), TwapError::InvalidEpoch);

        // `u32::MAX` fails the on-chain `t0 < type(uint32).max` guard.
        let mut at_max = twap;
        at_max.start = TwapStart::AtEpoch(u32::MAX);
        assert_eq!(at_max.static_input().unwrap_err(), TwapError::InvalidEpoch);

        // A timestamp just under the cap is accepted.
        let mut just_under = twap;
        just_under.start = TwapStart::AtEpoch(u32::MAX - 1);
        assert!(just_under.static_input().is_ok());
    }

    /// `AtMiningTime` legitimately encodes to `t0 = 0`: this lock-in
    /// guards against anyone "fixing" the sentinel branch to also
    /// reject zero, which would break the cabinet-anchored flow.
    #[test]
    fn twap_at_mining_time_still_encodes_t0_zero() {
        let twap = TwapData {
            sell_token: address!("6810e776880C02933D47DB1b9fc05908e5386b96"),
            buy_token: address!("DAE5F1590db13E3B40423B5b5c5fbf175515910b"),
            receiver: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            sell_amount: U256::from(1_000_000_000_000_000_000_u128),
            buy_amount: U256::from(1_000_000_000_000_000_000_u128),
            time_between_parts: 3600,
            number_of_parts: 10,
            start: TwapStart::AtMiningTime,
            duration: TwapDuration::Auto,
            app_data: B256::ZERO,
        };
        assert_eq!(twap.static_input().unwrap().t0, U256::ZERO);
    }

    /// The rejection is exact to the zero sentinel: any non-zero
    /// `AtEpoch(s)` round-trips into `t0 = s`.
    #[test]
    fn twap_at_epoch_one_round_trips() {
        let twap = TwapData {
            sell_token: address!("6810e776880C02933D47DB1b9fc05908e5386b96"),
            buy_token: address!("DAE5F1590db13E3B40423B5b5c5fbf175515910b"),
            receiver: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            sell_amount: U256::from(1_000_000_000_000_000_000_u128),
            buy_amount: U256::from(1_000_000_000_000_000_000_u128),
            time_between_parts: 3600,
            number_of_parts: 10,
            start: TwapStart::AtEpoch(1),
            duration: TwapDuration::Auto,
            app_data: B256::ZERO,
        };
        assert_eq!(twap.static_input().unwrap().t0, U256::from(1u32));
    }
}
