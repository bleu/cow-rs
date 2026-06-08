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
//! land in follow-up modules; the canonical `TWAP` handler is the first,
//! in [`TwapData`]. The canonical Solidity sources live in
//! [`cowprotocol/composable-cow`][cc].
//!
//! [cc]: https://github.com/cowprotocol/composable-cow

mod twap;

pub use twap::*;

use alloy_primitives::{Address, B256, address};
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

    /// `addr` when the ComposableCoW suite is deployed on this chain,
    /// `None` otherwise. The whole suite shares one deployment manifest,
    /// so every per-contract accessor below gates on the same predicate.
    const fn deployed(self, addr: Address) -> Option<Address> {
        if self.supports_composable_cow() {
            Some(addr)
        } else {
            None
        }
    }

    /// `ComposableCoW` deployment address on this chain, or `None` when
    /// the contract is not deployed there.
    pub const fn composable_cow_address(self) -> Option<Address> {
        self.deployed(COMPOSABLE_COW)
    }

    /// `ExtensibleFallbackHandler` deployment address on this chain, or
    /// `None` when the contract is not deployed there.
    pub const fn extensible_fallback_handler_address(self) -> Option<Address> {
        self.deployed(EXTENSIBLE_FALLBACK_HANDLER)
    }

    /// `CurrentBlockTimestampFactory` deployment address on this chain,
    /// or `None` when the contract is not deployed there.
    pub const fn current_block_timestamp_factory_address(self) -> Option<Address> {
        self.deployed(CURRENT_BLOCK_TIMESTAMP_FACTORY)
    }

    /// `TWAP` handler deployment address on this chain, or `None` when
    /// the contract is not deployed there.
    pub const fn twap_handler_address(self) -> Option<Address> {
        self.deployed(TWAP_HANDLER)
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
            assert_eq!(chain.twap_handler_address(), Some(TWAP_HANDLER));
        }
        for chain in [Chain::Polygon, Chain::Base, Chain::Avalanche] {
            assert!(chain.composable_cow_address().is_none());
            assert!(chain.twap_handler_address().is_none());
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
}
