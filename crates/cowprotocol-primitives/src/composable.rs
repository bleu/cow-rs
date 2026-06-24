//! ComposableCoW conditional orders.
//!
//! `ComposableCoW` is mfw78's CoW Protocol extension that turns the
//! `GPv2Order` primitive into a discrete instantiation of a longer-lived
//! conditional order. A registered order is identified by a 3-tuple
//! `(handler, salt, staticInput)` ([`ConditionalOrderParams`]); a watch
//! tower polls the handler on every block and either gets back a
//! discrete `GPv2Order` to submit or one of the custom-error signals
//! declared in `IConditionalOrder.sol`.
//!
//! Two layers live here:
//!
//! - [`ConditionalOrderParams`]: the 3-tuple ABI-encoded the same way as
//!   the Solidity counterpart, suitable for `ComposableCoW.create` and
//!   for hashing into the single-order or merkle-root index.
//! - [`Proof`]: the `(location, data)` pointer the contract stores
//!   alongside a merkle root in `ComposableCoW.setRoot`.
//!   [`ProofLocation`] enumerates the conventional values of the
//!   `location` field and [`Proof::new`] builds the pair from them.
//!
//! Handler-specific `staticInput` payloads (TWAP, GoodAfterTime, etc.)
//! land in follow-up modules; the canonical `TWAP` handler is the first,
//! in [`TwapData`]. The canonical Solidity sources live in
//! [`cowprotocol/composable-cow`][cc].
//!
//! [cc]: https://github.com/cowprotocol/composable-cow

mod twap;

pub use twap::*;

use alloy_primitives::{Address, B256, Bytes, U256, address};
use alloy_sol_types::{SolCall, SolError, SolEvent, SolValue, sol};

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
    /// upstream (`ComposableCoW.sol`); callers pass a [`ProofLocation`]
    /// enum value widened to `uint256`, which [`Proof::new`] does for
    /// them. Typing it as `U256` here is what
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

        /// Additive companion to [`ComposableCoW::ConditionalOrderCreated`],
        /// emitted alongside it in `create()` / `createWithContext()`
        /// whenever `dispatch == true`. The indexed `handler` and `ctx`
        /// (`= H(params)`) let watch towers and indexers filter at the
        /// RPC level: an `eth_subscribe logs` subscription with
        /// `topics: [REGISTERED_HASH, null, handlerAddr]` only delivers
        /// orders for one handler (TWAP, GoodAfterTime, ...). The
        /// existing [`ComposableCoW::ConditionalOrderCreated`] signature
        /// is intentionally untouched so indexers keyed on its topic-0
        /// hash continue to work.
        ///
        /// Topic-0 is
        /// `keccak256("ConditionalOrderRegistered(address,address,bytes32,(address,bytes32,bytes))")`,
        /// locked by `composable_cow_event_topic_hashes_match_keccak`.
        /// Source: `composable-cow/src/ComposableCoW.sol`
        ///.
        event ConditionalOrderRegistered(
            address indexed owner,
            address indexed handler,
            bytes32 indexed ctx,
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
        /// [`ProofLocation`].
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

        // --- M2 additive views ---

        /// One element of a [`batchGetTradeableOrdersWithSignature`]
        /// call. Mirrors the 4-argument list of
        /// `getTradeableOrderWithSignature` 1:1 (owner, params,
        /// offchainInput, proof). Source:
        /// `composable-cow/src/ComposableCoW.sol`
        ///.
        struct BatchOrderRequest {
            address owner;
            ConditionalOrderParams params;
            bytes offchainInput;
            bytes32[] proof;
        }

        /// One element of a [`batchGetTradeableOrdersWithSignature`]
        /// result. On success, `success == true` and (`order`,
        /// `signature`) carry the payload exactly as the per-request
        /// `getTradeableOrderWithSignature` would have returned;
        /// `revertData` is empty. On failure, `success == false` and
        /// `revertData` carries the raw `selector + abi.encode(args)`
        /// revert payload so the caller can decode polling hints like
        /// [`PollOutcome::TryAtEpoch`] / [`PollOutcome::Never`] via
        /// [`decode_conditional_order_revert`]. The contract's
        /// per-request try/catch isolation guarantees one failed
        /// request never blocks the rest of the batch.
        ///
        /// The embedded `GPv2OrderData` is the canonical 12-field order
        /// struct from [`crate::contracts`] — the `sol!` macro resolves
        /// the type by name across sibling blocks. On a failed request
        /// the field defaults to the zero-filled struct; consumers MUST
        /// check `success` before touching it.
        struct BatchOrderResult {
            bool success;
            GPv2OrderData order;
            bytes signature;
            bytes revertData;
        }

        /// Batched variant of `getTradeableOrderWithSignature`,
        /// returning one [`BatchOrderResult`] per input request in the
        /// same order. Saves up to N-1 RPC round trips for watch
        /// towers polling N watches on the same chain. Source:
        /// `composable-cow/src/ComposableCoW.sol`
        ///.
        function batchGetTradeableOrdersWithSignature(
            BatchOrderRequest[] requests
        ) external view returns (BatchOrderResult[] memory);

        /// Combined per-watch metadata returned by
        /// [`getOrderInfo`]. Fields default to inert values when they
        /// do not apply (e.g. `swapGuard == address(0)` when no guard
        /// is set, `cabinetValue == bytes32(0)` when no cabinet slot
        /// was written). Source:
        /// `composable-cow/src/ComposableCoW.sol`
        ///.
        struct OrderInfo {
            bytes32 hash;
            bool authorized;
            bytes32 cabinetValue;
            address swapGuard;
        }

        /// Single-call view that combines `hash()`, `singleOrders`,
        /// `cabinet` and `swapGuards` into one round trip. Source:
        /// `composable-cow/src/ComposableCoW.sol`
        ///.
        function getOrderInfo(
            address owner,
            ConditionalOrderParams params
        ) external view returns (OrderInfo memory);
    }
}

sol! {
    /// Canonical conditional-order interface defined in
    /// `composable-cow/src/interfaces/IConditionalOrder.sol`. The five
    /// custom errors below cover every revert a `getTradeableOrder` /
    /// `verify` implementation is expected to raise; watch towers use
    /// them as polling hints and the orderbook surfaces them to users
    /// when an order cannot yet be settled.
    ///
    /// Only the errors are bound here — the `verify` function takes
    /// `GPv2Order.Data` and is invoked through the EIP-1271 dispatch
    /// path, not as a direct user-facing entry point, so a Rust
    /// `*Call` type would be dead weight.
    #[derive(Debug)]
    interface IConditionalOrder {
        /// Generic "this order is not valid right now, do not retry
        /// without new information". Matches
        /// `OrderNotValid(string)` in `IConditionalOrder.sol`. The
        /// inner string is opaque human-readable context (TWAP uses it
        /// for `"not within span"` outside of the new precise polling
        /// hints, generic handlers use it for validation reasons).
        error OrderNotValid(string reason);

        /// "Try polling again on the next block". Matches
        /// `PollTryNextBlock(string)` in `IConditionalOrder.sol`.
        error PollTryNextBlock(string reason);

        /// "Try polling again at the given block number". Matches
        /// `PollTryAtBlock(uint256,string)` in `IConditionalOrder.sol`.
        error PollTryAtBlock(uint256 blockNumber, string reason);

        /// "Try polling again at the given Unix timestamp". Matches
        /// `PollTryAtEpoch(uint256,string)` in `IConditionalOrder.sol`.
        /// Emitted by the TWAP handler from
        /// [the TWAP handler] for the
        /// "before first part" (`PollTryAtEpoch(t0, ...)`) and
        /// "between parts" (`PollTryAtEpoch(nextPartStart, ...)`)
        /// lifecycle phases.
        error PollTryAtEpoch(uint256 timestamp, string reason);

        /// "This conditional order will never produce a tradeable
        /// order again, the watch tower can delete it". Matches
        /// `PollNever(string)` in `IConditionalOrder.sol`. Emitted by
        /// the TWAP handler from [the TWAP handler] when
        /// every part has been settled (`PollNever("all parts settled")`).
        error PollNever(string reason);
    }

    /// The `*NotAuthed`-style custom errors `ComposableCoW` itself
    /// raises (as opposed to the per-handler errors in
    /// [`IConditionalOrder`]). Surfacing them lets a Rust caller decode
    /// the revert payload of a failed
    /// [`batchGetTradeableOrdersWithSignature`] entry without round-
    /// tripping the bytes through a string.
    #[derive(Debug)]
    interface ComposableCoWErrors {
        /// `proof` did not authenticate against the owner's merkle
        /// root. The order is not registered.
        error ProofNotAuthed();
        /// `params` was not registered via `create` /
        /// `createWithContext` by the owner. The order is not
        /// registered.
        error SingleOrderNotAuthed();
        /// The owner installed a swap guard that vetoed this order.
        error SwapGuardRestricted();
        /// `params.handler == address(0)`, which `create` rejects.
        error InvalidHandler();
        /// `setSafeFallbackHandler` was called with a non-supported
        /// fallback handler.
        error InvalidFallbackHandler();
        /// The handler claimed to implement
        /// `IConditionalOrderGenerator` but does not via ERC-165.
        error InterfaceNotSupported();
    }
}

/// Where watch towers can find the merkle proofs backing a
/// `ComposableCoW.setRoot` registration.
///
/// The contract stores and emits the value as a plain `uint256`
/// ([`Proof::location`]) and never interprets it; the codes are an
/// off-chain convention between registrants and watch towers. The
/// discriminants mirror `ProofLocation` in cow-sdk ([cow-sdk @
/// `00c3dbd4`](https://github.com/cowprotocol/cow-sdk/blob/00c3dbd41c086ff9a51d5e5a30648615d4c66d0d/packages/composable/src/types.ts),
/// pinned in `parity/source-lock.toml`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProofLocation {
    /// The proofs are private to the caller; nothing is published.
    Private = 0,
    /// [`Proof::data`] carries the ABI-encoded proofs and conditional
    /// order parameters, emitted on-chain via the [`MerkleRootSet`]
    /// event.
    ///
    /// [`MerkleRootSet`]: ComposableCoW::MerkleRootSet
    Emitted = 1,
    /// [`Proof::data`] carries the Swarm address of the uploaded
    /// proofs and conditional order parameters.
    Swarm = 2,
    /// Reserved for Waku; upstream documents the payload as TBD.
    Waku = 3,
    /// Reserved for future use; upstream documents the payload as TBD.
    Reserved = 4,
    /// [`Proof::data`] carries the IPFS address of the uploaded
    /// proofs and conditional order parameters.
    Ipfs = 5,
}

impl From<ProofLocation> for U256 {
    /// Widen the location code to the `uint256` the contract stores
    /// and emits ([`Proof::location`]).
    fn from(location: ProofLocation) -> Self {
        Self::from(location as u8)
    }
}

impl Proof {
    /// Build the `(location, data)` pointer for `ComposableCoW.setRoot`
    /// / `setRootWithContext`, widening the typed [`ProofLocation`] to
    /// the `uint256` the contract decodes against.
    pub fn new(location: ProofLocation, data: Bytes) -> Self {
        Self {
            location: location.into(),
            data,
        }
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

/// Decoded `IConditionalOrder` revert returned by `getTradeableOrder`
/// or `getTradeableOrderWithSignature`. The five variants mirror the
/// five custom errors declared in
/// `composable-cow/src/interfaces/IConditionalOrder.sol`; the TWAP
/// handler's the TWAP handler in particular replaces the
/// generic `OrderNotValid("not within span")` for the
/// "before first part" / "between parts" lifecycle phases with the
/// precise [`PollOutcome::TryAtEpoch`] hint, and with
/// [`PollOutcome::Never`] for the terminal "all parts settled" phase.
///
/// Watch towers act on these as polling instructions: `TryNextBlock`
/// re-polls on the next block, `TryAtBlock` / `TryAtEpoch` schedule a
/// poll for the given trigger, `Never` deletes the watch, and
/// `OrderNotValid` keeps the watch but does not schedule a retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    /// Generic "not valid right now" — keep the watch, do not poll
    /// until something external changes. Mirrors
    /// `OrderNotValid(string)`.
    NotValid(String),
    /// "Re-poll on the next block". Mirrors
    /// `PollTryNextBlock(string)`.
    TryNextBlock(String),
    /// "Re-poll at the given block number". Mirrors
    /// `PollTryAtBlock(uint256,string)`.
    TryAtBlock {
        /// Block number to schedule the next poll for.
        block_number: U256,
        /// Human-readable context the handler attached to the revert.
        reason: String,
    },
    /// "Re-poll at the given Unix timestamp". Mirrors
    /// `PollTryAtEpoch(uint256,string)`. TWAP after
    /// the TWAP handler emits this for both the
    /// "before first part" (`timestamp = t0`) and the "between parts"
    /// (`timestamp = nextPartStart`) phases.
    TryAtEpoch {
        /// Unix timestamp (seconds) to schedule the next poll for.
        timestamp: U256,
        /// Human-readable context the handler attached to the revert.
        reason: String,
    },
    /// "Delete the watch — this conditional order will never produce
    /// a tradeable order again". Mirrors `PollNever(string)`. TWAP
    /// after the TWAP handler emits this for the
    /// "all parts settled" terminal phase.
    Never(String),
}

/// Decode an on-chain revert payload (`selector + abi.encode(args)`)
/// against the five [`IConditionalOrder`] custom errors and return the
/// matching [`PollOutcome`].
///
/// Returns `None` when:
///
/// - `data.len() < 4` (no selector to match against), or
/// - the selector does not belong to any `IConditionalOrder` error.
///
/// The caller is responsible for trying other error sets (e.g.
/// [`ComposableCoWErrors`] via [`decode_composable_cow_error`], or a
/// custom handler error) when this returns `None`.
///
/// Reverts emitted by `getTradeableOrder` and
/// `getTradeableOrderWithSignature` always carry an
/// `IConditionalOrder` error, including the TWAP-specific
/// `PollTryAtEpoch` / `PollNever` reverts introduced by
/// the TWAP handler. The decoder is exhaustive over the
/// five-error set so new handlers picking from the same vocabulary
/// (e.g. GoodAfterTime) decode out of the box.
pub fn decode_conditional_order_revert(data: &[u8]) -> Option<PollOutcome> {
    if data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = data[..4].try_into().ok()?;
    let args = &data[4..];

    if selector == IConditionalOrder::OrderNotValid::SELECTOR {
        let e = IConditionalOrder::OrderNotValid::abi_decode_raw(args).ok()?;
        return Some(PollOutcome::NotValid(e.reason));
    }
    if selector == IConditionalOrder::PollTryNextBlock::SELECTOR {
        let e = IConditionalOrder::PollTryNextBlock::abi_decode_raw(args).ok()?;
        return Some(PollOutcome::TryNextBlock(e.reason));
    }
    if selector == IConditionalOrder::PollTryAtBlock::SELECTOR {
        let e = IConditionalOrder::PollTryAtBlock::abi_decode_raw(args).ok()?;
        return Some(PollOutcome::TryAtBlock {
            block_number: e.blockNumber,
            reason: e.reason,
        });
    }
    if selector == IConditionalOrder::PollTryAtEpoch::SELECTOR {
        let e = IConditionalOrder::PollTryAtEpoch::abi_decode_raw(args).ok()?;
        return Some(PollOutcome::TryAtEpoch {
            timestamp: e.timestamp,
            reason: e.reason,
        });
    }
    if selector == IConditionalOrder::PollNever::SELECTOR {
        let e = IConditionalOrder::PollNever::abi_decode_raw(args).ok()?;
        return Some(PollOutcome::Never(e.reason));
    }
    None
}

/// `*NotAuthed`-style errors that `ComposableCoW` itself can raise
/// (versus per-handler errors in [`PollOutcome`]). Returned from
/// [`decode_composable_cow_error`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ComposableCoWError {
    /// The supplied merkle proof did not authenticate against the
    /// owner's published root.
    #[error("ComposableCoW.ProofNotAuthed")]
    ProofNotAuthed,
    /// The supplied `ConditionalOrderParams` was not registered via
    /// `create` / `createWithContext`.
    #[error("ComposableCoW.SingleOrderNotAuthed")]
    SingleOrderNotAuthed,
    /// The owner installed a swap guard that vetoed this order.
    #[error("ComposableCoW.SwapGuardRestricted")]
    SwapGuardRestricted,
    /// `params.handler == address(0)`.
    #[error("ComposableCoW.InvalidHandler")]
    InvalidHandler,
    /// A non-supported fallback handler was supplied.
    #[error("ComposableCoW.InvalidFallbackHandler")]
    InvalidFallbackHandler,
    /// The handler claimed `IConditionalOrderGenerator` but failed the
    /// ERC-165 supportsInterface check.
    #[error("ComposableCoW.InterfaceNotSupported")]
    InterfaceNotSupported,
}

/// Decode an on-chain revert payload against the `*NotAuthed`-style
/// errors `ComposableCoW` itself raises. Returns `None` when the
/// selector does not belong to that set; callers typically try
/// [`decode_conditional_order_revert`] first and fall back here.
pub fn decode_composable_cow_error(data: &[u8]) -> Option<ComposableCoWError> {
    if data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = data[..4].try_into().ok()?;

    if selector == ComposableCoWErrors::ProofNotAuthed::SELECTOR {
        return Some(ComposableCoWError::ProofNotAuthed);
    }
    if selector == ComposableCoWErrors::SingleOrderNotAuthed::SELECTOR {
        return Some(ComposableCoWError::SingleOrderNotAuthed);
    }
    if selector == ComposableCoWErrors::SwapGuardRestricted::SELECTOR {
        return Some(ComposableCoWError::SwapGuardRestricted);
    }
    if selector == ComposableCoWErrors::InvalidHandler::SELECTOR {
        return Some(ComposableCoWError::InvalidHandler);
    }
    if selector == ComposableCoWErrors::InvalidFallbackHandler::SELECTOR {
        return Some(ComposableCoWError::InvalidFallbackHandler);
    }
    if selector == ComposableCoWErrors::InterfaceNotSupported::SELECTOR {
        return Some(ComposableCoWError::InterfaceNotSupported);
    }
    None
}

/// Per-request decoded outcome of a
/// [`ComposableCoW::batchGetTradeableOrdersWithSignatureCall`] call. Each
/// input request lowers to exactly one of these on the way out, in
/// the same order as the original request slice.
///
/// `Submitted` carries the discrete order and EIP-1271 signature blob
/// the caller would forward to the orderbook. `PollHint` carries a
/// decoded [`PollOutcome`] when the per-request revert was one of the
/// five [`IConditionalOrder`] errors — TWAP's new
/// `PollTryAtEpoch(t0, ...)`, `PollTryAtEpoch(nextPartStart, ...)`
/// and `PollNever("all parts settled")` from
/// the TWAP handler all decode here.
/// `ComposableCoWError` carries a decoded `*NotAuthed`-style error
/// from [`ComposableCoWError`]. `UnknownRevert` is the escape hatch
/// for any other revert payload (raw `selector + args`); off-chain
/// indexers should treat it as opaque and surface the bytes for
/// human inspection.
///
/// `PartialEq` / `Eq` are deliberately not derived: `GPv2OrderData` in
/// `Submitted` does not implement them, and comparing decoded
/// outcomes for equality is not a flow this crate needs to support.
/// Use `matches!` plus field destructuring in tests.
#[derive(Clone, Debug)]
pub enum BatchOrderOutcome {
    /// `success == true` in the on-chain [`ComposableCoW::BatchOrderResult`].
    ///
    /// The `GPv2OrderData` payload is boxed to keep the
    /// [`BatchOrderOutcome`] enum compact: the 12-field order struct
    /// is ~320 bytes — large enough that every other variant
    /// (`PollHint`, `ComposableCoWError`, `UnknownRevert`) would pay
    /// the size cost on every collection element. The indirection is
    /// transparent to callers via auto-deref / `*order` when needed.
    Submitted {
        /// The discrete order to submit to the CoW Protocol orderbook.
        order: Box<GPv2OrderData>,
        /// EIP-1271 signature blob accompanying the order.
        signature: Bytes,
    },
    /// `success == false` and the decoded revert matched one of the
    /// five [`IConditionalOrder`] errors.
    PollHint(PollOutcome),
    /// `success == false` and the decoded revert matched one of the
    /// `*NotAuthed`-style errors `ComposableCoW` raises itself.
    ComposableCoWError(ComposableCoWError),
    /// `success == false` and the revert did not match any error we
    /// know how to decode (e.g. a handler-specific custom error). The
    /// raw revert payload is preserved verbatim for the caller.
    UnknownRevert(Bytes),
}

/// Lower one [`ComposableCoW::BatchOrderResult`] into the
/// [`BatchOrderOutcome`] taxonomy. `success` chooses between the
/// success branch (which keeps `order` + `signature`) and the
/// failure branch (which decodes `revertData` against
/// [`IConditionalOrder`] errors first, then `ComposableCoW` errors,
/// then falls back to [`BatchOrderOutcome::UnknownRevert`]).
///
/// Pure function: takes a borrowed result, clones what it keeps. No
/// network, no `Provider` — callers wrap their own RPC layer around
/// it. This mirrors the lower-level helpers (`safe_handler_signature`,
/// `forwarder_signature`) already in this module: cow-rs binds ABI
/// types and offers pure helpers, the caller assembles the
/// `eth_call` themselves.
pub fn decode_batch_order_result(result: &ComposableCoW::BatchOrderResult) -> BatchOrderOutcome {
    if result.success {
        return BatchOrderOutcome::Submitted {
            order: Box::new(result.order.clone()),
            signature: result.signature.clone(),
        };
    }
    let data = result.revertData.as_ref();
    if let Some(poll) = decode_conditional_order_revert(data) {
        return BatchOrderOutcome::PollHint(poll);
    }
    if let Some(err) = decode_composable_cow_error(data) {
        return BatchOrderOutcome::ComposableCoWError(err);
    }
    BatchOrderOutcome::UnknownRevert(result.revertData.clone())
}

/// Convenience wrapper: lower every entry of an on-chain
/// [`ComposableCoW::batchGetTradeableOrdersWithSignatureCall`] response
/// into the [`BatchOrderOutcome`] taxonomy, preserving order.
pub fn decode_batch_order_results(
    results: &[ComposableCoW::BatchOrderResult],
) -> Vec<BatchOrderOutcome> {
    results.iter().map(decode_batch_order_result).collect()
}

/// Build a topic-filter array for
/// `eth_subscribe`/`eth_getLogs` that returns only
/// [`ComposableCoW::ConditionalOrderRegistered`] events whose
/// `handler` indexed topic matches `handler`. The owner and `ctx`
/// topics are left unconstrained (`None`).
///
/// Returns the four-slot Ethereum topic-filter shape: topic-0
/// (signature hash) pinned, topic-1 (owner) unconstrained, topic-2
/// (handler) pinned, topic-3 (`ctx`) unconstrained. Serialise the
/// `Some(B256)` slots into JSON-RPC topic positions and leave the
/// `None` slots as JSON `null` to keep the filter open at that
/// position.
///
/// Indexed `address` topics are left-padded to 32 bytes with zeros
/// when emitted as `log.topics[i]`, which matches the encoding the
/// `From<Address> for B256` widening produces here.
pub fn registered_topic_filter_by_handler(handler: Address) -> [Option<B256>; 4] {
    [
        Some(ComposableCoW::ConditionalOrderRegistered::SIGNATURE_HASH),
        None,
        Some(B256::left_padding_from(handler.as_slice())),
        None,
    ]
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
        let proof = Proof::new(ProofLocation::Private, Bytes::from_static(b"hello"));
        let encoded = proof.abi_encode();
        let decoded = Proof::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.location, proof.location);
        assert_eq!(decoded.data, proof.data);
    }

    /// Locks the six location codes against the `ProofLocation` enum in
    /// cow-sdk's `packages/composable/src/types.ts` (pinned sha
    /// `00c3dbd4`, `parity/source-lock.toml`). The codes are an
    /// off-chain convention, so a renumbering here would silently
    /// mislead watch towers.
    #[test]
    fn proof_location_discriminants_match_cow_sdk() {
        let cases: [(ProofLocation, u8); 6] = [
            (ProofLocation::Private, 0),
            (ProofLocation::Emitted, 1),
            (ProofLocation::Swarm, 2),
            (ProofLocation::Waku, 3),
            (ProofLocation::Reserved, 4),
            (ProofLocation::Ipfs, 5),
        ];
        for (location, code) in cases {
            assert_eq!(location as u8, code, "{location:?}");
            let widened: U256 = location.into();
            assert_eq!(widened, U256::from(code), "{location:?}");
        }
    }

    /// `Proof::new` widens the typed location to the `uint256` field
    /// the contract decodes against and stores the data untouched.
    #[test]
    fn proof_new_widens_location_to_uint256() {
        let proof = Proof::new(ProofLocation::Ipfs, Bytes::from_static(b"ipfs://bafy"));
        assert_eq!(proof.location, U256::from(5));
        assert_eq!(proof.data.as_ref(), b"ipfs://bafy");
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
            // M2: batchGetTradeableOrdersWithSignature(
            //   (address,(address,bytes32,bytes),bytes,bytes32[])[]
            // ). The inner BatchOrderRequest tuple expands to its four
            // fields with ConditionalOrderParams inlined as (address,bytes32,bytes).
            (
                &ComposableCoW::batchGetTradeableOrdersWithSignatureCall::SELECTOR,
                b"batchGetTradeableOrdersWithSignature((address,(address,bytes32,bytes),bytes,bytes32[])[])",
            ),
            // M2: getOrderInfo(address,(address,bytes32,bytes))
            (
                &ComposableCoW::getOrderInfoCall::SELECTOR,
                b"getOrderInfo(address,(address,bytes32,bytes))",
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
        let proof = Proof::new(ProofLocation::Ipfs, Bytes::from_static(b"ipfs://bafy"));
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
        // M2: ConditionalOrderRegistered(address,address,bytes32,(address,bytes32,bytes))
        assert_eq!(
            ComposableCoW::ConditionalOrderRegistered::SIGNATURE_HASH,
            keccak256(
                "ConditionalOrderRegistered(address,address,bytes32,(address,bytes32,bytes))"
            )
        );
        // SwapGuardSet(address,address)
        assert_eq!(
            ComposableCoW::SwapGuardSet::SIGNATURE_HASH,
            keccak256("SwapGuardSet(address,address)")
        );
    }

    // --- ConditionalOrderRegistered event ---

    /// The `ConditionalOrderRegistered` event indexes `owner`,
    /// `handler` and `ctx` — three of the four event arguments. The
    /// indexed `address` topics are left-padded to 32 bytes with
    /// zeros, which is what `eth_subscribe`/`eth_getLogs` expects for
    /// the `topics` filter array. Round-trip the encode/decode path
    /// to lock this against accidental field reordering.
    #[test]
    fn conditional_order_registered_round_trips() {
        let owner = address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF");
        let handler = TWAP_HANDLER;
        let params = ConditionalOrderParams {
            handler,
            salt: B256::repeat_byte(0x11),
            staticInput: Bytes::from_static(&hex!("c0ffee")),
        };
        let ctx = keccak256(params.abi_encode());

        let evt = ComposableCoW::ConditionalOrderRegistered {
            owner,
            handler,
            ctx,
            params,
        };
        // Topic-0 is the signature hash; topic-1, topic-2, topic-3 are the
        // three indexed args left-padded to 32 bytes.
        let topics = evt.encode_topics_array::<4>();
        assert_eq!(
            topics[0].0,
            ComposableCoW::ConditionalOrderRegistered::SIGNATURE_HASH
        );
        assert_eq!(topics[1].0, B256::left_padding_from(owner.as_slice()));
        assert_eq!(topics[2].0, B256::left_padding_from(handler.as_slice()));
        assert_eq!(topics[3].0, ctx);
    }

    /// `registered_topic_filter_by_handler(h)` builds the four-slot
    /// `[topic-0, topic-1, topic-2, topic-3]` filter the watch tower
    /// passes to `eth_subscribe logs` to receive only events for one
    /// handler (TWAP, GoodAfterTime, ...). Topic-0 is the signature
    /// hash, topic-2 is the handler left-padded to 32 bytes, and
    /// topics 1 / 3 (owner / ctx) are left open.
    #[test]
    fn registered_topic_filter_pins_handler_and_signature() {
        let filter = registered_topic_filter_by_handler(TWAP_HANDLER);
        assert_eq!(
            filter[0],
            Some(ComposableCoW::ConditionalOrderRegistered::SIGNATURE_HASH)
        );
        assert_eq!(filter[1], None);
        assert_eq!(
            filter[2],
            Some(B256::left_padding_from(TWAP_HANDLER.as_slice()))
        );
        assert_eq!(filter[3], None);
    }

    // --- batchGetTradeableOrdersWithSignature ---

    /// `BatchOrderRequest` round-trips through `abi_encode` /
    /// `abi_decode`. The 4-field struct mirrors the
    /// `getTradeableOrderWithSignature` argument list 1:1.
    #[test]
    fn batch_order_request_round_trips() {
        let req = ComposableCoW::BatchOrderRequest {
            owner: address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            params: ConditionalOrderParams {
                handler: TWAP_HANDLER,
                salt: B256::repeat_byte(0x22),
                staticInput: Bytes::from_static(&hex!("c0ffee")),
            },
            offchainInput: Bytes::from_static(b"offchain"),
            proof: vec![B256::repeat_byte(0x33), B256::repeat_byte(0x44)],
        };
        let encoded = req.abi_encode();
        let decoded = ComposableCoW::BatchOrderRequest::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.owner, req.owner);
        assert_eq!(decoded.params.handler, req.params.handler);
        assert_eq!(decoded.params.salt, req.params.salt);
        assert_eq!(decoded.params.staticInput, req.params.staticInput);
        assert_eq!(decoded.offchainInput, req.offchainInput);
        assert_eq!(decoded.proof, req.proof);
    }

    fn sample_gpv2_order() -> GPv2OrderData {
        GPv2OrderData {
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
        }
    }

    /// `BatchOrderResult` round-trips through `abi_encode` /
    /// `abi_decode` with both `success = true` (carrying an order +
    /// signature) and `success = false` (carrying a revert payload).
    #[test]
    fn batch_order_result_round_trips() {
        let success = ComposableCoW::BatchOrderResult {
            success: true,
            order: sample_gpv2_order(),
            signature: Bytes::from_static(b"signature-blob"),
            revertData: Bytes::new(),
        };
        let encoded = success.abi_encode();
        let decoded = ComposableCoW::BatchOrderResult::abi_decode(&encoded).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.order.sellToken, success.order.sellToken);
        assert_eq!(decoded.signature, success.signature);
        assert!(decoded.revertData.is_empty());

        let failure = ComposableCoW::BatchOrderResult {
            success: false,
            order: GPv2OrderData {
                sellToken: Address::ZERO,
                buyToken: Address::ZERO,
                receiver: Address::ZERO,
                sellAmount: U256::ZERO,
                buyAmount: U256::ZERO,
                validTo: 0,
                appData: B256::ZERO,
                feeAmount: U256::ZERO,
                kind: B256::ZERO,
                partiallyFillable: false,
                sellTokenBalance: B256::ZERO,
                buyTokenBalance: B256::ZERO,
            },
            signature: Bytes::new(),
            revertData: Bytes::from_static(&hex!("deadbeef")),
        };
        let encoded = failure.abi_encode();
        let decoded = ComposableCoW::BatchOrderResult::abi_decode(&encoded).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.revertData.as_ref(), &hex!("deadbeef"));
    }

    /// `decode_batch_order_result` lowers a successful entry to
    /// `BatchOrderOutcome::Submitted` carrying the same order and
    /// signature.
    #[test]
    fn decode_batch_order_result_success() {
        let order = sample_gpv2_order();
        let sig = Bytes::from_static(b"signature-blob");
        let result = ComposableCoW::BatchOrderResult {
            success: true,
            order: order.clone(),
            signature: sig.clone(),
            revertData: Bytes::new(),
        };
        match decode_batch_order_result(&result) {
            BatchOrderOutcome::Submitted {
                order: out_order,
                signature,
            } => {
                assert_eq!(out_order.sellToken, order.sellToken);
                assert_eq!(out_order.buyToken, order.buyToken);
                assert_eq!(signature, sig);
            }
            other => panic!("expected Submitted, got {other:?}"),
        }
    }

    /// `decode_batch_order_result` lowers a failed entry whose
    /// revert payload is a `PollTryAtEpoch(timestamp, reason)` into
    /// `BatchOrderOutcome::PollHint(PollOutcome::TryAtEpoch { ... })`,
    /// preserving `timestamp` and `reason` byte-exact.
    #[test]
    fn decode_batch_order_result_poll_try_at_epoch() {
        let revert = IConditionalOrder::PollTryAtEpoch {
            timestamp: U256::from(1_700_000_000_u64),
            reason: "between parts".to_string(),
        };
        let payload = revert.abi_encode();
        let result = ComposableCoW::BatchOrderResult {
            success: false,
            order: sample_gpv2_order(),
            signature: Bytes::new(),
            revertData: Bytes::from(payload),
        };
        match decode_batch_order_result(&result) {
            BatchOrderOutcome::PollHint(PollOutcome::TryAtEpoch { timestamp, reason }) => {
                assert_eq!(timestamp, U256::from(1_700_000_000_u64));
                assert_eq!(reason, "between parts");
            }
            other => panic!("expected PollHint(TryAtEpoch), got {other:?}"),
        }
    }

    /// `decode_batch_order_result` lowers a failed entry whose
    /// revert payload is a `*NotAuthed`-style `ComposableCoW` error
    /// into `BatchOrderOutcome::ComposableCoWError(...)`.
    #[test]
    fn decode_batch_order_result_composable_cow_error() {
        let payload = ComposableCoWErrors::SingleOrderNotAuthed::SELECTOR.to_vec();
        let result = ComposableCoW::BatchOrderResult {
            success: false,
            order: sample_gpv2_order(),
            signature: Bytes::new(),
            revertData: Bytes::from(payload),
        };
        match decode_batch_order_result(&result) {
            BatchOrderOutcome::ComposableCoWError(ComposableCoWError::SingleOrderNotAuthed) => {}
            other => panic!("expected ComposableCoWError(SingleOrderNotAuthed), got {other:?}"),
        }
    }

    /// `decode_batch_order_result` falls back to `UnknownRevert`
    /// when the selector does not match either error set. The raw
    /// payload is preserved verbatim.
    #[test]
    fn decode_batch_order_result_unknown_revert() {
        let payload = hex!("12345678ff").to_vec();
        let result = ComposableCoW::BatchOrderResult {
            success: false,
            order: sample_gpv2_order(),
            signature: Bytes::new(),
            revertData: Bytes::from(payload.clone()),
        };
        match decode_batch_order_result(&result) {
            BatchOrderOutcome::UnknownRevert(bytes) => assert_eq!(bytes.as_ref(), &payload[..]),
            other => panic!("expected UnknownRevert, got {other:?}"),
        }
    }

    /// `decode_batch_order_results` preserves order: feed a mixed
    /// success/PollHint/UnknownRevert batch and the output enum
    /// variants line up 1:1 with the inputs.
    #[test]
    fn decode_batch_order_results_preserves_order() {
        let success = ComposableCoW::BatchOrderResult {
            success: true,
            order: sample_gpv2_order(),
            signature: Bytes::from_static(b"sig-1"),
            revertData: Bytes::new(),
        };
        let poll_never = IConditionalOrder::PollNever {
            reason: "all parts settled".to_string(),
        };
        let poll_payload = poll_never.abi_encode();
        let poll = ComposableCoW::BatchOrderResult {
            success: false,
            order: sample_gpv2_order(),
            signature: Bytes::new(),
            revertData: Bytes::from(poll_payload),
        };
        let unknown = ComposableCoW::BatchOrderResult {
            success: false,
            order: sample_gpv2_order(),
            signature: Bytes::new(),
            revertData: Bytes::from_static(&hex!("aabbccdd")),
        };

        let outcomes = decode_batch_order_results(&[success, poll, unknown]);
        assert_eq!(outcomes.len(), 3);
        assert!(matches!(outcomes[0], BatchOrderOutcome::Submitted { .. }));
        assert!(matches!(
            outcomes[1],
            BatchOrderOutcome::PollHint(PollOutcome::Never(ref r)) if r == "all parts settled"
        ));
        assert!(matches!(outcomes[2], BatchOrderOutcome::UnknownRevert(_)));
    }

    // --- getOrderInfo ---

    /// `OrderInfo` round-trips through `abi_encode` / `abi_decode`,
    /// locking the 4-field struct layout against accidental
    /// reordering.
    #[test]
    fn order_info_round_trips() {
        let info = ComposableCoW::OrderInfo {
            hash: B256::repeat_byte(0x55),
            authorized: true,
            cabinetValue: B256::repeat_byte(0x66),
            swapGuard: address!("AAAaAaaaAaAaaAaaAaaaaaAAaAAaaaaaaaAaaaAa"),
        };
        let encoded = info.abi_encode();
        let decoded = ComposableCoW::OrderInfo::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.hash, info.hash);
        assert!(decoded.authorized);
        assert_eq!(decoded.cabinetValue, info.cabinetValue);
        assert_eq!(decoded.swapGuard, info.swapGuard);
    }

    /// `getOrderInfo(owner, params)` round-trips with the canonical
    /// selector. Locks the most common watch-tower view call from
    /// the order-info accessor.
    #[test]
    fn get_order_info_call_round_trips() {
        let owner = address!("DeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF");
        let params = ConditionalOrderParams {
            handler: TWAP_HANDLER,
            salt: B256::repeat_byte(0x77),
            staticInput: Bytes::from_static(&hex!("c0ffee")),
        };
        let call = ComposableCoW::getOrderInfoCall {
            owner,
            params: params.clone(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], &ComposableCoW::getOrderInfoCall::SELECTOR);
        let decoded = ComposableCoW::getOrderInfoCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.owner, owner);
        assert_eq!(decoded.params.handler, params.handler);
        assert_eq!(decoded.params.salt, params.salt);
        assert_eq!(decoded.params.staticInput, params.staticInput);
    }

    // --- IConditionalOrder revert decoder ---

    /// All five `IConditionalOrder` errors decode into the matching
    /// [`PollOutcome`] variant, with `timestamp` / `blockNumber` /
    /// `reason` arguments preserved byte-for-byte. Locks the decoder
    /// against TWAP's new behaviour from the TWAP handler:
    /// `PollTryAtEpoch(t0, "before first part")`,
    /// `PollNever("all parts settled")`, and
    /// `PollTryAtEpoch(nextPartStart, "between parts")`.
    #[test]
    fn decode_conditional_order_revert_covers_all_five_errors() {
        // OrderNotValid("not within span") — the defensive fallback
        // the TWAP handler still raises outside the new precise
        // polling phases.
        let err = IConditionalOrder::OrderNotValid {
            reason: "not within span".to_string(),
        };
        let payload = err.abi_encode();
        assert_eq!(
            decode_conditional_order_revert(&payload),
            Some(PollOutcome::NotValid("not within span".to_string()))
        );

        // PollTryNextBlock("nudge")
        let err = IConditionalOrder::PollTryNextBlock {
            reason: "nudge".to_string(),
        };
        let payload = err.abi_encode();
        assert_eq!(
            decode_conditional_order_revert(&payload),
            Some(PollOutcome::TryNextBlock("nudge".to_string()))
        );

        // PollTryAtBlock(blockNumber, "later")
        let err = IConditionalOrder::PollTryAtBlock {
            blockNumber: U256::from(19_000_000_u64),
            reason: "later".to_string(),
        };
        let payload = err.abi_encode();
        assert_eq!(
            decode_conditional_order_revert(&payload),
            Some(PollOutcome::TryAtBlock {
                block_number: U256::from(19_000_000_u64),
                reason: "later".to_string(),
            })
        );

        // PollTryAtEpoch(t0, "before first part") — TWAP M2 phase 1.
        let err = IConditionalOrder::PollTryAtEpoch {
            timestamp: U256::from(1_700_000_000_u64),
            reason: "before first part".to_string(),
        };
        let payload = err.abi_encode();
        assert_eq!(
            decode_conditional_order_revert(&payload),
            Some(PollOutcome::TryAtEpoch {
                timestamp: U256::from(1_700_000_000_u64),
                reason: "before first part".to_string(),
            })
        );

        // PollTryAtEpoch(nextPartStart, "between parts") — TWAP M2 phase 3.
        let err = IConditionalOrder::PollTryAtEpoch {
            timestamp: U256::from(1_700_003_600_u64),
            reason: "between parts".to_string(),
        };
        let payload = err.abi_encode();
        assert_eq!(
            decode_conditional_order_revert(&payload),
            Some(PollOutcome::TryAtEpoch {
                timestamp: U256::from(1_700_003_600_u64),
                reason: "between parts".to_string(),
            })
        );

        // PollNever("all parts settled") — TWAP M2 phase 2 (terminal).
        let err = IConditionalOrder::PollNever {
            reason: "all parts settled".to_string(),
        };
        let payload = err.abi_encode();
        assert_eq!(
            decode_conditional_order_revert(&payload),
            Some(PollOutcome::Never("all parts settled".to_string()))
        );
    }

    /// Short payloads and selectors outside the five-error set
    /// return `None` (no panic, no spurious match) so callers can
    /// safely cascade to other decoders.
    #[test]
    fn decode_conditional_order_revert_returns_none_for_unrelated_payloads() {
        assert_eq!(decode_conditional_order_revert(&[]), None);
        assert_eq!(decode_conditional_order_revert(&hex!("aa")), None);
        assert_eq!(
            decode_conditional_order_revert(&hex!("12345678deadbeef")),
            None
        );
        // A ComposableCoW `*NotAuthed` selector is NOT an
        // IConditionalOrder error and must not decode here.
        assert_eq!(
            decode_conditional_order_revert(&ComposableCoWErrors::SingleOrderNotAuthed::SELECTOR),
            None
        );
    }

    /// The five `IConditionalOrder` error selectors must match the
    /// canonical `keccak256(signature)[..4]` values. Typos in the
    /// `sol!` field names or order would break the decoder.
    #[test]
    fn conditional_order_error_selectors_match_keccak() {
        let cases: &[(&[u8; 4], &[u8])] = &[
            (
                &IConditionalOrder::OrderNotValid::SELECTOR,
                b"OrderNotValid(string)",
            ),
            (
                &IConditionalOrder::PollTryNextBlock::SELECTOR,
                b"PollTryNextBlock(string)",
            ),
            (
                &IConditionalOrder::PollTryAtBlock::SELECTOR,
                b"PollTryAtBlock(uint256,string)",
            ),
            (
                &IConditionalOrder::PollTryAtEpoch::SELECTOR,
                b"PollTryAtEpoch(uint256,string)",
            ),
            (
                &IConditionalOrder::PollNever::SELECTOR,
                b"PollNever(string)",
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

    /// The six `ComposableCoW` `*NotAuthed`-style error selectors
    /// must match the canonical `keccak256(signature)[..4]` values.
    #[test]
    fn composable_cow_error_selectors_match_keccak() {
        let cases: &[(&[u8; 4], &[u8])] = &[
            (
                &ComposableCoWErrors::ProofNotAuthed::SELECTOR,
                b"ProofNotAuthed()",
            ),
            (
                &ComposableCoWErrors::SingleOrderNotAuthed::SELECTOR,
                b"SingleOrderNotAuthed()",
            ),
            (
                &ComposableCoWErrors::SwapGuardRestricted::SELECTOR,
                b"SwapGuardRestricted()",
            ),
            (
                &ComposableCoWErrors::InvalidHandler::SELECTOR,
                b"InvalidHandler()",
            ),
            (
                &ComposableCoWErrors::InvalidFallbackHandler::SELECTOR,
                b"InvalidFallbackHandler()",
            ),
            (
                &ComposableCoWErrors::InterfaceNotSupported::SELECTOR,
                b"InterfaceNotSupported()",
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

    /// `decode_composable_cow_error` covers every variant of
    /// [`ComposableCoWError`] and returns `None` for unrelated
    /// selectors so the cascade stays safe.
    #[test]
    fn decode_composable_cow_error_covers_all_variants() {
        let cases = [
            (
                ComposableCoWErrors::ProofNotAuthed::SELECTOR,
                ComposableCoWError::ProofNotAuthed,
            ),
            (
                ComposableCoWErrors::SingleOrderNotAuthed::SELECTOR,
                ComposableCoWError::SingleOrderNotAuthed,
            ),
            (
                ComposableCoWErrors::SwapGuardRestricted::SELECTOR,
                ComposableCoWError::SwapGuardRestricted,
            ),
            (
                ComposableCoWErrors::InvalidHandler::SELECTOR,
                ComposableCoWError::InvalidHandler,
            ),
            (
                ComposableCoWErrors::InvalidFallbackHandler::SELECTOR,
                ComposableCoWError::InvalidFallbackHandler,
            ),
            (
                ComposableCoWErrors::InterfaceNotSupported::SELECTOR,
                ComposableCoWError::InterfaceNotSupported,
            ),
        ];
        for (selector, expected) in cases {
            assert_eq!(decode_composable_cow_error(&selector), Some(expected));
        }
        // Unrelated selector (an IConditionalOrder error) returns None.
        assert_eq!(
            decode_composable_cow_error(&IConditionalOrder::PollNever::SELECTOR),
            None
        );
        assert_eq!(decode_composable_cow_error(&[]), None);
    }
}
