//! `staticInput` payloads for the canonical ComposableCoW handler set.
//!
//! Each submodule exposes the `Data` struct ABI-encoded as the
//! `staticInput` bytes of a [`crate::ConditionalOrderParams`], plus the
//! handler contract's CREATE2 deployment address. The handler set
//! mirrors `composable-cow/src/types/`:
//!
//! - [`twap`]: time-weighted average orders.
//!
//! Follow-up modules will add `good_after_time`, `stop_loss`,
//! `perpetual_stable_swap` and `trade_above_threshold` as separate
//! commits.
//!
//! ABI compatibility with the on-chain Solidity is locked by round-trip
//! tests per module. Each `Data` is generated via
//! `alloy_sol_types::sol!` against the canonical layout, so the wire
//! format follows the upstream contract without a transcription pass.

pub mod twap;
