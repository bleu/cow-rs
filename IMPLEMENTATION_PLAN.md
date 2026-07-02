## Stage 1: Integration Branch
**Goal**: Merge all open release PR heads onto `develop`.
**Success Criteria**: PRs #40-#48 are present with intentional conflict resolutions.
**Tests**: `git status` clean after merges.
**Status**: In Progress

## Stage 2: Release Blockers
**Goal**: Fix integration blockers from review.
**Success Criteria**: `Cargo.lock` is canonical and `order.rs` stays below 1000 lines.
**Tests**: `cargo +1.91.1 fmt --all -- --check`.
**Status**: Not Started

## Stage 3: Validation
**Goal**: Prove the integrated release candidate builds on native and wasm.
**Success Criteria**: format, clippy, tests, wasm checks, wasm tests, and wasm-size pass.
**Tests**: Full release validation command set.
**Status**: Not Started

## Stage 4: Publishable PR
**Goal**: Push an integration branch for final CI/review.
**Success Criteria**: Remote branch exists and PR is opened or updated.
**Tests**: GitHub branch/PR state.
**Status**: Not Started
