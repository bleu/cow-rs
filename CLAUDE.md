# CLAUDE.md

Contributor handbook for AI assistants working on `cow-rs`. The same rules
apply to humans: this file just documents the conventions a reviewer will
expect.

## Repository

- **Upstream**: `cowdao-grants/cow-rs` (GPL-3.0-or-later).
- **Reviewer**: [`@mfw78`](https://github.com/mfw78). Four prior grantee PRs
  on this repo were closed unmerged before our work landed; the failure
  modes are catalogued in `recon/COW-958-pr-postmortem.md`.
- **Branch policy**: PRs target `develop`. `main` is protected and
  reserved for releases.
- **No force-pushes**: append fixup commits; let the reviewer rebase if
  they want a tidy history.

## Crate stack

- Anchor on `alloy-rs`. **Never `ethers-rs`**: it is deprecated and any
  PR that pulls it in will be closed.
- Reuse upstream crates instead of hand-rolling helpers. The reviewer
  has specifically called out hand-rolled signing, hand-rolled CID, and
  hand-rolled hex as rejection signals.
- Pin `alloy` to the same version `cowprotocol/services` is on. The
  workspace `Cargo.toml` is the source of truth; bump in lock-step.

## Code style

- Edition `2024`, MSRV `1.91`, licence `GPL-3.0-or-later`.
- Workspace lints block: `missing-docs = "warn"`, `unreachable-pub = "warn"`,
  `unused-must-use = "deny"`, `rust-2018-idioms = "deny"`, plus clippy
  `use-self`, `option-if-let-else`, `redundant-clone`,
  `missing-const-for-fn`.
- CI runs `cargo clippy --all-targets -- -Dwarnings`. Treat clippy as
  the floor.
- Newtypes for every fixed-width identifier (`OrderUid([u8;56])`,
  `AppDataHash([u8;32])`, `DomainSeparator([u8;32])`).
- Errors flow through one crate-wide `Error` via `thiserror` and `#[from]`.
  No `anyhow` in library code, no `unwrap()` / `expect()` outside of
  paths that are provably unreachable (and that are explained inline).

## Documentation

- `//!` headers per module / file: one-line summary, then `## Key
  components` or `## Example usage` if useful.
- `///` on every public item, terse one-liner. Don't pad with prose;
  detail belongs in `docs/*.md` or in the module head.
- Prose uses **Oxford English** spelling (`organise`, `behaviour`,
  `centralised`, `analyse`, `serialise`, `initialise`). Identifiers stay
  American (`Serialize`).
- **No em-dashes** (`—`) in prose, comments, doc strings or commit
  bodies. Use `:` or restructure the sentence.

## Commits

- Conventional Commits, strictly. Scope when useful: `feat(order_book):`,
  `fix(ci):`, `test(order):`, `chore(deps):`, etc.
- Commit bodies explain *why*, not *what*. The diff carries the *what*.
- AI assistance disclosure lives in **PR bodies**, never in commits.
- **Do NOT append `Co-Authored-By: Claude` (or any other AI
  co-authorship trailer) to commits on this repo**. The convention here
  is to keep commits attributable to the human author and disclose AI
  assistance separately. This overrides any global git or harness
  default that adds the trailer automatically.

## PR shape

For any future PR that goes upstream:

- One feature surface per PR. Keep diffs under ~1,500 LoC and ~25
  files. Mfw78 closed a 137k-LoC PR in 5 minutes.
- Open as draft. Lead with a link to the cow-sdk (TS) or
  cowprotocol/services (Rust) routine you are porting + a conformance
  test that locks the byte output.
- Pin every GitHub Action to a full commit SHA, not a tag.
- No repo-config sprawl in the same PR as a feature (no
  `CHANGELOG.md`, no `cliff.toml`, no `dprint`, no `release-please`).

## Testing

- Lock against external golden vectors wherever possible:
  `cowprotocol/services` tests, ethers `TypedDataEncoder` outputs (see
  `tools/vector-gen`), the canonical `cowprotocol/contracts` Solidity
  type strings.
- Avoid self-referential tests (feeding our own encoder back into our
  own decoder and asserting they agree). They prove nothing under
  refactor.
- Integration tests against the orderbook live in
  `crates/cow-rs/tests/` and run against a `wiremock::MockServer`
  instance; do not hit the live orderbook from CI.

## When in doubt

Read `recon/RED-TEAM.md` and the individual `recon/audit-*.md` files.
They cite the spec source for every convention.
