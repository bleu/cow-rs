# Implementation Plan: maintainer feedback + thermo-nuclear review remediation

Scope: everything from the 2026-06-09 full-workspace quality review plus the latest
maintainer feedback (domain crates + meta crate as common WASM/non-WASM entry point,
type-state builders for `OrderBookApi`, `QuoteRequest`, and order submission).

All PRs target `develop`, Conventional Commits, each under 1.5k LoC diff, every commit
compiles and passes tests. Behavioural changes are flagged loudly in CHANGELOG entries.

## Maintainer feedback: status map

| Feedback item | Status | Where handled |
| --- | --- | --- |
| Domain crates (`-primitives`, `-appdata`, `-orderbook`, `-signing`) | Done (current workspace) | Stage 6 tightens the seams (wrong-layer types, dependency edges) |
| `cowprotocol` meta crate exporting a prelude | Done | Stage 5 documents it as the single entry point |
| Meta crate cfg-gated on wasm32, common entry for WASM and non-WASM | Gap | Stages 4 and 5 |
| Type-state builders for `OrderBookApi` / `QuoteRequest` / submission | Exists but duplicated three ways | Stages 1 to 3 (single canonical pipeline) |
| Chained `with_chain(..).build().quote_builder()...sign(wallet).submit()` | Compiles today, with diverged guards vs `TradingClient` | Stages 2 and 3 |
| `NamedChain::Gnosis` ergonomics | Missing (no alloy-chains dep) | Stage 2 |

Design decisions below come from a 3-design judge panel per crux. Pipeline crux winner:
"delete-first" (merge the api+costs context into the one canonical type-state builder,
route everything through the parity-locked `quote_amounts::compute`, delete
`TradingClient`). WASM crux winner: "transport-crate layout" (both transports live
beside the `HttpTransport` trait inside `cowprotocol-orderbook`, target-resolved
`DefaultTransport` alias, `cow-sdk-wasm` shrinks to JS bindings only).

## Open questions to settle with the maintainer before the affected stage lands

1. `sign()` fallibility: explicit `Result` + `?` (recommended, fail-fast house style)
   vs a deferred-error `OrderSubmission` that compiles the sketch verbatim. One-signature
   change either way; pre-agree before Stage 2.
2. `NamedChain`: `TryFrom<NamedChain>` + `.try_into()?` (recommended; a total `From`
   would hide unsupported chains) vs `with_chain(impl TryInto<Chain>)` with the error
   deferred into a fallible `build()`.
3. Zero-`from` guard width: only in the pipeline `build()` or hardened into
   `QuoteRequest::validate()` for every quote path. Confirm whether zero-from
   indicative quotes are a legitimate orderbook use case first.
4. `verify_owner` chokepoint in `post_order` (one extra ECDSA recovery per submission,
   chain-hint-gated skip for mock clients): acceptable cost?
5. Costs type: `OrderCosts` with neutral `Default` + pipeline-seeded
   `DEFAULT_SLIPPAGE_BPS = 50` (recommended) vs `Default` carrying 50 bps.
6. Should `submit()` skip the app-data PUT when the hash is `EMPTY_APP_DATA_HASH`?
7. Deleting `TradingClient` removes the TS-parity name `post_swap_order`: confirm the
   fluent chain + CHANGELOG migration recipe satisfies the grant deliverable.
8. BUY behavioural fix blast radius: any integrators pinning BUY UIDs derived from the
   old bare-sell projection?

---

## Stage 0: correctness quick wins and housekeeping

**Goal**: fix the three small verified bugs and the doc-link rot; clean the repo.
One PR (`fix:`), well under 500 LoC.

- wasm `get_quote` (endpoints.rs:54): stop hard-coding `EMPTY_APP_DATA_HASH` into the
  binding check. Delete the eager check (the projection chokepoint re-runs it with the
  real digest) or derive the digest from `request.app_data`. Today every quote with a
  pinned non-empty `appData` fails spuriously.
- `SubgraphClient::totals()` (subgraph.rs:294): empty result set must error, not
  `unwrap_or_default()` into fabricated empty strings. Drop the `Default` derive on
  `Totals`.
- browser.rs fixtures: correct the fabricated empty-app-data keccak comment (real
  digest `0xb48d...739d`) and rename the silently dropped `sellTokenSource` /
  `buyTokenDestination` keys to the wire keys `sellTokenBalance` / `buyTokenBalance`.
- Fix all seven broken intra-doc links (four `crate::OrderCreation` in signing, three
  `crate::SubgraphClient` / `crate::OrderData` in primitives) as prose references.
  Quality gate: `cargo doc` warning-free.
- Local housekeeping (no PR): delete the 13 GB of stale `.claude/worktrees/`; decide
  whether `.agents/` is tracked or ignored.

**Success Criteria**: pinned-appData quotes succeed in the browser test; empty subgraph
totals surface an error; zero rustdoc warnings workspace-wide.
**Tests**: new browser regression test for pinned appData; wiremock test for empty
`totals`; existing suites green.
**Status**: Complete

## Stage 1: one projection (BUY fix), `OrderCosts`, `ProtocolFeeBps`

**Goal**: a single quote-to-`OrderData` projection routed through the parity-locked
`quote_amounts::compute`. One PR.

- New `ProtocolFeeBps` newtype (scaled u64, `FromStr` = today's
  `parse_protocol_fee_bps`); the stringly `Option<String>` leaves the public stack and
  `"abc"` fails at the setter, not at sign time.
- New public `OrderCosts { partner_fee_bps, slippage_bps, protocol_fee_bps_override }`
  with neutral `Default`; replaces private `CostParams` now and `SwapOrder`'s triple in
  Stage 3. `DEFAULT_SLIPPAGE_BPS = 50` is a named constant the pipeline seeds.
- `OrderQuoteResponse::try_to_order_data(&self, request, app_data, &OrderCosts)`
  becomes THE projection; `try_into_signed_order_data` and `_with_costs` are deleted.
  At `OrderCosts::default()` this equals the old basic path for SELL exactly and fixes
  the BUY divergence: the signed sell becomes `sellAmount + feeAmount`, matching the
  pinned TS reference (`getQuoteAmountsAndCosts.ts` in `parity/source-lock.toml`).
  Loud CHANGELOG entry: BUY orders now sign different amounts (the correct ones).
- Fold `Error::QuoteAmountOverflow` into the staged `QuoteFeeMathOverflow`; audit and
  update every test whose expected variant shifts.
- Also collapse the duplicated fee-fold expression and the hand-rolled `Full` appData
  mismatch arm onto `ensure_eq` while in the file.

**Success Criteria**: exactly one projection function; BUY parity test against the TS
vector passes; zero-sellAmount edge behaviour documented and tested.
**Tests**: BUY-at-zero-costs vector test vs the TS reference; SELL equivalence test
old-vs-new; error-variant migration covered.
**Status**: Complete

## Stage 2: the canonical type-state pipeline

**Goal**: the maintainer's chain, one builder, guards structural. One PR (split into
additive + deletion PRs if review stalls).

- Merge `OrderBookQuoteBuilder` and the request-only `QuoteRequestBuilder` into ONE
  `QuoteRequestBuilder<T, SellToken, BuyToken, From, Amount>` that holds the
  `OrderBookApi<T>` handle and `OrderCosts`. The 18 request fields + costs live in one
  private `QuoteParts` payload struct so the type-state cast is a 3-line move, not a
  19-field copy. Every optional setter lives directly on the builder; the `configure()`
  hatch and the 130-line wrapper replica are deleted.
- `into_request()` (consumes self) replaces `build_request()`; `build()` rejects
  `from == Address::ZERO` pre-quote and runs `check_response_matches_request`, so
  `QuotedOrder` is born response-bound (hostile-orderbook binding fails at quote time).
- `QuotedOrder::sign(signer)` (EIP-712, api chain) and `sign_with(chain, scheme,
  signer)` (absorbs the `ChainMismatch` cross-check); `verify_owner` runs inside, so
  the submission type is only constructible from an owner-verified `OrderCreation`.
  Signer taken by value with `S: SignerSync` (alloy auto_impl covers `&S`), so both
  `.sign(wallet)` and `.sign(&wallet)` compile.
- Rename `SignedOrderSubmission` to `OrderSubmission` (maintainer nomenclature);
  `submit()` PUTs the canonical app-data JSON before POSTing (TradingClient parity,
  subject to open question 6).
- `impl From<&AppDataDoc> for QuoteAppData`; delete the `QuoteAppData::hash`/`full`
  identity constructors.
- `alloy-chains` optional dep; `TryFrom<NamedChain> for Chain`;
  `with_chain(impl Into<Chain>)` stays total.
- Const constructors `sell_before_fee` / `sell_after_fee` / `buy_after_fee` stay as
  DTO sugar for the low-level `api.quote(&request)` path (all production consumers);
  the `with_sell_amount` alias keeps one doc line saying it aliases `_before_fee`.

**Success Criteria**: the maintainer's chained example compiles (modulo `.try_into()?`
and `.with_from(..)`, both flagged to him); no pass-through builder layer remains; the
mock-transport pipeline test exercises the full chain without reqwest.
**Tests**: chain-compiles doc test; born-verified binding test; `verify_owner`
rejection test on the fluent path (previously impossible); typestate compile-fail
tests for missing required fields.
**Status**: Complete

## Stage 3: delete `TradingClient`

**Goal**: one pipeline, structurally enforced invariants. One PR, mostly deletions.

- Delete `TradingClient`, `SwapOrder`, `PostedSwapOrder` (~700 LoC source). The
  pipeline is a strict superset after Stage 2.
- CHANGELOG migration recipe mapping `post_swap_order` 1:1 onto the
  `quote_builder()` chain.
- Chain-hint-gated `verify_owner` chokepoint inside `OrderBookApi::post_order`
  (verified: passes EIP-1271/PreSign with non-zero `from`, rejects zero-`from`; breaks
  no contract-wallet flow). Drop `cow-sdk-wasm`'s now-redundant pre-flight if the
  chokepoint lands (open question 4).
- Port `TradingClient`'s oversize-app-data test onto the pipeline via
  `with_app_data(&doc)`.
- Re-export `SignerSync` from `cowprotocol-signing` so orderbook's optional
  `alloy-signer` dep can go, without reversing commit 4f47a11's feature gating intent.

**Success Criteria**: one quote-sign-submit implementation in the workspace; grep for
`verify_owner` shows the chokepoint plus tests only.
**Tests**: all `TradingClient` behaviour tests ported to the pipeline before deletion
(R24 fail-fast, app-data pinning race, chain mismatch).
**Status**: Complete

## Stage 4: transports under one roof, subgraph generification

**Goal**: `cowprotocol-orderbook/src/transport/{mod,reqwest,fetch}.rs`; subgraph rides
the shared transport. First of two WASM-crux PRs (~850 LoC).

- Move `ReqwestTransport` + the capped readers (`read_capped_body` streaming cap) into
  `transport/reqwest.rs`, gated on `cfg(feature = "http-client")` ONLY in this PR (the
  `not(wasm32)` arm waits for Stage 5 so the existing wasm32 all-features CI check
  stays green at every commit).
- `HttpRequest` grows a redacted bearer field (name TBD: `bearer` vs `bearer_token`,
  keep `SubgraphClient`'s field consistent); extend the existing
  `debug_does_not_leak_bearer_token` test to `HttpRequest`'s `Debug`.
- `SubgraphClient<T: HttpTransport = DefaultTransport>`: deletes the byte-identical
  `build_client`/`read_capped_text` duplicates and inherits the streaming cap (the
  current copy materialises hostile bodies before capping).
- Wiremock test pinning that subgraph `execute` keeps raw
  non-2xx -> `Error::UnexpectedStatus` (must NOT silently adopt
  `into_status_error`'s ApiError decode during the rewrite).
- While in subgraph: collapse `last_days_volume`/`last_hours_volume` onto one `$first`
  helper; render `GraphQl` error's `first` in `Display` instead of storing it.

**Success Criteria**: zero duplicated transport plumbing (grep `build_client`,
`read_capped_text` returns nothing); subgraph capped-streaming test passes.
**Tests**: streaming-cap test for subgraph path; bearer redaction; status-mapping pin.
**Status**: Complete

## Stage 5: wasm32 target switch, meta crate as the single entry point

**Goal**: `cargo add cowprotocol` works on both targets; `cow-sdk-wasm` is JS bindings
only. Second WASM-crux PR (~800 LoC).

- `FetchTransport` moves to `transport/fetch.rs` under
  `cfg(all(feature = "http-client", target_arch = "wasm32"))`; target-resolved
  `pub type DefaultTransport` becomes `OrderBookApi`'s default param. Delete the wasm32
  reqwest target dep and the buffered fallback in the same commit.
- Fix the cap-after-copy hole during the move: check `js_sys::JsString::length()`
  before `as_string()` (UTF-16 units lower-bound the UTF-8 size), keep the exact
  post-copy check as backstop. The module doc's security claim becomes true.
- `cow-sdk-wasm` shrinks to `#[wasm_bindgen]` exports + serde-wasm-bindgen glue:
  delete its `transport.rs`; `endpoints::client(chain)` collapses to
  `OrderBookApi::new(chain)`; demote `js-sys` to a wasm32 dev-dependency (browser tests
  stub `globalThis.fetch` with it; do NOT delete it).
- Delete the duplicated `parse_scheme`/`scheme_to_str` wire mappings (serde already
  defines them on `EcdsaSigningScheme`); add the `get_fn` Reflect helper.
- CI: cargo-tree guard asserting reqwest never enters the wasm graph; `cargo check -p
  cowprotocol --no-default-features --target wasm32-unknown-unknown`; wasm32 clippy
  `-Dwarnings` lane; docs.rs `targets` metadata on orderbook + meta crates.
- Meta crate / README docs: `cowprotocol` is the single entry point for native and
  wasm Rust consumers (the Flutter+Rust wallet shape); `cow-sdk-wasm` is JS-only.
- Measure the wasm size ceiling (737280 bytes) before the shim-flip commit; agreed
  escape hatch: transport-only sub-feature split if DCE does not strip the unused
  pipeline types.
- Pre-verify on rust 1.91 that `dep:` feature entries naming optional target-table
  deps resolve for both targets; fallback documented (non-optional wasm32 target deps,
  cfg-gated).

**Success Criteria**: a Rust-wasm consumer depends on `cowprotocol` alone and gets a
working `OrderBookApi` + `SubgraphClient`; wasm binary within ceiling; reqwest absent
from the wasm graph (CI-enforced).
**Tests**: browser suite green against the bindings-only shim; optional
`SubgraphClient<FetchTransport>` browser test; rustdoc note that bare wasm32 cfg also
matches wasip1/p2 (no JS host: compiles, fails at runtime, not a regression).
**Status**: Complete

## Stage 6: crate re-layering

**Goal**: every type in its canonical crate; dependency edges minimal. One PR.

- `Order`/`OrderStatus` (the GET response model, four `serde_json::Value` blobs) move
  from signing to orderbook, next to `OrderCreation`; `cowprotocol::` paths unchanged
  via re-exports. Signing crate sharpens to the 12 signed fields + hashing.
- `OrderClass`/`OrderUid` move to primitives; the appdata -> signing dependency edge
  (and its alloy-signer baggage) is deleted; appdata stops re-exporting the whole
  `order` module.
- Move `SignatureError::SignerMismatch` to the orderbook error enum that actually
  raises it, or document why it stays.
- Decide (mild, optional): `orderbook_base_url`/barn/gateway knowledge out of
  primitives so its dep set shrinks to alloy + serde + thiserror.

**Success Criteria**: `cargo tree -p cowprotocol-appdata` shows no signing edge;
signing crate has no serde_json in non-test surface.
**Tests**: existing suites; doc-link check stays clean after moves.
**Status**: Complete

## Stage 7: primitives hygiene

**Goal**: no dead API, no magic numbers, honest errors, interop-safe merkle. One PR.

- Delete `PollOutcome` (exported enum with no producer, no decoder, no consumer);
  reintroduce alongside a real polling feature with `from_revert_data` + vector tests.
- `Multiplexer`: adopt OZ `StandardMerkleTree` semantics (sort leaves by hash,
  complete-binary-tree layout); lock `root()` against a vector generated by
  `@openzeppelin/merkle-tree` (script in `test-harness/`); delete the
  "do not cross-publish" caveat. Behavioural change, loud CHANGELOG entry.
- `ProofLocation` `repr(u8)` enum (Private/Emitted/Swarm/Waku/Reserved/Ipfs) +
  `Proof::new`; kills the `U256::from(4)` magic numbers and makes both doc promises
  true.
- `UnsupportedChain` gets a real shape (`Id(u64)` / `Slug`), deleting the
  `UnsupportedChain(0)` sentinel; serde `expecting` string corrected; add `Serialize`
  (integer id) for boundary symmetry; test `"\"mainnet\""`.
- Demote `Signature::empty_for`/`zero_ecdsa` to a test helper (every consumer is test
  code; public constructor producing an invalid value of its own type).

**Success Criteria**: no public item without a non-test consumer or a decode path;
merkle root reproducible from JS tooling.
**Tests**: OZ-generated root vector; `ProofLocation` round-trip; chain slug error
message test ("unsupported chain slug" not "id 0").
**Status**: Complete

## Stage 8: legibility sweep

**Goal**: the remaining verified minors, batched by crate. One PR.
(appdata and signing items are Complete; orderbook items remain.)

- `order_book/tests.rs`: `assert_binding_rejects` helper collapses the ~15 copy-pasted
  mismatch tests (~450 -> ~80 LoC); group into `mod transport_cap / wire_shape /
  request_binding / validate / app_data`; move the two wiremock tests to
  `cowprotocol/tests/orderbook_mock.rs`.
- `cancellation.rs`: `eip712::single(uid)` / `eip712::collection(uids)` helpers route
  all five payload literals; `recover_owner`'s Vec clone disappears; drop the
  `self`-ignoring `SignedOrderCancellation::hash_struct` asymmetry.
- `signature.rs`: collapse the duplicated Eip712/EthSign arms in `from_bytes`/`recover`
  via `try_to_ecdsa_scheme()` + `as_ecdsa()`; delete the redundant EIP-1271 cap tests.
- `api.rs`: sync the cfg-twin struct docs (`chain: Option<Chain>` invariant written
  once, keep-in-sync marker); `send` takes `url::Url` so `get_json_with_query` stops
  bypassing it.
- appdata: builders route through `AppDataPartnerFee::new` (currently zero callers);
  `validate_fee_policy` goes private; tuple-match the `Deserialize` helper (~42 -> ~20
  lines, keep the hand impls, they are load-bearing); split the CID block into
  `app_data/cid.rs`.
- Keep or drop `Chain::settlement()`/`vault_relayer()` identity wrappers (decision:
  keep for forward-compat, note why, drop the `let _ = self;` idiom when a second
  table column exists).

**Success Criteria**: no copy-pasted logic flagged in the review remains; all suites
green; LoC net-negative.
**Tests**: behaviour-preserving; existing coverage carries.
**Status**: Not Started

---

## Sequencing notes

- Stages 0 and 1 are independent and can land immediately, in either order.
- Stage 2 depends on 1 (the single projection). Stage 3 depends on 2.
- Stages 4 and 5 are independent of 1 to 3 (different files) and can proceed in
  parallel with them; 5 depends on 4.
- Stages 6 to 8 are independent of each other; 6 should land before 8's signing-crate
  items to avoid double-touching moved files.
- Per the parallel-agents rule: if stages run concurrently, they touch disjoint files
  except `lib.rs` re-export lists; rebase those by hand.
- Each stage maps cleanly onto a Linear ticket in the rust-sdk project (COW-9xx) if
  ticket tracking is wanted.
