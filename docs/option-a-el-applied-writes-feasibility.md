# Option A: EL-applied registry writes — feasibility & strategy (#777)

Decision document for moving the `Registry` writes (`recordKey` / `recordWeight`
/ `recordSettled`) from **signed system transactions** to **EL-applied system
calls** (the EIP-4788 model), with a strong preference for using **reth as a
library/SDK** rather than forking its source.

Tracking: #777 (active — the chosen writer mechanism; we are resolving
SDK-vs-thin-fork now). Umbrella #769, milestone #726. Context:
[`validator-identity-onchain-auth.md`](validator-identity-onchain-auth.md) (the
#763/#764 split that selected Option A for the writer),
[`validator-registry-and-slashing.md`](validator-registry-and-slashing.md) (the
registry mirror, settled frontier, and EL-lag invariant).

## TL;DR recommendation

1. **Go A1, not A2.** Build a **custom `reth` binary** via the reth SDK
   (`NodeBuilder` + a custom `BlockExecutor` that applies our registry system
   call), and keep boule driving it **over the Engine API exactly as today**.
   Do **not** embed reth in-process in `boule-reth` (A2). The Engine API boundary
   stays; only the EL *binary* changes.
2. **SDK-composed custom binary, not a source fork.** The reth SDK exposes the
   exact seam we need (`ConfigureEvm` → `BlockExecutorFactory` → `BlockExecutor`,
   wired via `ExecutorBuilder`), it is the same seam reth itself uses for
   EIP-4788/2935/7002/7251, and there is a near-verbatim upstream template
   (`examples/custom-beacon-withdrawals`). A thin fork is the documented
   fallback if the seam regresses, but it is not needed today.
3. **Feed `recordWeight` from consensus via Engine API payload attributes**
   (option (b) below): boule passes the authoritative `(validator, weight)`
   deltas (and the rotated keys + settled view) into the EL as a **custom field
   on `PayloadAttributes`**, and the custom executor writes exactly those into
   `Registry` storage. The EVM-state-derivation options (a)/(c) do not work
   (Staking holds no balances) or re-introduce an in-EVM decoder we deliberately
   rejected.
4. **Rough effort:** ~1.5–3 weeks for a working A1 MVP behind the existing
   genesis/predeploy pins, dominated by (i) standing up the custom-binary crate +
   build/release path and (ii) plumbing the custom payload-attributes field
   through both reth's engine types and boule's `build_proposal`/`commit`. The
   executor logic itself is small (the template's custom logic is well under 200
   lines).

## A1 vs A2 — establish the blast radius first

This is the load-bearing distinction, and it makes Option A tractable. There are
two very different ways to "do A":

### A1 — custom EL *binary*, still driven over the Engine API (LIGHT) ✅ recommend

- Produce a **custom `reth` binary** whose block executor applies our registry
  system call at a block boundary (exactly where stock reth applies EIP-4788).
- boule keeps running it as an **external process** and keeps driving it over the
  **Engine API (V3/V4)** — `engine_forkchoiceUpdatedV3` / `engine_getPayloadV4`
  / `engine_newPayloadV4` — precisely as
  [`engine.rs`](../crates/boule-reth/src/engine.rs) does today.
- **`boule-reth` client code barely changes.** The deletions are larger than the
  additions: the whole signed-system-tx path goes away (see "Impact" below). The
  only *addition* on the boule side is putting the authoritative writes into the
  payload attributes on `build_proposal` and reading nothing back for them.
- The fork-vs-SDK question collapses to *"how is that custom binary produced?"* —
  and the answer is "by an SDK `NodeBuilder` assembly," see below.

### A2 — embed reth in-process in `boule-reth` (HEAVY) ❌ reject

- Pull reth's crates into boule's own build and run the node in-process,
  bypassing the Engine API.
- This is a far bigger change: it pulls the entire reth dependency tree into the
  workspace build (huge compile, `cargo deny`/license surface, version-pinning
  churn), couples boule's process lifecycle to reth's, and discards the clean
  deferred-execution Engine API boundary that the safety core relies on
  (`docs`/`lib.rs` layer diagram). It buys us nothing Option A needs: applying a
  system call does **not** require in-process embedding — it requires a custom
  *executor in the EL binary*, which A1 already delivers.

**Conclusion: A1 is viable and is the pragmatic target.** Everything below is
about producing the A1 custom binary.

## The executor seam (real APIs + the EIP-4788 template)

reth's EVM/execution layer was unified under one trait, **`ConfigureEvm`**, in
the 1.3.0 reshuffle (the old `ConfigureEvmEnv` + `BlockExecutionStrategyFactory`
were merged), and that is the shape in the 1.x/2.x SDK boule targets (local box:
**reth v2.2.0**; current major **reth 2.0**, April 2026). The relevant traits,
top-to-bottom:

- **`ConfigureEvm`** (`reth_evm::ConfigureEvm`) — the top-level EVM/execution
  config. It exposes `block_executor_factory()` and `block_assembler()` and is
  what a node component returns.
- **`BlockExecutorFactory`** (`reth_evm::execute::BlockExecutorFactory`) — its
  `create_executor(evm, ctx)` builds a per-block executor, given the
  `ExecutionCtx` (the per-block context that carries system-call inputs —
  withdrawals, beacon root, etc.).
- **`BlockExecutor`** (`reth_evm::execute::BlockExecutor`, re-exported as
  `reth_ethereum::evm::primitives::execute::BlockExecutor`) — the per-block
  executor with the hooks we need:
  - **`apply_pre_execution_changes()`** — runs *before* the block's txs. This is
    exactly where stock reth applies the **EIP-4788** beacon-root system call and
    **EIP-2935** block-hash history.
  - `execute_transaction*` / `commit_transaction` — the tx loop.
  - **`finish()`** — runs *after* the txs. This is where stock reth applies the
    **EIP-7002/7251** withdrawal/consolidation requests, and where the
    `custom-beacon-withdrawals` example injects its system call.
- **`ExecutorBuilder`** (`reth_node_builder` component builder) — the node-wiring
  trait; its async `build_evm(ctx)` returns our `ConfigureEvm`. Composed via
  `EthereumNode::components().executor(OurExecutorBuilder::default())` on the
  `NodeBuilder`.

### How reth's own system calls work (the template)

A system call is just an EVM call **from the system address** (`0xfffe…`-style,
no private key) to a fixed contract, executed outside the normal tx list, whose
state changes are committed into the block's state. reth drives these through a
`SystemCaller` / `evm.transact_system_call(...)` and then
`evm.db_mut().commit(state)`. Our registry write is structurally identical: a
call from the EL-only `SYSTEM` address to the `Registry` predeploy with our
`recordKey` / `recordWeight` / `recordSettled` calldata.

The canonical, copy-this template is upstream:
**`reth/examples/custom-beacon-withdrawals`** (added in v1.1.1, maintained
through 2.x). It implements all four traits above for a custom node and, in
`BlockExecutor::finish()`, calls a helper `apply_withdrawals_contract_call()`
that:

1. builds the system-call calldata,
2. invokes `evm.transact_system_call(SYSTEM_ADDRESS, WITHDRAWALS_ADDRESS, input)`,
3. handles a revert as a `BlockExecutionError`,
4. removes the transient touched accounts (system caller + beneficiary) from the
   resulting state so they don't pollute the state root,
5. commits with `evm.db_mut().commit(state)`.

It is wired into a node with:

```rust
let handle = builder
    .with_types::<EthereumNode>()
    .with_components(
        EthereumNode::components().executor(CustomExecutorBuilder::default()),
    )
    .with_add_ons(EthereumAddOns::default())
    .launch()
    .await?;
```

The custom logic in that example is **well under ~200 lines** of Rust, almost all
boilerplate trait-delegation to the inner `EthEvmConfig` / `EthBlockExecutor`
with one overridden hook. Our executor is the same shape: delegate everything to
the Ethereum executor, override the chosen hook to apply our registry writes.

**This confirms requirement (1) of #777 affirmatively:** the SDK exposes a
custom-block-executor / system-call extension point that mutates predeploy
storage at a block boundary, composable via `NodeBuilder` into a custom `reth`
binary — at the version boule targets, and it is reth's *own* mechanism for the
4788-family system calls, so it is as stable as any SDK surface gets.

### Pre- vs post-execution placement

Apply the registry writes in **`apply_pre_execution_changes()`** (the EIP-4788
slot), not `finish()`. Rationale: the registry writes are a pure deterministic
mirror that depends only on consensus inputs we pass in via payload attributes,
**not** on anything the block's transactions do. Applying them pre-execution
keeps them independent of tx outcomes and matches the EIP-4788 mental model
(record the block-boundary fact, then run the block). `recordSettled` and
`recordWeight` likewise depend only on consensus state, so all three belong
pre-execution. (The withdrawals example uses `finish()` only because beacon
withdrawals are conceptually post-block; ours are not.)

## API stability across reth releases

- The trait *names and shape* (`ConfigureEvm` / `BlockExecutorFactory` /
  `BlockExecutor` / `ExecutorBuilder`) have been the stable SDK surface since the
  1.3.0 unification and persist through 2.x. This is the **same** seam op-reth
  and AlphaNet build on — Paradigm explicitly frames the SDK as "build on, don't
  fork" and AlphaNet/op-reth are *built on* the node-builder API "without forking
  the node."
- That said, the SDK is **pre-1.0 as an API** in practice: method signatures and
  associated types (e.g. `ExecutionCtx`, the `SystemCaller` plumbing) have
  churned across minor releases (the 1.3.0 merge itself was a churn event). A
  custom-binary assembly will need a small touch-up on each reth upgrade. Crucial
  point for the strategy comparison: **this churn falls on the
  ~200-line executor assembly, which is exactly the SDK's contract** — and it is
  the *same* churn op-reth absorbs every release.

## SDK custom binary vs. a thin source fork — recommendation

| | **SDK-composed custom binary** (recommend) | **Thin source fork** (fallback) |
|---|---|---|
| What you own | A small `boule-el` crate: `NodeBuilder` assembly + one `BlockExecutor` (~200 LOC) | A patched checkout of all of reth + a rebase each upgrade |
| Upgrade cost | Re-pin reth crates; fix the ~200 LOC against evolved SDK traits | `git rebase` your diff onto each new reth tag; resolve conflicts across the *whole* executor path |
| Conflict surface | Bounded to the traits you implement | Anywhere your diff touches reth's execution code that upstream also changed |
| Precedent | op-reth, AlphaNet, shadow-reth — all built-on-not-forked | Taiko (deliberately isolates its fork surface; cited as the *thin-fork* model) |
| Risk if SDK regresses | Re-evaluate; worst case fall back to the fork | n/a (already forked) |
| License/`cargo deny` | reth crates as deps (already true for any A1 binary) | same |

**Recommendation: SDK-composed custom binary.** The maintenance argument is
decisive. A fork makes us re-derive and re-merge a diff against *all* of reth's
evolving execution path on every upgrade; the SDK confines the churn to the
~200-line assembly we own and that the SDK is contractually designed to support.
The work we'd do is the same work op-reth/AlphaNet do continuously and
successfully. The thin fork (Taiko-style, smallest isolated surface) remains the
explicit fallback **only** if a future reth release removes or hard-breaks the
custom-executor seam in a way the assembly can't absorb — which there is no
current sign of, since it is reth's *own* 4788 mechanism.

## The `recordWeight`-under-A design (the hard part)

The custom executor must write the **consensus-authoritative** validator weight
deterministically, identically on every replica's EL. Where does it get the
value? Three candidates:

- **(a) Read resulting EVM state after the block's staking txs.** ❌ Does not
  work. The `Staking` predeploy is a **pure event emitter that holds no
  balances in state** (`docs/validator-registry-and-slashing.md`; `staking.rs`).
  The authoritative weight lives **consensus-side** in `BondedStakeLedger`
  (#654), reconstructed from `Deposit`/`Withdraw`/`Slashed` events by
  `derive_validator_updates` in `application.rs`. There is no EVM-state value to
  read. (This is the exact reason Option B failed for `recordWeight` and we chose
  A at all.)
- **(b) boule passes the authoritative deltas into the EL via payload
  attributes; the executor writes exactly those.** ✅ **Recommended.** boule
  already computes the per-block `Vec<ValidatorUpdate>` (the genuine weight
  changes) in `commit` and the rotated keys / conservative settled view in the
  same place. We hand those to the EL as a **custom field on the engine
  `PayloadAttributes`** at `build_proposal` time, and the custom executor reads
  them out of its `ExecutionCtx` and applies the corresponding `recordWeight` /
  `recordKey` / `recordSettled` storage writes. This keeps consensus
  authoritative (the "mirror, not inversion" rule holds), needs no in-EVM
  decoder, and is deterministic across replicas because the payload — including
  our custom attribute — is part of the block every replica re-executes.
- **(c) The executor derives weight from the block's staking events.** ❌ Reject.
  It would re-implement `BondedStakeLedger`'s accounting (unbonding maturity
  #660, slashing #658b) inside the EL, and would have to decode consensus
  semantics in Solidity/Rust-in-the-EL — exactly the in-EVM-decoder coupling we
  rejected for rotations (`validator-registry-and-slashing.md`, "Rotations — NOT
  decoded in Solidity"). It also can't see `recordWeight`'s *settled* timing
  needs.

### What consensus must supply (option b, concretely)

A custom `PayloadAttributes` field — call it `bouleRegistryWrites` — carrying, for
the block being built:

- the rotated-key writes (`record_key_for_rotation` output: `validator`, `vEff`,
  128-byte EIP-2537 key) — already computed in `registry::record_key_for_rotation`;
- the seated-weight deltas (`ValidatorUpdate { node_id, weight }`) — already
  computed by `derive_validator_updates`;
- the conservative settled view (`conservative_settled_view(view)`) — already
  computed.

These are **exactly the three things the current signed-tx path already
assembles** (`record_rotated_keys` / `record_validator_weights` /
`record_settled_view`). Under A1 we stop *signing and submitting* them and
instead *attach them to the payload* and let the executor apply them.

### The determinism subtlety the migration must preserve

Today these writes are **proposer-only** and **async/lagged** — which is the root
of the whole #767 EL-lag/settled-frontier saga. Under A1, every replica's EL
applies the *same* writes from the *same* payload attributes during the block it
executes — **synchronously, in the block itself, no nonce races, no proposer
gating**. That:

- **collapses the #767 problem space**: `recordKey` and `recordWeight` now land
  in the *same* block whose effect they mirror (no lag between commit and
  record), so `keyAt`/`weightOf` are never stale at the committed frontier. The
  conservative `SETTLED_VIEW_MARGIN` + execution-confirmation gate exist
  precisely to paper over the async-tx lag; with synchronous in-block writes most
  of that machinery can be **retired or sharply simplified** (a follow-up to
  confirm, not assumed here).
- **removes the shared-nonce cross-proposer race** (#766/#767 axis 1) outright —
  there is no system account and no nonce.
- requires the custom field to be **part of the executed payload** (it is:
  payload attributes flow into the built block and are re-executed via
  `newPayloadV4`), so all replicas converge by construction — the same guarantee
  the design doc names under "Determinism across replicas."

> **One open question to nail in the spike/design:** the custom
> `PayloadAttributes` field must survive the build→propagate→re-execute round
> trip so a *non-proposing* replica's `newPayloadV4` applies the identical
> writes. In stock Ethereum, `PayloadAttributes` are a *building* input, not a
> field of the sealed block; the values that must persist (beacon root, etc.) are
> committed into the header/state. So our writes' **inputs** must be recoverable
> at `newPayloadV4` time on every node — either by committing a commitment to
> them into the block (header extra-data / a predeploy slot) or by deriving them
> from already-committed consensus data the EL can see. This is the single
> highest-risk detail of A1 and the first thing the spike should prove.

## Architectural & operational impact on `boule-reth`

### Boule client code (A1 — mostly deletions)

Removed / collapsed (from `application.rs`, `system_account.rs`, `registry.rs`):

- `submit_system_call`, `evm_chain_id`, `system_account_writes_settled`,
  `build_system_call`, the whole **`system_account` module**
  (`SYSTEM_ACCOUNT_PRIVATE_KEY`, `signer`, genesis funding alloc) — gone (#763's
  committed-key hole closed by construction).
- the proposer-only gating around `record_rotated_keys` /
  `record_validator_weights` / `record_settled_view` — gone; every replica's EL
  applies the writes.
- most of the #767 settled-frontier conservatism (re-evaluate; likely retire the
  margin/execution-confirmation gate once writes are synchronous).
- the `EngineTransport::send_raw_transaction` / `eth_get_transaction_count*`
  read-back surface used only by the writer.

Added:

- a custom `PayloadAttributes` field on the build path; the `recordKey` /
  `recordWeight` / `recordSettled` **calldata builders stay** (`registry.rs`) —
  the executor uses the same encodings, just applied as system calls.

The contracts change only their access gate: `recordKey`/`recordWeight`/
`recordSettled` move from `require(msg.sender == WRITER)` (a fundable EOA) to
`require(msg.sender == SYSTEM)` (the EL-only system caller). Bodies unchanged.
The genesis-seed path (`genesis_seed_storage`) is untouched.

### New artifact: the custom EL binary

- A new crate (e.g. `boule-el`) producing a `boule-reth-node` binary: a
  `NodeBuilder` assembly + one `BlockExecutor`/`ConfigureEvm`/`ExecutorBuilder`
  set. Depends on reth SDK crates (`reth-node-builder`, `reth-evm`,
  `reth-ethereum`, `revm`, `alloy-*`). **This is the only place reth crates enter
  the build**, and it builds a *binary*, not a lib boule links — so it does not
  pull reth into `boule-core`/`boule-consensus`.
- **Build/CI cost:** a reth-SDK build is large. Keep it a separate crate/binary,
  gate it behind a cargo feature or its own CI job, and throttle (`--jobs 3`).
  `cargo deny` must learn reth's license/advisory surface.
- **Ops:** `run-reth.sh` changes from `exec reth node …` to `exec
  boule-reth-node node …` (same flags, same Engine API, same JWT, same generated
  genesis). Deployment ships one extra binary. **Sync, Engine API, and the boule
  process model are unchanged** — this is the core A1 win.

### What does *not* change

- The deferred-execution model and the Engine API boundary (`engine.rs`).
- boule's process lifecycle (reth still a separate process).
- The genesis/predeploy generation (`build.rs`, `gen-genesis`), the staking /
  slashing / rotation / endpoint / param read paths (`eth_getLogs`), and the
  consensus `Application` seam.

## Spike status

**Not run as a live build** (deliberate, per #777's "don't sink hours into a full
reth build if the source already answers it"). A reth-SDK node build is huge and
the seam is already proven upstream: `examples/custom-beacon-withdrawals` *is* a
compiling, runnable custom-`BlockExecutor` node that applies a state-mutating
system call at a block boundary and is wired via `NodeBuilder` —
byte-for-byte the pattern A1 needs. The cheapest real spike, when we commit to
A1, is to **fork that example in a `boule-el` crate**, swap its
`apply_withdrawals_contract_call` for a one-line `recordSettled(view)` write to
the `Registry` predeploy, drive it from a throwaway payload-attributes field, and
confirm `settledView()` advances over the Engine API. That directly exercises the
one genuine unknown (custom payload-attrs surviving build→re-execute) and is a
day or two, not the multi-week MVP.

## Recommendation & effort estimate

- **Mechanism:** **A1** — custom reth binary via the **SDK**, driven over the
  unchanged Engine API. **Not** A2 (in-process embed), **not** a source fork.
- **Weight feed:** **option (b)** — consensus passes the authoritative
  `(keys, weights, settledView)` into the EL as a custom `PayloadAttributes`
  field; the executor applies them as system calls in
  `apply_pre_execution_changes()`. Inputs must be recoverable at `newPayloadV4`
  time on every replica (the #1 detail to prove).
- **Effort:** ~**1.5–3 weeks** for an MVP behind the existing pins:
  - ~2 days: `boule-el` crate from the withdrawals example; trivial system write;
    Engine-API spike proving custom payload-attrs round-trip. **(do this first —
    go/no-go on the open question)**
  - ~3–5 days: real executor applying all three writes from the attrs; contract
    gate `WRITER`→`SYSTEM`; multi-node determinism check (#766).
  - ~3–5 days: boule-side deletions (system account, signed-tx path, proposer
    gating), retire/simplify the #767 conservatism, CI/`cargo deny`/build wiring
    for the new binary.
- **Top risks / unknowns:**
  1. **Custom payload-attributes round-trip** (build → propagate → `newPayloadV4`
     on a non-proposing node). The whole determinism story depends on it; prove
     it in the spike before anything else.
  2. **SDK API churn** on reth upgrades — bounded to the ~200-line assembly, but
     real; it is the ongoing cost we're accepting (vs. a fork's rebase cost).
  3. **Build/CI weight** of a reth-SDK binary (compile time, `cargo deny`
     surface) — manageable with a separate crate + gated CI job.
  4. **#767 simplification is assumed, not proven** — synchronous in-block writes
     *should* let us retire the conservative settled frontier; confirm in design
     before deleting that safety machinery.

Relates #777.
