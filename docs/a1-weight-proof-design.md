# A1 — vote-time prevention of forged `extra_data` **weights** (#797 residual)

The remaining half of #797. #798 closed the **keys** and **settledView** halves
of the Byzantine-leader forgery: a non-leader now re-derives those two fields
from state it already holds at vote time (the proposed block's own rotation
commands; the block view) and refuses to vote on a mismatch
(`RethApplication::validate_registry_extra_data`). The **weights** field was left
as *detect-after-final* (`detect_weight_extra_data_divergence` logs a
`BFT-SAFETY-VIOLATION` at commit) because a voter cannot re-derive it at vote
time under deferred EL execution.

This doc records the **trace** that decided whether a *cheap* vote-time proof is
possible, the conclusion (**it is not** — only a receipt/MPT inclusion proof
works), and the concrete **option-1 design** for that heavier path, so the
heavy build is a deliberate decision rather than an accident.

> **Status: BUILT + gap-excuse closed (#797).** Option 1 (the receipt-inclusion
> proof) is implemented, and the **gap-excuse residual is now closed**: a proof
> anchors to the weight's **named source block within a bounded recent window
> `K`** (`MAX_WEIGHT_PROOF_ANCHOR_LAG`), not only the immediate parent, and a
> weight that names no resolvable in-window source is **rejected, not deferred**.
> A Byzantine leader can no longer pass a forged weight off as "too far back to
> verify". See [Implementation](#implementation-what-was-built) and
> [The gap-excuse fix](#the-gap-excuse-fix-797--reject-not-defer) at the end. The
> only weight case still left to commit-time detection is the *exact* post-
> `Withdraw` seated amount, which needs ledger state.

## TL;DR

- **The registry weight in `extra_data` is the same `ValidatorUpdate` quantity
  that drives the consensus reconfig** — both come from one
  `derive_validator_updates` call. So in principle the weight *is* backed by a
  consensus command.
- **But the cheap "match against a committed command the voter already holds"
  proof (option 2) is NOT viable**, on two independent grounds (either alone is
  fatal):
  1. **The materialised `ReconfigCommand` commits much later than the
     `extra_data` weight appears.** The weight rides the *very next* block
     (1-block lag); the command is minted only when this node is *leader* with
     no reconfig boundary already pending, then needs a 3-chain to commit, with
     `v_eff = view + 8`. At the instant a validator votes on block N, the command
     justifying N's weight is, in general, **not yet committed** (often not yet
     minted).
  2. **The voter's own derivation buffers lag EL execution.** Both
     `pending_weights` (→ `extra_data`) and `staged_validator_updates`
     (→ reconfig) are mutated **only at `commit`**, fed by
     `derive_validator_updates` reading staking/slashing **logs** of a block the
     EL has reported `VALID`. Under deferred/lagged execution a voter on block N
     **may not have executed** the block whose logs N's weight mirrors (its EL
     may still be `SYNCING`), so its buffers are **not guaranteed** to match the
     leader's. Rejecting on a buffer mismatch would be an **honest-rejects-honest
     liveness hole**.
- **Therefore only option 1 — a leader-carried receipt (MPT) inclusion proof of
  the `Deposit`/`Withdraw`/`Slashed` event against a committed block's
  `receiptsRoot` — is correct.** Per the structured task this is the STOP point:
  the MPT machinery is **not** built here. The design below is what to build if
  we take the heavy path.

## The weight flow (full trace)

Files: `crates/boule-reth/src/application.rs`,
`crates/boule-node/src/consensus_node/{commit,app_reconfig,action_interpreter,block_builder}.rs`,
`crates/boule-reth/src/{registry_payload,staking}.rs`.

A staking/slashing weight change has a single origin and then **forks into two
independent downstream channels** with **different lifecycles**:

```
Staking predeploy  Deposit/Withdraw  (Slashing predeploy  Slashed)
        │  emitted in EVM block B (== the EVM block of boule block K)
        ▼
RethApplication::commit(K)               ← only once the EL reports K VALID
        │  derive_validator_updates(K): eth_getLogs(B) → stake_source.apply/slash
        ▼
   Vec<ValidatorUpdate>  (node_id, absolute new seated weight)
        │
        ├─►  reconcile_pending_weights → self.pending_weights buffer (per replica)
        │          │  snapshotted at the NEXT build into block (K+1).extra_data
        │          ▼
        │     RegistryPayload.weights  →  extra_data of block K+1   ── 1-block lag
        │     (the EL mirror the Slashing/Governance predeploys read)
        │
        └─►  CommitResult.validator_updates → ConsensusNode.staged_validator_updates
                   │  minted ONLY when this node is leader & no boundary pending:
                   │  mint_staged_reconfig(view) → ReconfigCommand{changes,removes,
                   │                                v_eff = view + max(.., 8)}
                   ▼
             ReconfigCommand committed in some block ≥ K+1, applied at v_eff
             (the consensus-native validator-set change)
```

`staged_updates_to_reconfig` (`app_reconfig.rs`) shows the two are the **same
quantity**: a `(node_id, weight)` update becomes a `WeightChange{node_id,
weight}` (seated, weight>0) or a `remove` (seated, weight==0); `extra_data`
carries the identical `(node_id, weight)` pair. So the registry weight is *not*
an independent number — it mirrors the consensus update.

### Why the two channels' timing diverges (the crux)

| | `extra_data` weight (mirror) | `ReconfigCommand` (consensus) |
|---|---|---|
| **Lifecycle of the buffer** | `pending_weights`, cleared in `reconcile_pending_weights` once a committed block's `extra_data` mirrored the exact `(v,w)` | `staged_validator_updates`, cleared in `apply_committed_reconfigs` only when the **boundary lands** |
| **When it appears** | block **K+1** (the next block built, lag = 1) | a later block: requires **this node = leader** + **no pending boundary**, then a 3-chain to commit |
| **Effective at** | applied by the EL the moment K+1 is executed | `v_eff = view + max(min_v_eff_delay, MIN_V_EFF_DELAY, APP_RECONFIG_SETTLE_VIEWS=8)` |

`action_interpreter` calls `mint_staged_reconfig(view)` *then* `build_proposal`
in the **same** build, so when **this** leader both mints and builds in one shot,
the `ReconfigCommand` *can* land in the same block K+1 that carries the weight in
`extra_data`. But that is **not guaranteed**: the next builder may be a different
node; `mint_staged_reconfig` early-returns under the `pending` guard (a boundary
already in flight) or when nothing is actionable; and `staged_validator_updates`
persists (re-minted) across builds until the boundary lands. So a voter on K+1
cannot assume the justifying command is in K+1 or in any already-committed block.

### Why a voter can't just re-derive it (deferred execution)

`derive_validator_updates` runs inside `commit` **only on `ElStatus::Valid`** and
reads `eth_getLogs` for the just-executed block. Under deferred execution a voter
on block N is voting *before* it has necessarily executed N−1 (its EL may be
`SYNCING`; `build_proposal` itself bails with "reth EL still syncing" in that
state). So the voter's `pending_weights` / `staged_validator_updates` are a
function of **how far its EL has executed**, which lags consensus and differs
across honest replicas. Any vote-time check that compares `extra_data` weights to
those buffers can reject an **honest** leader purely from lag → a liveness hole.
This is exactly the reasoning #798 recorded for deferring weights.

**Decision: option 2 fails. STOP — do not build the MPT proof here.**

## Option 1 design (the heavy path, for the human to decide)

Make the weight **self-proving** in the proposal: the leader carries, alongside
the `extra_data` weight delta, a **Merkle-Patricia receipt-inclusion proof** that
the originating `Deposit`/`Withdraw`/`Slashed` **log** is in a block whose
`receiptsRoot` the voter can trust *without executing that block*. The voter
verifies the proof against that root and recomputes the weight delta from the
proven log — turning "trust the leader's number" into "verify a committed root +
a deterministic re-derivation".

### What the leader carries (per weight delta in `extra_data`)

For each `(node_id, weight)` the `extra_data` claims:

1. The **source EVM block identity** B (number + `receiptsRoot`) whose execution
   emitted the log — i.e. the EVM block of the boule block K whose `commit`
   derived this delta (the block one before the carrying block, by the lag).
2. The **receipt-trie inclusion proof**: the receipt's RLP and the MPT branch
   nodes from `receiptsRoot` down to it (a `Vec<Vec<u8>>` of trie nodes keyed by
   `rlp(receipt_index)`), plus the **log index** within that receipt.
3. Implicitly, the log's topics/data (recovered from the proven receipt), from
   which the voter recomputes the `StakeOp` (`parse_stake_logs` /
   `parse_slashed_logs`) and hence the same absolute weight `stake_source` would
   produce.

This rides a new `extra_data`/attribute section (or a sibling consensus field),
NOT the EL system-call payload — the EL still applies the bare write set; the
proof is consumed only by boule's `validate_proposal`.

### How the voter verifies (no EL execution)

In `RethApplication::validate_registry_extra_data` (extend the existing hook):

1. **Anchor `receiptsRoot` to committed consensus state.** The voter must obtain
   B's `receiptsRoot` from something it already trusts at vote time. Two sub-options:
   - **(1a) parent-chain anchor.** B is the EVM block of boule block K, and K is
     an **ancestor already in `pending_blocks`** (the proposed block's parent
     chain) whose execution payload the voter has the bytes of. The voter reads
     `receiptsRoot` straight from K's execution payload — *no proof of the root
     needed*, only the receipt-inclusion proof *into* it. This is the cheapest
     anchor and matches the 1-block lag (K = carrying_block − 1).
   - **(1b) committed-frontier anchor.** Use `BlockHeader::committed_state_root`
     (the lagged EL state root over the committed frontier the header already
     commits to, reproducible by a voter at `committed_height`) and prove
     `receiptsRoot` under it via a second (state-trie) proof. Strictly heavier;
     only needed if the source block is below the parent chain the voter holds.
   For the 1-block-lag common case **(1a) suffices** and is far cheaper.
2. **Verify the MPT receipt-inclusion proof** against that `receiptsRoot`:
   walk the provided trie nodes from the root hash, hashing each (keccak256) and
   following the nibble path of `rlp(receipt_index)`, terminating at the claimed
   receipt RLP. Reject on any hash/branch mismatch.
3. **Re-derive the weight from the proven log** and compare to the `extra_data`
   claim. The log → `StakeOp` decode is the existing `parse_stake_logs` /
   `parse_slashed_logs`; applying it to the voter's `stake_source` view of that
   validator must produce the claimed absolute weight. Reject on mismatch, or if
   the proven log's `node_id`/amount don't match the claim, or if a claimed
   delta has **no** backing proof.

A forged weight then has **no valid receipt proof** (the leader cannot fabricate
a log under a real `receiptsRoot` without a real EVM execution), so it is
**rejected at vote time** — closing the residual.

### Cost & risks

- **New machinery:** an MPT (receipt-trie) verifier — keccak256 + RLP + nibble
  traversal. boule has no MPT verifier today; reth's `alloy-trie`/`alloy-rlp` are
  in the (separate-workspace) EL but **not** a `boule-reth` dependency. Either
  pull a vetted `alloy-trie`/`alloy-rlp` into `boule-reth` (dependency-surface +
  `cargo deny`) or write a minimal audited verifier. This is the bulk of the cost.
- **Proposal size:** a Merkle proof per weight delta (a few hundred bytes to a
  few KB each). Weight deltas are rare (only blocks with staking/slashing events),
  so amortised cost is low, but a slashing storm could fan out proofs.
- **Anchor correctness:** (1a) requires the source EVM block to be on the
  proposed block's held parent chain — true for the 1-block lag, but a
  self-synced-gap commit (`backfill_self_synced_gap`) could push the source below
  what a lagging voter holds, forcing (1b). The design must pick (1a) with a
  documented fallback to (1b)/detect-at-commit when the anchor isn't held.
- **Determinism:** the proof is verified, not re-executed, so it adds no
  nondeterminism; honest leaders always produce a valid proof, so no
  honest-rejects-honest (the liveness property option 2 violated).

### Recommendation

Build option 1 with the **(1a) parent-chain `receiptsRoot` anchor** for the
common 1-block lag, falling back to commit-time detection (today's behaviour)
only for the rare case where the source block isn't on the voter's held chain.
Pull `alloy-rlp` + `alloy-trie` (already in the workspace's lockfile via the EL)
rather than hand-rolling the MPT verifier, gated behind `cargo deny`. Until then,
weights remain **detect-after-final**, which #798 already surfaces loudly.

## Implementation (what was built)

Option 1 with the **(1a) parent-chain `receiptsRoot` anchor** is implemented in
`crates/boule-reth/src/weight_proof.rs`, wired into the #798 vote-time hook.

### Pieces

- **Deps:** `alloy-trie` (`proof::verify_proof` verifier + `HashBuilder` /
  `ProofRetainer` builder), `alloy-rlp`, `nybbles` — all already in the
  workspace lockfile via the EL tree, so `cargo deny` is unaffected. The receipt
  is reconstructed into alloy's `ReceiptEnvelope` (explicit field parse, not
  serde-flatten) so its `encoded_2718()` is the exact trie-leaf bytes; a unit
  test (`our_trie_root_matches_alloy_for_each_index`) pins our hand-built trie
  root to alloy's canonical `ordered_trie_root_encoded`, so the proof anchors to
  the real `receiptsRoot`.
- **Carrier:** a **dedicated boule block command** tagged `WPR1`
  (`WeightProofSet`), *not* the registry `extra_data`. The EL still applies only
  the bare write set, so the cross-crate registry codec stays byte-pinned; the
  command is covered by `commands_commitment` and ignored by the EL and every
  `apply_committed_*` path (none recognise the tag).
- **Leader** (`build_proposal`): when the block's `extra_data` carries weight
  deltas, walk the recent source candidates (parent chain through
  `pending_blocks`, bounded to the window), fetch each candidate's receipts
  (`eth_getBlockReceipts`), and build a receipt-inclusion proof per delta against
  the first candidate carrying its log — **naming that source block's boule
  hash** in the proof (`anchor_block`). Usually the source is the parent (the
  1-block path). Best-effort on a receipt-fetch failure (the delta then falls to
  commit detection) rather than failing the proposal.
- **Voter** (`validate_proposal` → `validate_weight_proofs` →
  `WeightProofSet::verify_against_recent`): the hook receives a `RecentBlocks`
  resolver (the integration layer's `pending_blocks` **plus** the durable
  committed-block store), resolves each proof's **named source block**, reads its
  execution-payload `receiptsRoot`, verifies each carried proof against it, and
  re-derives each delta from the proven log.

### The gap-excuse fix (#797 — reject, not defer)

The original build anchored only to the **immediate parent**, so any weight whose
source was a few blocks back (a self-synced gap, or simply the normal commit-depth
lag) couldn't anchor and was **deferred** to commit detection. A Byzantine leader
could exploit that by claiming its forged weight's source was "too far back to
verify" — the **gap-excuse residual**.

The premise that closes it (verified in code): a weight delta is staged in
`pending_weights` at its **source block's commit** (a three-chain deep), and the
*next* built block snapshots the whole pending set — so an honest source is at
most the commit depth back from the block carrying the delta. The voter always
still holds that source: it is either an **uncommitted ancestor** (the safety
core's `pending_blocks`, retained for `height > committed`) or the
**just-committed frontier** (the durable block store the integration layer reads).
There is therefore **no honest reason** for a proposer to carry a weight whose
source it can't anchor to a recent committed block within a bounded window
`K = MAX_WEIGHT_PROOF_ANCHOR_LAG` (set generously above the commit depth so no
honest leader is ever rejected).

So the fix: each proof **names its source block**, the voter resolves it from the
recent window and verifies against **that block's** `receiptsRoot` (not only the
parent's), and a weight that names **no resolvable in-window source** is
**rejected** — closing the gap-excuse. The only weight case left to commit
detection is the *exact* post-`Withdraw` amount (it needs ledger state); every
other forgery, including the "too far back" excuse, is now refused at vote time.

### The prevented-vs-detected split the build settled on

Re-deriving the *exact absolute* seated weight at vote time needs ledger state
(prior balance + #660 unbonding maturity) a lagging voter may not hold, so the
verifier deliberately uses **only the proof + the proven log**, with **no
voter-side ledger state** — this is what keeps it lag-independent (no
honest-rejects-honest). With that constraint the sound, vote-time-**prevented**
guarantees are:

1. **Existence + node binding + in-window source.** Every weight delta MUST carry
   a valid MPT inclusion proof of ≥1 staking/slashing log **for that exact
   `node_id`** in the **named source block's** `receiptsRoot`, where that source
   is a block the voter holds within the recent anchor window `K`. No proof /
   invalid proof / wrong-node proof / **unresolvable-or-too-far-back source** →
   reject. This is the core #797 attack closed: a leader can't invent a weight
   from nothing (the fabricated-`Slashed` framing of an honest validator, or a
   governance/param-swinging weight — neither has a real log to prove), **and**
   can't dodge by claiming the source is "too far back" (the gap-excuse) — every
   claimed weight must name a held in-window source.
2. **`Slashed` pins weight 0.** A delta backed by a proven `Slashed` must claim
   weight `0`; a non-zero claim → reject.
3. **Deposit floor.** A pure-`Deposit` delta's absolute weight is
   `prior + Σdeposits ≥ Σdeposits > 0`, so a claim below the proven deposit sum
   (or `0`) → reject.
4. **Amount binding.** A carried proof whose own asserted weight disagrees with
   the `extra_data` claim for that node → reject.

**Detected-at-commit (not vote-time-pinnable), documented honestly:**

- The **exact post-`Withdraw` amount** (`prior − amount`) — `prior` is ledger
  state. The proof still binds the delta to a *real `Withdraw` for the claimed
  node* at vote time; the precise value is left to
  `detect_weight_extra_data_divergence`. **This is now the only deferred weight
  case** — the self-synced-gap / multi-block-lag source is no longer deferred
  (see below).

The **multi-block-lag / self-synced-gap source** (#674) is no longer deferred:
the proof names its source block and the voter anchors to **that** block's
`receiptsRoot` (resolved from `pending_blocks` or the committed store), so a
legitimate multi-block-lag weight is **accepted** and an unanchorable one is
**rejected**. This closes the gap-excuse residual.

### Tests (the bar)

`weight_proof.rs` and `application.rs` cover: an honest deposit validates with
its proof (1-block lag); a **legitimate multi-block-lag weight (source 3 back,
valid proof) is accepted** (the liveness bar); a weight naming an **unheld /
too-far-back source is rejected at vote time** (the gap-excuse exploit); a forged
weight with **no** receipt proof is rejected; a proof of a **different amount** is
rejected; a sub-deposit-floor claim is rejected; `Slashed` must claim 0; a
tampered proof under the named source's real root is rejected; and the codec
round-trips (now including the `anchor_block`). The cross-crate registry codec
determinism pin (`registry_payload.rs`) is untouched and still passes.
