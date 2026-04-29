# HotStuff: notes for this codebase

Working notes on HotStuff as implemented (and planned to be implemented) in
`ambros-p2p`. Written while working on [#23][issue-23] (the milestone-7 parent)
and its sub-issues; referenced from code comments that would otherwise need
to re-derive the same tradeoffs.

This file is **not** a reproduction of the HotStuff paper. It is an
opinionated crosswalk between the paper's vocabulary and our code, plus the
design decisions where the paper leaves us a choice. Read the paper itself if
you want the full argument.

Looking for an introduction rather than a crosswalk? See
[hotstuff-walkthrough.md](hotstuff-walkthrough.md), a ~45-minute pedagogical
tour aimed at engineers new to BFT consensus.

## Paper reference

- Yin, Malkhi, Reiter, Golan Gueta, Abraham. *HotStuff: BFT Consensus in the
  Lens of Blockchain.* arXiv:1803.05069v6 (2019-07-23). Also PODC 2019.
- Citations below are to the arXiv v6 section numbering — Section 4 is "Basic
  HotStuff", Section 5 is "Chained HotStuff", Section 6 is "Implementation",
  Appendix B is the safety proof for the implementation pseudocode.

## What the safety core in this repo targets

We implement **Chained HotStuff** with **Section 6's relaxations** (sometimes
called "Event-driven HotStuff" in the paper):

- One message type on the wire for the normal case (`ConsensusMsg::Proposal`
  + `Vote`), plus `NewView` for view changes.
- Collected-signature QCs (one Ed25519 signature per signer + a
  `SignerBitmap`); BLS aggregation is out of scope.
- Relaxed high-QC / lock update (height-based), strict direct-parent
  requirement on three-chain commit.

Non-goals that sometimes confuse readers:

- We do **not** implement Basic HotStuff's four-phase pipeline. Section 5
  collapses it into a single `generic` phase; that's what we use.
- We do **not** do "dummy nodes" to pad view gaps. Section 5 needs them
  because Chained HotStuff numbers heights by views; we number heights
  contiguously and let views advance freely. See [Dummy nodes](#dummy-nodes)
  below for why this works.
- We do **not** do leader "proofs" (PBFT-style unlocking evidence); HotStuff
  doesn't need them because Three-Chain commit + QC-carried justify subsume
  the role.

## Vocabulary crosswalk

Paper name → where it lives in our code:

| Paper                          | Our code                                                      |
| ------------------------------ | ------------------------------------------------------------- |
| `genericQC`, `highQC`, `qcHigh` | `HotStuffState::high_qc`                                      |
| `lockedQC`                     | `HotStuffState::locked_qc`                                    |
| `vheight`                      | `HotStuffState::last_voted_view`                              |
| `block` (the locked *node*)    | Not a separate field — recoverable from `locked_qc.block_hash` |
| `bexec` (last executed node)   | Not stored; the integration layer (#24) tracks execution height |
| `V[·]` (vote bucket)           | `HotStuffCore::vote_bucket`                                   |
| `b0` (genesis)                 | `HotStuffState::genesis_hash`                                 |
| `getLeader()`                  | `round_robin_leader` in `step.rs`; pacemaker uses `LeaderSelector` |
| `safeNode(node, qc)`           | `safety_rules::safe_to_vote(proposal, state)`                 |
| `onReceiveProposal`            | `HotStuffCore::on_proposal_received`                          |
| `update(b*)`                   | Split across B3 (high-qc), B4 (lock), B5 (commit) in `step::step` |
| `onReceiveVote`                | `HotStuffCore::step` → `VoteReceived` arm (C1/C2, upcoming)   |
| `onNextSyncView`               | `PacemakerAdvance` → `Broadcast(NewView)` (C4, upcoming)      |
| `onReceiveNewView`             | `HotStuffCore::step` → `NewViewReceived` arm (C3, upcoming)   |
| `Pacemaker`                    | `consensus::pacemaker` (milestone 6, already landed)          |

The `b`, `b'`, `b''`, `b*` notation from the paper's `update` procedure is
used throughout these notes. Given an incoming proposal's block `b*`:

- `b''` is the block `b*.justify` is over — i.e., `b*`'s parent's block, if
  the proposer is well-behaved.
- `b'` is `b''.justify`'s block — grandparent of `b*`.
- `b` is `b'.justify`'s block — great-grandparent.

Walking backwards: `b ← b' ← b'' ← b*`.

## The safety predicate

`safeNode(node, qc)` in the paper is the disjunction of two rules (Algorithm
1, lines 25–27):

1. **Safety rule (extension):** `node` extends `lockedQC.node`.
2. **Liveness rule:** `qc.viewNumber > lockedQC.viewNumber`.

Either one is enough. Our `safety_rules::safe_to_vote` adds a third precondition
up front — `proposal.block.view > state.last_voted_view` — which the paper
enforces as a separate invariant ("vheight is monotonic"). Keeping all three
conditions in one predicate is fine: the composition is identical, and
bundling makes `safe_to_vote` honestly reflect what "may we vote?" costs.

The monotonic-vheight invariant earns its own remark in the appendix (§B.1,
"Why monotonic vheight"). Dropping it breaks safety even with the lock,
because a replica could double-vote across views before learning both chains.
Our `last_voted_view` field and the `view > last_voted_view` check exist
precisely to preserve this.

## The chain rules

Section 5, "One-Chain, Two-Chain, and Three-Chain". Given the four-node
lookback `b ← b' ← b'' ← b*`:

- **One-Chain** fires when `b*.parent == b''`. When a replica votes for `b*`,
  it should update `high_qc ← b*.justify`.
- **Two-Chain** fires when `b*.parent == b'' ∧ b''.parent == b'`. Update
  `locked_qc ← b''.justify` (the QC *over `b'`*).
- **Three-Chain** fires when `b*.parent == b'' ∧ b''.parent == b' ∧
  b'.parent == b`. Commit `b`.

The paper's Section 6 (Algorithm 4, `update(b*)`) then **relaxes One-Chain
and Two-Chain** to a pure height comparison, while keeping Three-Chain
strict:

```
procedure update(b*):
    b'' ← b*.justify.node
    b'  ← b''.justify.node
    b   ← b'.justify.node

    # One-Chain, relaxed: update on height, regardless of direct parents.
    updateQCHigh(b*.justify)

    # Two-Chain, relaxed: update on height, regardless of direct parents.
    if b'.height > block.height:
        block ← b'

    # Three-Chain, strict: direct parents required.
    if b''.parent == b' and b'.parent == b:
        onCommit(b)
        bexec ← b
```

The paper explicitly calls out why these relaxations are safe (end of
Section 5, and the proof in Appendix B). The direct-parent requirement on
commit is **not** optional: Appendix B.1 ("Why direct parent") gives a
specific attack that breaks safety if you weaken the Three-Chain rule.

## The `b''.justify` problem (relevant to B4)

Two-Chain lock promotion wants `locked_qc ← b''.justify`. That is the QC
over `b'`. Our design has a subtle mismatch here that we inherited from
milestone 7.A:

- The paper's `Block` carries its `.justify` field ([Alg 3], line 4:
  `b.justify ← qc`). Given `b''`, the paper reaches into `b''.justify`
  directly.
- Our `Block` (in `src/replication/block.rs`) carries only the header —
  `parent_hash`, `height`, `view`, `proposer`, state/commands commitments.
  The `justify` lives **outside the block**, on the `Proposal` wrapper.

Consequence: when we insert blocks into `pending_blocks` we lose the QC that
certified each one. To do Two-Chain lock promotion cleanly, we need to
recover `b''.justify` somehow. Options we've considered (to be resolved in
B4's design):

1. **Add a `QuorumCertificate` field to `Block`.** Biggest change; bloats
   every block by a signature set on the wire. Changes the block hash
   definition (or forces us to exclude the justify from the hash, which
   muddies `validate_structural`).
2. **Store a side map `state.qcs: HashMap<BlockHash, QuorumCertificate>`**,
   populated every time we receive a proposal (the proposal's `.justify`
   gets stored keyed by `justify.block_hash`). Small, local change. Requires
   us to skip lock promotion when the required QC isn't in the map
   (e.g. if we joined late). This is safe — the relaxation says we *may*
   skip any round.
3. **Lock on height only, without storing the QC at all** — track a
   `locked_height: u64` instead of `locked_qc: QuorumCertificate`. We'd
   lose the ability to ship the locked QC anywhere (e.g. in a `NewView`
   message), which 7.A's `NewView` explicitly carries as `high_qc`, not
   `locked_qc`, so this might actually work. Would need verification.

Option 2 is my current leaning: it's local, doesn't change block shape, and
a missing QC safely means "skip this round's lock update" which is a
permitted outcome. Decide explicitly in B4's implementation.

## Dummy nodes (we don't use them)

Chained HotStuff's `createLeaf` (Algorithm 3, line 2) pads with "blank
nodes" up to the current view's height, so view numbers equal node heights.
This matters because (a) the paper talks about "height" and means
"view number", and (b) the parent-pointer walk can skip over views where
nothing was decided.

Our `Block` has independent `height` (contiguous, `parent.height + 1`) and
`view` (monotonic but allowed to skip). We don't pad. Trade-off:

- Win: no blank nodes cluttering `pending_blocks`, simpler
  `validate_structural`, trivial replay.
- Cost: `b*.justify.node` may not equal `b*.parent` on the wire. The Section
  6 relaxation happens to tolerate this for One/Two-Chain (they just ask
  whether heights improved), so the only place it matters is Three-Chain
  commit. Our `three_chain_commit` in `safety_rules.rs` checks consecutive
  *views* on the three walked blocks, which is strictly stronger than
  direct parents in the dummy-node world — it gives us the paper's
  safety guarantee without the padding.

The cost of this choice is that our three-chain rule fires less often than
the paper's (it requires three consecutive views, no gap). That's liveness,
not safety. Liveness is the pacemaker's job; if the pacemaker is healthy,
view gaps close.

## Mapping to the codebase

### Already landed

| Component | Module | Landed in |
| --- | --- | --- |
| Wire types (`Proposal`, `Vote`, `NewView`, `ConsensusMsg`), `QuorumCertificate`, `SignerBitmap` | `consensus::hotstuff::qc` | [#94] (milestone 7.A) |
| `HotStuffState` | `consensus::hotstuff::state` | [#94] (milestone 7.B) |
| `extends`, `safe_to_vote`, `should_update_high_qc`, `three_chain_commit` | `consensus::hotstuff::safety_rules` | [#94] (milestone 7.B) |
| `Event` / `StateUpdate` / `Action` / `BlockBuilder` / `HotStuffCore` scaffold | `consensus::hotstuff::step` | [#95] (7.C A1–A6) |
| `ProposalReceived` dispatch: missing-parent, vote cast, high-qc adoption | `consensus::hotstuff::step` | [#96] (7.C B1–B3) |
| Pacemaker, leader selector, timeout policy | `consensus::pacemaker` | Milestone 6 |

### Upcoming — [#93] (milestone 7.C)

| Piece | Paper reference | Notes |
| --- | --- | --- |
| **B4** — Two-Chain lock promote | §5 "If b* forms a Two-Chain…"; §6 Alg 4 lines 8–9 | Resolve the `b''.justify` problem above before coding. |
| **B5** — Three-Chain commit + prune `pending_blocks` | §5 "Finally, if b* forms a Three-Chain…"; §6 Alg 4 lines 10–12 | Direct-parent check is mandatory (§B.1 "Why direct parent"). |
| **C1/C2** — `VoteReceived` leader path | §6 Alg 4 `onReceiveVote` | `vote_bucket` accumulates partials; quorum triggers QC assembly and a proposal broadcast via `BlockBuilder`. |
| **C3** — `NewViewReceived` → adopt `high_qc` | §6 Alg 5 `onReceiveNewView` | One-liner via `should_update_high_qc`. |
| **C4** — `PacemakerAdvance` → `Broadcast(NewView)` | §6 Alg 5 `onNextSyncView` | Also re-evaluates `parked_proposals` whose parents have since arrived. |
| **D2** — Happy-path three-chain test | — | Pins B4+B5 end-to-end. |
| **D7/D8/D9** — Parent-arrives / view-change / replay tests | — | See [#93] for exact contract. |
| **E-series** — Property test (no conflicting commits) | §A Theorem 5, §B Theorem 8 | The theorems are what the property test encodes. |

### Upcoming — [#24] (milestone 8, integration)

Concerns the paper talks about that land in the integration layer, not in
`HotStuffCore`:

- **WAL durability ordering.** Alg 4 mutates `vheight` / `block` /
  `qc_high` before responding on the wire. We mirror this with
  `Persist` actions that the integration layer must sync to disk
  **before** flushing the outbound `Broadcast` / `SendTo`. Crash-before-
  persist + send-after-restart would break the vheight monotonicity
  invariant (§B.1 "Why monotonic vheight").
- **Signature verification.** §6's pseudocode implicitly verifies every
  `partialSig` before adding to `V[·]`. In our split, `HotStuffCore`
  trusts the `Signed<T>` envelope; the integration layer runs
  verification on inbound bytes before handing us the event. This keeps
  the core pure (deterministic for replay) at the cost of an invariant
  the integration layer must uphold.
- **Clock + timers.** The paper's `nextView(viewNumber)` is pacemaker
  logic with a real clock. We've already factored it out of the safety
  core (milestone 6); the integration layer maps
  `Action::ResetTimer(Duration)` and `Action::AdvanceToView(View)` onto
  actual timers.
- **Block fetching.** The paper assumes branches are delivered before
  messages reference them (§4.2 "Tree and branches"). We don't make that
  assumption: `HotStuffCore` emits `RequestBlock(hash, peer)` when a
  proposal references an unknown parent, and parks the proposal. The
  integration layer turns that into an RPC.
- **BLS aggregation.** Referenced in §6 but explicitly a later
  optimization. Our `SignerBitmap + Vec<[u8; 64]>` layout leaves room
  to swap the representation later without touching the state machine.

### Longer horizon (no issues yet)

- **Dynamic validator sets.** The paper doesn't cover this. [#23] and
  [#24] explicitly call it a non-goal. Any future change will need to
  revisit how `validator_set` is threaded through `HotStuffState`.
- **Optimistic responsiveness tuning.** Section 8 of the paper measures
  this; our focus for now is correctness, not perf. When the
  integration layer lands, measure against the paper's numbers before
  touching the pacemaker's timeout policy.

## Quick proof sketch (Theorem 8, Appendix B)

For reference, since the E-series property test encodes the conclusion:

- Lemma 6: two conflicting nodes at the same height cannot both have valid
  QCs (pigeonhole on the `2f+1` honest voters).
- Lemma 7: two conflicting committed nodes would require the "first switching
  point" `qc_s` — a QC whose node conflicts with the older of the two. The
  lock held by the intersecting honest replica `r` rules out one half of
  `safeNode`'s disjunction; the minimality of `qc_s` rules out the other.
  Contradiction.
- Theorem 8: execution order agrees across honest replicas — an immediate
  corollary once Lemma 7 holds.

Everything the property test in E-series checks is Lemma 7 restricted to
"at the same height". If that lemma holds, every honest replica agrees on
committed blocks.

## References from the code

Code comments that reference this file should link the specific section:

```rust
// See docs/consensus/hotstuff-notes.md#the-bjustify-problem-relevant-to-b4
```

Prefer linking the section rather than re-deriving the tradeoff in a code
comment. Keep the notes in sync with the code; if the code deviates from
what's described here, update both.

[issue-23]: https://github.com/zrbecker/ambros-p2p/issues/23
[#93]: https://github.com/zrbecker/ambros-p2p/issues/93
[#94]: https://github.com/zrbecker/ambros-p2p/pull/94
[#95]: https://github.com/zrbecker/ambros-p2p/pull/95
[#96]: https://github.com/zrbecker/ambros-p2p/pull/96
[#24]: https://github.com/zrbecker/ambros-p2p/issues/24
