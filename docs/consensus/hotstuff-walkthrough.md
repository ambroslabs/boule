# A walkthrough of HotStuff

This document is a guided tour of the HotStuff consensus protocol as
implemented in this codebase. The audience is a CS graduate who has
seen leader-follower replication and basic distributed-systems
vocabulary (RPC, timeouts, leader election) but has not spent time
inside a Byzantine-fault-tolerant (BFT) protocol.

You should plan on about 45 minutes. The code samples are simplified
distillations of what `src/consensus/hotstuff/` actually does — the
real code carries production concerns (cache eviction, signature
schemes, snapshot loading, retry budgets) that obscure the protocol
itself. Wherever a sample omits something important, there is a
pointer to the real source.

After reading you should be able to:

- explain why HotStuff needs three chained QCs to commit a block,
- read the safety predicates in [src/consensus/hotstuff/safety_rules.rs](../../src/consensus/hotstuff/safety_rules.rs)
  and predict what they do,
- trace a single block from proposal to commit,
- explain what changes when the leader crashes.

Companion reading: [hotstuff-notes.md](hotstuff-notes.md) — a
condensed crosswalk between the HotStuff paper and our code, useful
once you want to map the simplifications below back to the paper's
notation.

---

## 1. The setting

A BFT replicated state machine has `n` replicas. Up to `f` of them may
be Byzantine: crashed, slow, or actively malicious. The system must
agree on a single ordered sequence of *commands*, even when some
replicas are lying about what they have seen. Honest replicas, given
the same prefix of committed commands, must always reach the same
state.

For the protocol to make progress at all you need
`n ≥ 3f + 1`. This is a fundamental result, not a HotStuff
quirk — it falls out of needing two non-overlapping quorums of size
`2f + 1` to be impossible. Every quorum of `2f + 1` validators
contains at least `f + 1` honest ones, and any two such quorums share
at least one honest replica. That single shared honest replica is
the "memory" that prevents conflicting decisions across views.

In our codebase the validator count is whatever
`ValidatorSet::len()` reports, and the quorum threshold is
[`quorum_size`](../../src/consensus/hotstuff/qc.rs):

```rust
/// HotStuff quorum threshold: 2n/3 + 1.
/// For n = 3f + 1 this equals 2f + 1.
pub const fn quorum_size(n: usize) -> usize {
    (2 * n) / 3 + 1
}
```

Plug in `n = 4` (the smallest interesting set): `quorum_size(4) = 3`,
so any three validators form a quorum and the system tolerates one
Byzantine replica.

### What's hard about this

The hard part isn't agreeing once. The hard part is agreeing
*repeatedly* in the face of network delays you cannot distinguish
from malice. A fast leader can finish a round quickly; a crashed
leader looks identical to a slow one to everyone else. We need a
protocol that makes progress whenever the network is well-behaved
("synchronous") *and* never produces conflicting decisions even when
it isn't ("asynchronous").

HotStuff is a member of the *partially synchronous* family: it
guarantees safety always, and liveness whenever the network is
synchronous for long enough. "Long enough" is a real-world tunable —
in practice tens to hundreds of milliseconds.

---

## 2. The shape of a HotStuff round

HotStuff structures the protocol around a sequence of *views*. Each
view has a designated leader. The leader proposes a block; the other
replicas vote on it; the votes get aggregated into a *quorum
certificate* (QC); the QC justifies the next view's proposal. If
nothing arrives within a timeout, the view changes and a new leader
takes over.

The big idea, the thing that distinguishes HotStuff from PBFT-style
protocols, is that votes never have to be "all-to-all". The leader is
the single point that aggregates votes into a QC, and the QC then
travels with the next proposal. This linearizes communication: each
view is `O(n)` messages, not `O(n²)`. (The original paper makes a
careful argument for this; we won't reproduce it here.)

### The wire types

There are exactly three message types in normal operation, plus one
for view changes:

```rust
// Simplified from src/consensus/hotstuff/qc.rs

/// A leader's proposal. Carries the new block and a QC over its parent.
pub struct Proposal {
    pub block: Block,
    pub justify: QuorumCertificate,
}

/// A replica's vote: "I think this block is safe at this view."
pub struct Vote {
    pub view: View,
    pub block_hash: BlockHash,
}

/// "I'm advancing to a new view; here's the freshest QC I know about."
pub struct NewView {
    pub high_qc: QuorumCertificate,
}

/// "I'm giving up on this view; please form a TC and move on."
pub struct TimeoutVote {
    pub view: View,
    pub high_qc: Option<QuorumCertificate>,
}
```

A `View` is just a `u64` counter that monotonically increases. A
`BlockHash` is a 32-byte SHA-256 hash. None of this is fancy.

`Proposal`, `Vote`, and `NewView` cover the happy path. `TimeoutVote`
is what lets the cluster recover when the leader is unresponsive —
we'll get to it in §10.

### The state of a single replica

Every replica carries a small bit of state that summarizes "what I
have observed so far":

```rust
// Simplified from src/consensus/hotstuff/state.rs

pub struct HotStuffState {
    /// View the pacemaker has us in.
    pub current_view: View,

    /// Highest-view QC we have seen anywhere.
    pub high_qc: Option<QuorumCertificate>,

    /// Block we have promised never to abandon (the "lock").
    pub locked: Option<Locked>,

    /// View of the most recent block we voted on.
    pub last_voted_view: View,

    /// Blocks we know about but haven't committed yet.
    pub pending_blocks: HashMap<BlockHash, Block>,
}
```

Read those four state-tracking fields carefully — they are *the*
load-bearing variables of HotStuff:

- `current_view` is "what view am I working on right now?"
- `high_qc` is "what's the freshest piece of evidence I have that the
  cluster has made progress?"
- `locked` is "what block have I committed not to vote against?"
- `last_voted_view` is "what's the latest view I have already cast a
  vote in?"

Everything HotStuff does, it does to keep these four variables
consistent with each other and with a quorum of honest peers.

---

## 3. Quorum certificates

A quorum certificate (QC) is a proof — verifiable by anyone holding
the validator set's public keys — that a quorum of validators signed
off on the same `(view, block_hash)` pair.

In our code:

```rust
// Simplified from src/consensus/hotstuff/qc.rs

pub struct QuorumCertificate {
    pub view: View,
    pub block_hash: BlockHash,

    /// Bitmap: bit `i` is set iff validator `i` signed.
    signers: SignerBitmap,

    /// One signature per signer (Ed25519) or one aggregate (BLS).
    signatures: QcSignatures,
}
```

Conceptually a QC says: "at least `2f + 1` validators saw this block
at this view and considered it safe." Once you have a QC, you can
forward it to any honest replica and convince them too — this is the
key property that lets HotStuff be one-leader-aggregates rather than
all-to-all.

Building a QC from votes is a small accumulation loop:

```rust
// Simplified from on_vote_received in src/consensus/hotstuff/step.rs

let mut qc = QuorumCertificate::new(vote.view, vote.block_hash, n_validators);
for vote in incoming_votes {
    let voter_idx = validator_set.index_of(&vote.signer)?;
    qc.add_signature(voter_idx, vote.sig);
    if qc.signer_count() >= quorum_size(n_validators) {
        // We have a quorum — the QC is now valid.
        break;
    }
}
```

The real `on_vote_received` keeps a *bucket* of in-progress QCs
(keyed by `(view, block_hash)`) so it can absorb late and out-of-order
votes, and it has to keep buckets bounded under flood; see
[step.rs:on_vote_received](../../src/consensus/hotstuff/step.rs).

### What a QC means

A QC over `(v, b)` carries information at three layers:

1. **Authentication**: the signatures verify against the validator
   set's public keys.
2. **Quorum**: at least one honest validator signed (because the
   quorum is `2f + 1` and there are at most `f` Byzantine replicas).
3. **Endorsement**: every honest signer believed `b` was safe at view
   `v` according to HotStuff's voting rule.

Layer 3 is the one HotStuff really cares about: a QC is the signal
"the cluster, by an honest-replica majority, considered this block
safe." It's the only piece of evidence in the protocol that crosses
view boundaries.

---

## 4. Blocks and the chain

Blocks form a tree (or, in the happy path, a linear chain) by
parent-pointers:

```rust
// Simplified from src/replication/block.rs

pub struct BlockHeader {
    pub parent_hash: BlockHash,
    pub height: u64,            // contiguous: parent.height + 1
    pub view: u64,              // monotonically increasing, may skip
    pub proposer: NodeId,
    // ...payload commitments
}

pub struct Block {
    pub header: BlockHeader,
    pub commands: Vec<Bytes>,
}
```

A few things to notice:

- **Height** is contiguous (parent + 1). It never skips.
- **View** is *not* contiguous — it can skip when views fail (no QC
  forms before the timer expires). View `v + 1`'s block can have
  `parent.view = v - 5` if views `v - 4..v` all failed.
- The *block hash* is a hash of the header. The header includes the
  parent hash, height, view, proposer, and payload commitments —
  enough that two distinct blocks at the same height under the same
  parent will hash differently.

The genesis block is special: its parent hash is all zeros, its
height is 0, its view is 0, and every replica constructs it
identically from the same initial-state commitment.

### The "chain" in chained HotStuff

When you walk a sequence of blocks via parent pointers, you get a
chain. Most of the time HotStuff is operating on this chain
linearly: each new block has the previous block as its parent.

But blocks are speculative until committed — the chain can fork.
Two competing leaders, each holding a different `high_qc`, could
each try to extend a different block. HotStuff's safety rules
ensure only one of those forks ever gets committed, and after the
fork resolves, the losing branch is dead but harmless.

---

## 5. A view, end to end

Let's walk through one happy-path view. Call it view `v`. The
cluster is healthy, no one is Byzantine, the network is fast.

```
                   leader of view v                replicas
                   ────────────────                 ────────
1. (already)       hold high_qc over block b_prev
2. build proposal: block b_v parented on b_prev,
                   justify = high_qc
3. broadcast       Proposal(b_v, justify=high_qc)
                                    ──────────────▶  receive proposal
                                                     check safe_to_vote
                                                     if safe: send Vote(v, b_v.hash)
4. collect votes  ◀──────────────  votes
   when we hit quorum:
   form QC_v over (v, b_v.hash)
   adopt QC_v as new high_qc
   advance pacemaker to view v+1
```

At the end of view `v`, every honest replica that voted has done two
things: bumped `last_voted_view` to `v`, and (if the proposal's
justify was fresher than what they had) adopted the proposal's
justify as their new `high_qc`.

That is *one round*. To turn one round into a commit, HotStuff
chains three of them.

### Why one round isn't enough

Here's the puzzle. After view `v` produces `QC_v`, the leader of view
`v + 1` knows the cluster considered `b_v` safe. But "safe" doesn't
mean "committed" — it means "no one will *ever* vote for a conflicting
block at the same height." The cluster could still time out before
view `v + 1` produces its own QC, and we'd never hear about `b_v`
again from the protocol's perspective. (It would still be in
`pending_blocks` on every honest replica, but nothing would ever
*finalize* it.)

To commit, we need not just a QC over `b_v`, but evidence that the
cluster *kept going from there*. That evidence is the next QC, and
the one after that. Three in a row.

---

## 6. The voting rule: safe_to_vote

Before we can talk about what gets committed, we need the rule for
*when an honest replica casts a vote*. This is the heart of HotStuff
safety. The actual function:

```rust
// Simplified from src/consensus/hotstuff/safety_rules.rs

pub fn safe_to_vote(proposal: &Proposal, state: &HotStuffState) -> bool {
    let view = proposal.block.header.view;

    // Rule 0: never vote twice in the same view.
    if view <= state.last_voted_view {
        return false;
    }

    // No lock yet → any fresh-view proposal is safe.
    let Some(locked) = state.locked else {
        return true;
    };

    // Rule 1 (extension): proposal extends our locked block.
    if extends(&proposal.block.hash(), &locked.block_hash, &state.pending_blocks) {
        return true;
    }

    // Rule 2 (liveness): proposal carries a justify newer than our lock.
    proposal.justify.view > locked.view
}
```

Three predicates, three jobs:

1. **Rule 0 (vheight monotonicity).** A replica never votes twice in
   the same view. This is a local invariant: it prevents an honest
   replica from contributing a vote to two conflicting QCs at the
   same view, which combined with the quorum size rules out two
   conflicting QCs ever forming. (Pigeonhole: each QC needs `2f + 1`
   signers, so two QCs at the same view would need `4f + 2 > n`
   distinct signers; impossible.)

2. **Rule 1 (extension rule, "safety").** If we are locked on a block
   `B`, we may vote for a proposal whose chain extends `B` — that is,
   walking the proposal's parent pointers eventually reaches `B`.
   This is the "I have committed not to abandon `B`, and this
   proposal does not abandon `B`" branch.

3. **Rule 2 (liveness rule).** If we are locked on a block `B` but the
   proposal does *not* extend `B`, we may still vote — *if* the
   proposal's justify is at a view strictly later than the view at
   which we locked. This is the trapdoor that lets the cluster
   recover from a temporary fork: if a quorum has moved past our
   lock, we should follow them.

Without Rule 2, a single bad-luck moment (one replica locks on a
block, the rest of the cluster never sees it) would deadlock the
chain forever. Rule 2 says "if a quorum's evidence is fresher than
my lock, the cluster has clearly moved on, so I can move on too."

The `extends` walk is just a parent-pointer chase:

```rust
// Simplified from src/consensus/hotstuff/safety_rules.rs

pub fn extends(
    block_hash: &BlockHash,
    ancestor_hash: &BlockHash,
    pending: &HashMap<BlockHash, Block>,
) -> bool {
    if block_hash == ancestor_hash {
        return true;
    }
    let mut current = *block_hash;
    loop {
        let Some(block) = pending.get(&current) else {
            return false;          // chain breaks here
        };
        let parent = block.header.parent_hash;
        if parent == *ancestor_hash {
            return true;
        }
        if parent == [0u8; 32] {
            return false;          // walked off the genesis sentinel
        }
        current = parent;
    }
}
```

The real version adds a visited-hash set to defend against cycles
crafted by Byzantine peers — see the comment in
[safety_rules.rs](../../src/consensus/hotstuff/safety_rules.rs).

### What the lock means, intuitively

"Locked on `B` at view `v_lock`" means: I have seen evidence (a
two-chain — see §8) that a quorum of honest replicas considered `B`
worth committing at view `v_lock`. I will not vote for any
*conflicting* block until I see fresher evidence that the cluster
has moved on.

The extension rule says: a proposal that extends `B` doesn't
conflict, so it's fine to vote for. The liveness rule says: if the
proposal can show me a justify newer than `v_lock`, the cluster has
clearly continued past my lock and I should catch up. Both rules
are essential — drop either and the protocol fails (one fails
safety, the other fails liveness).

---

## 7. The three-chain commit rule

Now we can describe how blocks get committed. Imagine four blocks in a
row, each with a QC justifying the next:

```
b1 ─QC1─▶ b2 ─QC2─▶ b3 ─QC3─▶ b4
view v1   view v2   view v3   view v4
```

The arrows mean "QCi was carried as the *justify* of the proposal that
produced bi+1." For the three-chain rule to fire and commit `b1`,
two conditions must hold:

1. **The chain is direct.** `b2`'s parent is `b1`, `b3`'s parent is
   `b2`, `b4`'s parent is `b3`. No skipped blocks.
2. **The views are consecutive.** `v2 = v1 + 1`, `v3 = v2 + 1`,
   `v4 = v3 + 1`. No skipped views.

When those hold, *and* you have just observed `QC3`, you commit `b1`.
Note: it's the QC over `b3` that triggers committing `b1` (the
oldest of the four blocks).

The simplified rule:

```rust
// Simplified from three_chain_commit in src/consensus/hotstuff/safety_rules.rs

pub fn three_chain_commit(new_qc: &QuorumCertificate, state: &HotStuffState) -> Option<Block> {
    let b3 = state.pending_blocks.get(&new_qc.block_hash)?;
    if b3.header.view != new_qc.view {
        return None;
    }

    let b2 = state.pending_blocks.get(&b3.header.parent_hash)?;
    if b2.header.view + 1 != b3.header.view {
        return None;  // view gap → skip
    }

    let b1 = state.pending_blocks.get(&b2.header.parent_hash)?;
    if b1.header.view + 1 != b2.header.view {
        return None;
    }

    Some(b1.clone())   // commit b1
}
```

(The function returns `b1` rather than committing it directly because
the safety core is pure — it returns what to commit, and the
integration layer applies it. We'll see this pattern again in §11.)

### Why three?

This is the single most-confusing part of HotStuff for newcomers.
The two natural questions are: "why three?" and "why consecutive
views?"

A QC over `b1` (call it `QC1`) means at least `2f + 1` replicas
voted for `b1`. By Rule 0, none of those replicas will *ever* vote
again at view `v1`. That's enough to rule out a *conflicting block at
view `v1`*. But it's not enough to rule out a conflicting block at
some later view extending a different parent.

A QC over `b2` extending `b1` (`QC2`) means at least `2f + 1`
replicas had Rule 1 satisfied by `b2`'s extension of `b1` — and
because `b2`'s justify is `QC1` (a view newer than any prior lock),
anyone holding an older lock could vote for `b2` via Rule 2. So
after `QC2` exists, every honest replica that holds a lock has a
lock at view `v1` or later. The two-chain has *promoted the lock*.

But locks at `v1` aren't safe enough. A Byzantine leader could still
build a competing chain by exploiting the liveness rule (Rule 2) —
finding a quorum willing to vote against the lock because the
liveness rule fires. The only way to truly close that escape hatch
is to push *every* honest replica's lock to *at least* `v2`. That
requires another round.

A QC over `b3` extending `b2` (`QC3`) means every honest replica
that voted has either updated its lock to `v2` (via the two-chain
between `b1` and `b2`) or had its liveness rule satisfied by a
justify of view `v2`. Either way, no honest replica can subsequently
vote for a block that conflicts with `b1` — both Rule 1 and Rule 2
will reject it.

That's why three. The three-chain is what gets every honest replica
*committed* to `b1`'s branch.

### Why consecutive views?

The paper's basic chain rule allows direct parents at any views; our
implementation, like most production HotStuff variants, requires
consecutive views (`v2 = v1 + 1`, etc.). This is a stricter
condition that gives the same safety guarantee in our world (where
heights are contiguous and views are independent) without needing
"dummy" padding blocks to fill view gaps. See
[hotstuff-notes.md#dummy-nodes-we-dont-use-them](hotstuff-notes.md#dummy-nodes-we-dont-use-them)
for the trade-off.

The cost is a liveness one: if any view in a candidate three-chain
fails, we don't commit that round, and we have to wait for three
more consecutive views. In practice this is fine — view failures
are rare in a healthy cluster.

---

## 8. The two-chain rule (locking)

The three-chain rule fires at *commit*. Two views earlier, the
two-chain rule fires at *lock*.

When you receive a proposal whose chain has the structure
`b ← b' ← b''` (block, parent, grandparent — with `b''` being the
proposed block's parent's parent), and `b'.height` is greater than
your current lock's height, you *promote* your lock to `b'`.

The simplified version:

```rust
// Simplified from on_proposal_received in src/consensus/hotstuff/step.rs

let parent_hash = proposal.block.header.parent_hash;
if let Some(parent) = state.pending_blocks.get(&parent_hash) {
    let grandparent_hash = parent.header.parent_hash;
    if let Some(grandparent) = state.pending_blocks.get(&grandparent_hash) {
        let current_height = state.locked.map(|l| l.height).unwrap_or(0);
        if grandparent.header.height > current_height {
            state.locked = Some(Locked {
                view: grandparent.header.view,
                height: grandparent.header.height,
                block_hash: grandparent_hash,
            });
        }
    }
}
```

So when a proposal at view `v` arrives, we look two blocks back. If
that grandparent's height beats our current lock, we promote. The
lock advances *one block* per healthy round.

Why height-based? See the comment in
[state.rs](../../src/consensus/hotstuff/state.rs) for the full
argument: views can skip, heights can't, and a Byzantine proposer
could use a synthetic-high-view sibling to mess with us if we
compared on view. Heights stay honest because they're constrained
to `parent.height + 1`.

### Lock + commit working together

Walking through the four-block chain `b1 ← b2 ← b3 ← b4` again:

- When the proposal for `b3` arrives, we have `b1 ← b2 ← b3`. The
  two-chain rule fires using `b3`'s grandparent `b1`: lock advances
  to `b1`'s height/view.
- When the proposal for `b4` arrives, we have `b2 ← b3 ← b4`. The
  two-chain rule promotes the lock to `b2`. Simultaneously, the
  proposal carries `QC3`, which is a QC over `b3`. We feed `QC3` into
  `three_chain_commit`: it walks `b3 ← b2 ← b1`, finds consecutive
  views, and returns `b1` for commit.

Lock advances by one block per round; commit fires two rounds later
on the block we locked on two rounds ago. That's the steady-state
rhythm of chained HotStuff.

---

## 9. The pacemaker: who proposes when

We've talked about *what* a leader does (build a proposal, justify it
with `high_qc`, broadcast it). We haven't talked about *who is leader
when*, and *what happens when nothing arrives*.

That's the pacemaker's job. It's deliberately separated from the
safety rules — see
[src/consensus/pacemaker/mod.rs](../../src/consensus/pacemaker/mod.rs).
Safety lives in the safety core; liveness lives in the pacemaker.
The two halves communicate via well-defined events.

### Who is leader?

The simplest scheme is round-robin:

```rust
// Simplified from src/consensus/pacemaker/leader.rs

fn leader_for_view(view: View, validators: &ValidatorSet) -> NodeId {
    let n = validators.len();
    *validators.get((view as usize) % n).unwrap()
}
```

Every replica computes the leader the same way for the same view,
because the validator set is deterministic and replicated. Validator
order is canonical (sorted bytes), so there's no disagreement.

### What happens on timeout?

Every replica arms a timer for the current view. If the timer fires
before a QC forms (i.e., before the cluster makes progress), the
replica suspects the leader is down. It broadcasts a `TimeoutVote`
saying "I give up on view `v`; here's the freshest QC I know about
(`high_qc`)."

When a quorum of `TimeoutVote`s arrive, they form a *timeout
certificate* (TC). A TC over view `v` is just as legitimate as a QC
for the purpose of advancing the pacemaker:

- `OnQc(v)` from the safety core → advance to view `v + 1`.
- `OnTimeoutCert(v)` from the dispatch layer → advance to view `v + 1`.

The pacemaker doesn't care which one fired. Either is "the cluster
moved past view `v`."

There's also a `OnRoundSync(v)` event that lets a single peer's
`TimeoutVote` pull a lagging replica forward (one signer is enough
evidence for "I should be at this view too" but not for QC-level
trust); see the comment on `Event::OnRoundSync` in
[pacemaker/mod.rs](../../src/consensus/pacemaker/mod.rs) for why
single-signer evidence is treated separately from QC adoption.

### View change with NewView

When a replica advances its view (due to QC, TC, or round-sync), it
broadcasts a `NewView` carrying its current `high_qc`:

```rust
// Simplified from on_pacemaker_advance in src/consensus/hotstuff/step.rs

fn on_pacemaker_advance(&mut self, v: View) -> Vec<Action> {
    self.state.current_view = v;
    let mut actions = Vec::new();
    if let Some(high_qc) = self.state.high_qc.clone() {
        actions.push(Action::Broadcast(ConsensusMsg::NewView(NewView { high_qc })));
    }
    actions
}
```

The new view's leader collects `NewView`s. When it's ready to
propose, it picks the freshest `high_qc` it has seen across all the
`NewView`s and uses it as its proposal's justify. This is what
prevents a leader from "rolling back" the chain by ignoring fresher
QCs in the cluster: even if it tried, an honest replica holding a
fresher QC wouldn't pass the liveness rule and would refuse to vote.

### Putting timeouts together

A view ends in one of three ways:

1. **Happy path**: leader proposes, replicas vote, QC forms. Pacemaker
   advances on `OnQc`. New leader proposes. New view starts.
2. **Timeout**: timer expires before a QC forms. Replicas broadcast
   `TimeoutVote`, a TC forms, pacemaker advances on `OnTimeoutCert`.
   The next leader, holding a `high_qc` from some earlier successful
   view, proposes a block extending it. The cluster picks back up.
3. **Round sync**: a lagging replica sees a single `TimeoutVote` for
   view `v > current_view`, jumps forward to `v` on `OnRoundSync`,
   then participates normally.

In all three cases, the safety rules continue to apply. The pacemaker
can drag a replica's view forward, but it can't make the safety core
vote for an unsafe block. That's the modularity discipline mentioned
at the top of `src/consensus/hotstuff/mod.rs`.

---

## 10. The safety core as a state machine

We've covered the rules in pieces. The actual driver that puts them
all together is `HotStuffCore::step`. The shape is:

```rust
// Simplified from src/consensus/hotstuff/step.rs

pub enum Event {
    ProposalReceived(Signed<Proposal>),
    VoteReceived(Signed<Vote>, Option<BlsPartialSig>),
    NewViewReceived(Signed<NewView>),
    PacemakerAdvance(View),
}

pub enum Action {
    Broadcast(ConsensusMsg),
    SendTo(NodeId, ConsensusMsg),
    Persist(StateUpdate),
    Commit(Block),
    RequestBlock { hash: BlockHash, peer: NodeId, /* ... */ },
}

pub fn step(&mut self, event: Event) -> Vec<Action> {
    match event {
        Event::ProposalReceived(p)   => self.on_proposal_received(p),
        Event::VoteReceived(v, b)    => self.on_vote_received(v, b),
        Event::NewViewReceived(nv)   => self.on_new_view_received(nv),
        Event::PacemakerAdvance(v)   => self.on_pacemaker_advance(v),
    }
}
```

The core is a *pure* state machine — no I/O, no clock, no network.
Inputs are events; outputs are actions. The integration layer is
responsible for turning actions into real effects (sending bytes,
syncing to disk, committing to the application state machine). This
is what lets the safety core run inside a deterministic simulator
(every test in `src/consensus/sim.rs` does this) and in production
unchanged.

### Walking through `on_proposal_received`

This is the longest of the four handlers and the most representative.
A simplified, all-the-rules-in-one version:

```rust
fn on_proposal_received(&mut self, signed: Signed<Proposal>) -> Vec<Action> {
    let proposal = signed.payload;
    let parent_hash = proposal.block.header.parent_hash;

    // B1: don't have parent → ask for it, park the proposal.
    if !self.state.pending_blocks.contains_key(&parent_hash) {
        self.parked_proposals.insert(proposal.block.hash(), signed);
        return vec![Action::RequestBlock { hash: parent_hash, peer: signed.signer, .. }];
    }

    // B2: insert the new block so safety walks can follow its chain.
    self.state.insert_pending(proposal.block.clone());

    let mut actions = Vec::new();

    // B3: vote if the proposal is safe; adopt its justify as high_qc.
    if safe_to_vote(&proposal, &self.state) {
        let view = proposal.block.header.view;
        let block_hash = proposal.block.hash();

        self.state.last_voted_view = view;
        actions.push(Action::Persist(StateUpdate::VotedInView { view }));

        if should_update_high_qc(&proposal.justify, &self.state) {
            self.state.high_qc = Some(proposal.justify.clone());
            actions.push(Action::Persist(StateUpdate::HighQc(proposal.justify.clone())));
        }

        actions.push(Action::Broadcast(ConsensusMsg::Vote(Vote { view, block_hash })));
    }

    // B4: two-chain lock promotion.
    if let Some(parent) = self.state.pending_blocks.get(&parent_hash) {
        let gp_hash = parent.header.parent_hash;
        if let Some(gp) = self.state.pending_blocks.get(&gp_hash) {
            let current_height = self.state.locked.map(|l| l.height).unwrap_or(0);
            if gp.header.height > current_height {
                let new_lock = Locked {
                    view: gp.header.view,
                    height: gp.header.height,
                    block_hash: gp_hash,
                };
                self.state.locked = Some(new_lock);
                actions.push(Action::Persist(StateUpdate::Locked(new_lock)));
            }
        }
    }

    // B5: three-chain commit.
    if let Some(committed) = three_chain_commit(&proposal.justify, &self.state) {
        let h = committed.header.height;
        actions.push(Action::Commit(committed));
        self.state.pending_blocks.retain(|_, b| b.header.height > h);
    }

    actions
}
```

That's the entire happy path: B1 handles missing parents, B2 inserts
the new block, B3 votes, B4 advances the lock, B5 fires the commit
when the three-chain materializes.

Notice the discipline: every state mutation that has to survive a
crash gets a paired `Action::Persist`. The pure core mutates its
in-memory state immediately, then *announces* what to persist. The
integration layer must sync the persistence before the corresponding
network broadcast leaves the machine. (Otherwise: crash after sending
a vote but before persisting the vote-view, restart, vote again at
the same view → safety violated.)

### Walking through `on_vote_received`

Aggregating votes into a QC:

```rust
fn on_vote_received(&mut self, signed: Signed<Vote>, _: Option<BlsPartialSig>) -> Vec<Action> {
    let vote = signed.payload;
    let next_view = vote.view + 1;

    let voter_idx = self.state.validator_set.index_of(&signed.signer)?;
    let key = (vote.view, vote.block_hash);

    let qc = self.vote_bucket.entry(key)
        .or_insert_with(|| QuorumCertificate::new(vote.view, vote.block_hash, n_validators));

    let had_quorum = qc.has_quorum(&self.state.validator_set);
    qc.add_signature(voter_idx, signed.sig);
    let has_quorum_now = qc.has_quorum(&self.state.validator_set);

    // Only fire the "QC formed" branch on the transition.
    if had_quorum || !has_quorum_now {
        return Vec::new();
    }

    let formed = qc.clone();
    let mut actions = Vec::new();

    // Adopt as high_qc if fresher.
    if should_update_high_qc(&formed, &self.state) {
        self.state.high_qc = Some(formed.clone());
        actions.push(Action::Persist(StateUpdate::HighQc(formed.clone())));
    }

    // If we are the next-view leader, propose immediately.
    if leader_for_view(next_view, &self.state.validator_set) == self.self_id {
        if let Some(parent) = self.state.pending_blocks.get(&formed.block_hash).cloned() {
            let new_block = self.builder.build(&parent, next_view, &formed);
            actions.push(Action::Broadcast(ConsensusMsg::Proposal(Proposal {
                block: new_block,
                justify: formed,
            })));
        }
    }

    actions
}
```

Two key behaviors:

1. **Every replica aggregates**, not just the leader. The original
   paper had voters address the next-view leader directly; we
   broadcast votes so a Byzantine or crashed next-view leader doesn't
   starve the protocol. Any honest replica that crosses quorum
   forms the QC.
2. **Idempotent on quorum.** Late votes after the QC is formed are
   silently absorbed; only the *transition* from sub-quorum to quorum
   triggers the proposal/persist actions.

### `on_new_view_received` and `on_pacemaker_advance`

These two are short. `on_new_view_received` simply adopts a fresher
`high_qc` if the sender's is newer:

```rust
fn on_new_view_received(&mut self, signed: Signed<NewView>) -> Vec<Action> {
    let qc = signed.payload.high_qc;
    if !should_update_high_qc(&qc, &self.state) {
        return Vec::new();
    }
    self.state.high_qc = Some(qc.clone());
    vec![Action::Persist(StateUpdate::HighQc(qc))]
}
```

`on_pacemaker_advance` records the new view, broadcasts a `NewView`
to advertise our `high_qc`, and (if we became leader) proposes:

```rust
fn on_pacemaker_advance(&mut self, v: View) -> Vec<Action> {
    self.state.current_view = v;
    let mut actions = Vec::new();
    if let Some(high_qc) = self.state.high_qc.clone() {
        actions.push(Action::Broadcast(ConsensusMsg::NewView(NewView { high_qc })));
    }
    if leader_for_view(v, &self.state.validator_set) == self.self_id {
        actions.extend(self.try_propose_as_leader(v));
    }
    actions
}
```

The real handler also un-parks proposals whose missing parents have
arrived, and drives a retry/backoff loop for outstanding
`RequestBlock` calls — see
[on_pacemaker_advance](../../src/consensus/hotstuff/step.rs).

---

## 11. Why it's safe (informal sketch)

Here's a hand-wavy version of why two honest replicas never commit
conflicting blocks. The full argument is the proof in Appendix B of
the HotStuff paper; this sketch is enough to convince yourself the
rules in §6–§8 hang together.

Suppose for contradiction that two honest replicas commit conflicting
blocks. Call them `b` and `b'`, at heights `h_b` and `h_b'`. Without
loss of generality, say `h_b ≤ h_b'`. Each replica committed via the
three-chain rule, so each has a chain of three QCs witnessing its
commit:

```
replica A:  b ─QC_b─▶ x ─QC_x─▶ y ─QC_y─▶ ...    (committed b)
replica B:  b' ─QC_b'─▶ x' ─QC_x'─▶ y' ─QC_y'─▶ ...    (committed b')
```

Walk back through B's three-chain. At every step there is a QC over a
block extending `b'`. By the two-chain rule, B's QC chain *promoted
the lock* of every honest replica that voted in those views to a view
≥ the view at which `b'` was proposed.

Now consider the QCs over `b`'s chain. If those QCs occurred at views
*later* than `b'`'s lock-promotion views, then every honest signer
must have either (a) voted via the extension rule, meaning their lock
was on `b'`'s ancestor *and* `b` extends `b'`, contradicting the
"conflicting" premise; or (b) voted via the liveness rule, meaning
their justify view exceeded their lock's view, which requires a QC
view past `b'`'s commit chain — a chain back into `b`'s commit chain,
which is what we're trying to prove can't intersect with `b'`'s.

If those QCs occurred at views *earlier* than `b'`'s lock-promotion
views, run the same argument the other way around using A's
three-chain.

The rigorous argument plugs in pigeonhole on the quorum-overlap of
honest signers (any two `2f + 1`-quorums share at least one honest
member), and shows that single honest member's `last_voted_view`
prevents them from contributing to both QC chains. The sketch here
is just to give you the shape: "lock + extension rule + monotonic
vheight" closes every escape hatch.

The property test in
[step.rs](../../src/consensus/hotstuff/step.rs) (search for
`property::`) randomizes Byzantine behavior, runs hundreds of seeds,
and verifies no two honest replicas ever commit conflicting blocks.
That test is the empirical encoding of the proof above.

---

## 12. Things we glossed over

This walkthrough was pedagogically simplified. Here's what real
HotStuff implementations have to deal with that we didn't show:

- **Cache eviction.** `pending_blocks`, the vote bucket, and the
  parked-proposals map all need bounded memory under flood. The real
  code has a per-cache cap and a victim-selection policy that won't
  evict blocks the safety walks need. See
  [state.rs](../../src/consensus/hotstuff/state.rs)
  and the `evict_*` helpers in
  [step.rs](../../src/consensus/hotstuff/step.rs).
- **Block sync.** When a proposal references a parent we don't have,
  we have to fetch it from someone. The real code has a retry/backoff
  loop with peer rotation; see `BlockSyncReason` and
  `try_emit_block_sync_retry` in
  [step.rs](../../src/consensus/hotstuff/step.rs).
- **Persistence ordering.** The integration layer must sync each
  `Action::Persist` to disk *before* flushing the corresponding
  network broadcast. Get this wrong and safety breaks across crashes.
  See the persistence-ordering section of
  [hotstuff-notes.md](hotstuff-notes.md).
- **Validator-set reconfiguration.** When the validator set changes,
  votes that span the boundary need to be validated against the
  *right* committee. The real code has a `ValidatorSetHistory` and
  consults it on every vote ingest.
- **Signature schemes.** Our QCs can carry collected Ed25519
  signatures (one per signer) or a single aggregated BLS signature.
  Aggregation matters at scale because QC size and verification cost
  drop from `O(n)` to `O(1)`. See
  [qc.rs](../../src/consensus/hotstuff/qc.rs).
- **Pacemaker timeout policy.** We didn't talk about how long the
  view timer should be. Production code uses an exponential backoff
  on consecutive failures; see
  [pacemaker/timeout.rs](../../src/consensus/pacemaker/timeout.rs).
- **The dispatch layer.** What we called "the integration layer" is
  in practice [src/consensus/dispatch.rs](../../src/consensus/dispatch.rs)
  and friends — it's the layer that owns signatures, the WAL, and the
  network, and turns inbound bytes into safety-core events.

---

## 13. Where to read next

The path that worked for the author of this document, in order:

1. Read this walkthrough.
2. Read [hotstuff-notes.md](hotstuff-notes.md) — the paper-to-code
   crosswalk. It will mention vocabulary that the paper uses but
   we've avoided here (`b''`, `vheight`, `genericQC`, etc.) and tell
   you which of our fields each paper concept maps to.
3. Read [src/consensus/hotstuff/safety_rules.rs](../../src/consensus/hotstuff/safety_rules.rs)
   end to end. It's short, well-commented, and contains the heart of
   the protocol's safety argument.
4. Read [src/consensus/hotstuff/step.rs](../../src/consensus/hotstuff/step.rs)
   in order: `on_proposal_received`, then `on_vote_received`, then
   `on_new_view_received`, then `on_pacemaker_advance`. The comments
   are deliberately verbose because the protocol is subtle.
5. Read the HotStuff paper itself: Yin, Malkhi, Reiter, Golan Gueta,
   Abraham. *HotStuff: BFT Consensus in the Lens of Blockchain.*
   arXiv:1803.05069v6. Section 5 (Chained HotStuff) and Section 6
   (Implementation) are the relevant ones; Appendix B is the safety
   proof. It's surprisingly readable once you've read the source.

Stuck somewhere? Open an issue or grep the codebase — every safety
rule in `safety_rules.rs` has a unit test in the same file, and most
of the subtle behaviors in `step.rs` are covered by named tests. The
tests are often the clearest specification of "what this rule
actually does".
