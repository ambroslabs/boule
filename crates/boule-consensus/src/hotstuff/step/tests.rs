//! Unit tests and the shared fixtures they build on.
//!
//! We hand-construct `Signed<T>` envelopes rather than signing with
//! real Ed25519 keys: the safety core explicitly does **not**
//! verify signatures (that's the integration layer's job per #24),
//! so tests can put any byte pattern in the `sig` field and the
//! core will trust it. The upside is determinism — no keypair
//! generation in hot test paths — and the downside is that these
//! envelopes would be rejected on the wire, which is exactly the
//! boundary we want.
//!
//! `TestBlockBuilder` and friends live here rather than in a
//! separate `testing` submodule because clippy's
//! `items_after_test_module` forbids a second top-level test
//! module past this one; keeping everything under a single
//! `#[cfg(test)] mod tests` root makes room for future `mod
//! property` additions as nested submodules.

use super::*;
use crate::replication::block::BlockHeader;
use crate::validator_set::ValidatorSet;

// ── Fixture constants and helpers ────────────────────────────────

/// Stand-in [`NodeId`] constructor. Tests only ever identify nodes
/// by the discriminator byte, so `nid(3)` is shorthand for the
/// all-`0x03` node id that sorts into position 2 of the canonical
/// four-validator set.
pub(crate) fn nid(b: u8) -> NodeId {
    [b; 32]
}

pub(crate) fn vid(b: u8) -> crate::validator_set::ValidatorId {
    crate::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
}

/// The canonical four-validator set used across the step tests.
/// Sorted order matches the byte value: `[nid(1), nid(2), nid(3), nid(4)]`.
pub(crate) fn validators() -> ValidatorSet {
    ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)])
}

/// Build a [`Signed<Vote>`] whose `sig` bytes are
/// `[sender[0]; 64]` — distinct per sender so tests can inspect
/// QC signature ordering if needed. The core doesn't verify
/// signatures; any byte pattern is accepted.
pub(crate) fn signed_vote(
    view: impl Into<View>,
    block_hash: BlockHash,
    sender: NodeId,
) -> Signed<Vote> {
    let view = view.into();
    Signed {
        payload: Vote { view, block_hash },
        signer: sender,
        sig: [sender[0]; 64],
    }
}

/// Deterministic BLS keypair for `sender`, seeded from its NodeId so
/// the same sender always yields the same partial. The safety core's
/// vote handler folds partials via `add_bls_partial` without
/// verifying them against any registered pubkey, so this stand-in key
/// is sufficient to drive the BLS QC-formation path in unit tests.
pub(crate) fn bls_key_for(
    sender: NodeId,
) -> (
    boule_core::crypto::sig_scheme::BlsSecretKey,
    boule_core::crypto::sig_scheme::BlsPublicKey,
) {
    let mut ikm = sender;
    ikm[0] ^= 0xB1; // salt away from any other seed scheme in this file
    boule_core::crypto::sig_scheme::BlsAggregated::keygen(&ikm).expect("test BLS keygen")
}

/// Real BLS partial from `sender` over the canonical `(view,
/// block_hash)` Vote pre-image. Folds cleanly into a BLS
/// [`QuorumCertificate`] via `add_bls_partial`.
pub(crate) fn bls_partial(
    view: View,
    block_hash: BlockHash,
    sender: NodeId,
) -> boule_core::crypto::sig_scheme::BlsPartialSig {
    let (sk, _) = bls_key_for(sender);
    let preimg = boule_core::crypto::signed::preimage::<Vote>(
        &Vote { view, block_hash },
        &boule_core::crypto::signed::ChainId::TEST,
    )
    .expect("Vote preimage must succeed");
    boule_core::crypto::sig_scheme::BlsAggregated::sign_partial(&sk, &preimg)
        .expect("BLS partial signing must not fail")
}

/// Build a BLS-flavored [`VoteVariant`] carrying a real partial from
/// `sender` — the BLS analog of wrapping [`signed_vote`] in
/// [`VoteVariant::Ed25519`]. Use this everywhere a scheme-agnostic
/// safety/liveness test needs to feed a vote into the core.
pub(crate) fn bls_vote(
    view: impl Into<View>,
    block_hash: BlockHash,
    sender: NodeId,
) -> VoteVariant {
    let view = view.into();
    VoteVariant::Bls {
        signed: crate::dispatch::Verified::unchecked(signed_vote(view, block_hash, sender)),
        partial: bls_partial(view, block_hash, sender),
    }
}

/// Wrap an already-built [`Signed<Vote>`] in a BLS [`VoteVariant`],
/// deriving a real partial over the vote's own `(view, block_hash)`
/// under a deterministic key for the envelope's signer.
pub(crate) fn bls_vote_from_signed(signed: Signed<Vote>) -> VoteVariant {
    let partial = bls_partial(
        signed.payload.view,
        signed.payload.block_hash,
        signed.signer,
    );
    VoteVariant::Bls {
        signed: crate::dispatch::Verified::unchecked(signed),
        partial,
    }
}

/// As [`bls_vote_from_signed`] but stamping `stable_id` as the
/// resolved [`ValidatorId`](crate::validator_set::ValidatorId) on the
/// envelope — the BLS analog of
/// `Verified::unchecked_with_signer(signed, stable_id)`.
pub(crate) fn bls_vote_from_signed_with_signer(
    signed: Signed<Vote>,
    stable_id: crate::validator_set::ValidatorId,
) -> VoteVariant {
    let partial = bls_partial(
        signed.payload.view,
        signed.payload.block_hash,
        signed.signer,
    );
    VoteVariant::Bls {
        signed: crate::dispatch::Verified::unchecked_with_signer(signed, stable_id),
        partial,
    }
}

/// Build a [`Signed<NewView>`] from `sender` carrying `high_qc`.
/// Same zero-verification stance as the proposal/vote helpers.
pub(crate) fn signed_newview(high_qc: QuorumCertificate, sender: NodeId) -> Signed<NewView> {
    Signed {
        payload: NewView { high_qc },
        signer: sender,
        sig: [0u8; 64],
    }
}

/// Build an all-zero-signature [`Signed<Proposal>`] from `sender`.
/// The safety core never verifies the envelope; the `sig` bytes
/// are deliberately meaningless so tests stay deterministic.
pub(crate) fn signed_proposal(
    block: Block,
    justify: QuorumCertificate,
    sender: NodeId,
) -> Signed<Proposal> {
    Signed {
        payload: Proposal { block, justify },
        signer: sender,
        sig: [0u8; 64],
    }
}

/// Build a skeletal [`QuorumCertificate`] — right view and block
/// hash, no signatures populated — sized for the canonical
/// four-validator set. Adequate for the safety-rule predicates
/// because they only read `view` / `block_hash`.
pub(crate) fn dummy_qc(view: impl Into<View>, block_hash: BlockHash) -> QuorumCertificate {
    let view = view.into();
    QuorumCertificate::new(view, block_hash, validators().len())
}

/// Chain `views` blocks onto `genesis`, each parented to its
/// predecessor; `views[0]` becomes genesis's child. Height advances
/// alongside the index so the chain respects
/// [`crate::replication::block::validate_structural`].
///
/// `proposer` is stamped into every header; callers that need a
/// per-block proposer can mutate the returned blocks.
pub(crate) fn chain_from_genesis(genesis: &Block, views: &[u64], proposer: NodeId) -> Vec<Block> {
    let mut out = Vec::with_capacity(views.len());
    let mut parent_hash = genesis.hash();
    for (i, &view) in views.iter().enumerate() {
        let height = genesis.header.height + Height((i as u64) + 1);
        let view = View(view);
        let header = BlockHeader {
            parent_hash,
            height,
            view,
            proposer,
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        };
        let block = Block {
            header,
            commands: Vec::new(),
        };
        parent_hash = block.hash();
        out.push(block);
    }
    out
}

/// Deterministic [`BlockBuilder`] used wherever a core's
/// leader-path needs a block stamped out. Stamps an empty-commands
/// child with zero `state_commitment` — the execution layer is
/// out of scope here.
pub(crate) struct TestBlockBuilder {
    pub proposer: NodeId,
}

impl BlockBuilder for TestBlockBuilder {
    fn build(
        &self,
        parent: &Block,
        view: View,
        _high_qc: &QuorumCertificate,
        _pending_blocks: &HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> anyhow::Result<Block> {
        let header = BlockHeader {
            parent_hash: parent.hash(),
            height: parent.header.height + 1,
            view,
            proposer: self.proposer,
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: timestamp.max(parent.header.timestamp),
        };
        Ok(Block {
            header,
            commands: Vec::new(),
        })
    }
}

/// Build a fresh [`HotStuffCore`] whose `self_id` is `nid(self_byte)`
/// over the canonical four-validator set, rooted at a standard
/// all-zero-state-commitment genesis block.
pub(crate) fn make_core(self_byte: u8) -> HotStuffCore {
    let state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
    HotStuffCore::new(nid(self_byte), state)
}

/// Build an orphan block whose `parent_hash` is `orphan_parent` and
/// whose own contents are deterministic given the view. Used to
/// exercise the missing-parent dispatch branch.
fn orphan_child(orphan_parent: BlockHash, view: impl Into<View>, proposer: NodeId) -> Block {
    let view = view.into();
    let header = BlockHeader {
        parent_hash: orphan_parent,
        height: Height(1),
        view,
        proposer,
        state_commitment: [0; 32],
        commands_commitment: Block::commands_commitment(&[]),
        validator_history_commitment: [0; 32],
        committed_height: Height::ZERO,
        committed_state_root: [0; 32],
        timestamp: 0,
    };
    Block {
        header,
        commands: Vec::new(),
    }
}

// ── B1: missing-parent branch ───────────────────────────────────

#[test]
fn proposal_with_unknown_parent_parks_and_requests_block() {
    let mut core = make_core(1);
    let sender = nid(2);
    let orphan_parent: BlockHash = [0xAA; 32];
    let child = orphan_child(orphan_parent, 1, nid(3));
    let child_hash = child.hash();

    // Justify can be any QC — dispatch doesn't inspect it on the
    // missing-parent branch because it returns before the
    // safe-to-vote check.
    let justify = dummy_qc(View(0), core.state().genesis_hash);
    let signed = signed_proposal(child, justify, sender);

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    // Single RequestBlock aimed at the sender with the orphan
    // parent hash. The safety state is untouched: we have not
    // voted, not locked, not updated high_qc.
    assert_eq!(
        actions,
        vec![Action::RequestBlock {
            hash: orphan_parent,
            peer: sender,
            expected_height: Height(0),
            reason: BlockSyncReason::UnknownParentOnProposal,
        }],
    );
    assert!(core.parked_proposals.contains_key(&child_hash));
    assert_eq!(core.state().last_voted_view, View(0));
    assert!(core.state().locked.is_none());
    assert!(core.state().high_qc.is_none());
}

#[test]
fn reparking_same_proposal_is_idempotent() {
    // Repeated delivery of the same orphan proposal must neither
    // grow `parked_proposals` unboundedly nor silently drop the
    // second `RequestBlock` — the integration layer might resend
    // the probe if the first went unanswered.
    let mut core = make_core(1);
    let sender = nid(2);
    let orphan_parent: BlockHash = [0xAA; 32];
    let child = orphan_child(orphan_parent, 1, nid(3));
    let justify = dummy_qc(View(0), core.state().genesis_hash);
    let signed = signed_proposal(child, justify, sender);

    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed.clone()),
    ));
    let second = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    assert_eq!(
        second,
        vec![Action::RequestBlock {
            hash: orphan_parent,
            peer: sender,
            expected_height: Height(0),
            reason: BlockSyncReason::UnknownParentOnProposal,
        }],
        "re-delivery must still produce a RequestBlock so the \
             driver can retry the fetch",
    );
    assert_eq!(core.parked_proposals.len(), 1);
}

// ── B2 / B3: happy-path vote and HighQc adoption ─────────────────

// Round-robin leader for the canonical four-validator set:
// `[nid(1), nid(2), nid(3), nid(4)]`. view 1 → nid(2),
// view 2 → nid(3). These are hard-coded in the test assertions
// below on purpose — if the RoundRobinSelector mapping ever
// changes, the tests should fail loudly rather than silently
// keep using a stale leader.

#[test]
fn first_proposal_emits_persist_vote_and_adopts_high_qc() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let block = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
    let block_hash = block.hash();
    let justify = dummy_qc(View(0), genesis.hash());
    let signed = signed_proposal(block, justify.clone(), nid(2));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    assert_eq!(
        actions,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(1) }),
            Action::Persist(StateUpdate::HighQc(justify)),
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(1),
                block_hash,
            })),
        ],
        "happy-path emission order is VotedInView → HighQc → Broadcast(Vote)",
    );
    assert_eq!(core.state().last_voted_view, View(1));
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.view()),
        Some(View(0)),
        "high_qc adopted from the proposal's justify",
    );
}

// ── D3: vote-only-once at same view ──────────────────────────────

#[test]
fn second_proposal_at_same_view_emits_no_vote_but_emits_equivocation_evidence() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());

    // First proposal at view 1 — vote emitted.
    let block_a = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
    let block_a_hash = block_a.hash();
    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_a, justify.clone(), nid(2))),
    ));
    assert_eq!(core.state().last_voted_view, View(1));

    // Second proposal at view 1 with a DIFFERENT block from the
    // same leader. Same view, different state_commitment →
    // different hash. Two effects layer on top of each other:
    //
    // 1. The safe-to-vote view check rules out a second vote, so
    //    `last_voted_view` and `high_qc` stay put.
    // 2. The proposal-equivocation detector (audit finding L5-1)
    //    fires on the second arrival — distinct `block_hash`
    //    from the same `(view, leader)` is non-repudiable
    //    evidence of a Byzantine proposer — and emits exactly one
    //    `Action::ProposalEquivocationEvidence`. The fork is
    //    still admitted into `pending_blocks` so a later
    //    block-sync resolution against this hash succeeds.
    let block_b = Block {
        header: BlockHeader {
            parent_hash: genesis.hash(),
            height: Height(1),
            view: View(1),
            proposer: nid(2),
            state_commitment: [0xFF; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    };
    let block_b_hash = block_b.hash();
    let signed_b = signed_proposal(block_b, justify, nid(2));
    let second = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_b),
    ));

    assert_eq!(
        second,
        vec![Action::ProposalEquivocationEvidence {
            leader: vid(2),
            view: View(1),
            block_a: block_a_hash,
            block_b: block_b_hash,
        }],
        "a second proposal at the same view must emit only \
             ProposalEquivocationEvidence (no second vote): {second:?}",
    );
    assert_eq!(core.state().last_voted_view, View(1));
    // The forked block IS inserted into pending_blocks — the
    // core tracks the fork even though it won't vote on it —
    // which matters for the three-chain commit rule later.
    assert!(core.state().pending_blocks.contains_key(&block_b_hash));
}

// ── D4: refuse-to-vote when both extension and liveness fail ─────

/// Build a "fork at `view`, rooted on genesis" — the canonical
/// shape the safety-rule tests use to exercise non-extension.
fn fork_rooted_on_genesis(genesis_hash: BlockHash, view: impl Into<View>) -> Block {
    let view = view.into();
    Block {
        header: BlockHeader {
            parent_hash: genesis_hash,
            height: Height(1),
            view,
            proposer: nid(3),
            state_commitment: [view.0 as u8; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    }
}

#[test]
fn refuses_to_vote_when_not_extending_lock_and_justify_stale() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);

    // Lock the core on a block at view 5.
    let locked_block = chain_from_genesis(&genesis, &[5], nid(2))[0].clone();
    let locked_hash = locked_block.hash();
    let locked_height = locked_block.header.height;
    core.state.insert_pending(locked_block);
    core.state.locked = Some(Locked {
        view: View(5),
        height: locked_height,
        block_hash: locked_hash,
    });
    core.state.last_voted_view = View(5);

    // Fork at view 6 rooted directly on genesis (does NOT extend
    // the locked block at view 5) with a justify at view 3 —
    // strictly older than the lock. Neither the extension rule
    // nor the liveness rule fires; safe_to_vote returns false.
    let fork = fork_rooted_on_genesis(genesis.hash(), 6);
    let fork_hash = fork.hash();
    let stale_justify = dummy_qc(View(3), genesis.hash());
    let signed = signed_proposal(fork, stale_justify, nid(3));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    assert!(
        actions.is_empty(),
        "stale justify + non-extension must yield no actions: {actions:?}",
    );
    assert_eq!(
        core.state().last_voted_view,
        View(5),
        "last_voted_view untouched when refusing to vote",
    );
    assert_eq!(
        core.state().locked.map(|l| l.view),
        Some(View(5)),
        "lock is not disturbed by a refused proposal",
    );
    // The fork IS inserted into pending_blocks — a later proposal
    // whose chain happens to pass through this fork can still
    // walk through it; the safety rules, not the storage layer,
    // are what gate voting.
    assert!(core.state().pending_blocks.contains_key(&fork_hash));
}

#[test]
fn liveness_rule_permits_vote_on_fork_when_justify_fresher_than_lock() {
    // Companion to the refuse test above. Same lock setup, but
    // the fork's justify is view 9 > locked view 5. The liveness
    // rule fires and the core votes even though the fork does
    // not extend the locked block. Without this path, a slow
    // node that locked on a dead branch would never catch up.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);

    let locked_block = chain_from_genesis(&genesis, &[5], nid(2))[0].clone();
    let locked_hash = locked_block.hash();
    let locked_height = locked_block.header.height;
    core.state.insert_pending(locked_block);
    core.state.locked = Some(Locked {
        view: View(5),
        height: locked_height,
        block_hash: locked_hash,
    });
    core.state.last_voted_view = View(5);

    let fork = fork_rooted_on_genesis(genesis.hash(), 10);
    let fork_hash = fork.hash();
    let fresh_justify = dummy_qc(View(9), [0xEE; 32]);
    let signed = signed_proposal(fork, fresh_justify.clone(), nid(3));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    assert_eq!(
        actions,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(10) }),
            Action::Persist(StateUpdate::HighQc(fresh_justify)),
            // Votes are broadcast (not addressed to the next
            // leader) so that QC formation survives the next
            // leader being crashed — see `on_proposal_received`
            // (#124).
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(10),
                block_hash: fork_hash,
            })),
        ],
    );
    assert_eq!(core.state().last_voted_view, View(10));
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.view()),
        Some(View(9))
    );
}

// ── D5: Byzantine fork at same view from different proposers ─────

#[test]
fn byzantine_second_proposer_at_same_view_does_not_extract_a_vote() {
    // Distinct from D3's vote-only-once test: there the second
    // proposal came from the same proposer (shaped like a
    // retry). Here the second proposal comes from a DIFFERENT
    // validator — the Byzantine shape — pretending to lead the
    // same view. Either the view-freshness check or a
    // higher-level "wrong leader" filter could block this; the
    // test pins that *at least* the view-freshness check does,
    // which is the lower bound the safety core needs to uphold
    // regardless of what the integration layer (#24) filters.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());

    // The legitimate view-1 leader (nid(2)) proposes first.
    let block_a = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
    let block_a_hash = block_a.hash();
    let first = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_a, justify.clone(), nid(2))),
    ));
    assert!(
        first
            .iter()
            .any(|a| matches!(a, Action::Broadcast(ConsensusMsg::Vote(_)))),
        "legitimate first proposal is expected to produce a Vote: {first:?}",
    );

    // Byzantine nid(3) stuffs a conflicting block at the same
    // view. `safe_to_vote` rejects on view-freshness grounds;
    // the core emits no action at all.
    let block_b = Block {
        header: BlockHeader {
            parent_hash: genesis.hash(),
            height: Height(1),
            view: View(1),
            proposer: nid(3),
            state_commitment: [0xCC; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    };
    let block_b_hash = block_b.hash();
    let second = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_b, justify, nid(3))),
    ));

    assert!(
        second.is_empty(),
        "Byzantine fork must not extract a second vote: {second:?}",
    );
    assert_eq!(core.state().last_voted_view, View(1));
    // Both branches of the fork stay tracked in pending_blocks:
    // a future three-chain walk might need either of them, and
    // removing a block because we didn't vote on it would be a
    // storage leak back into safety semantics.
    assert!(core.state().pending_blocks.contains_key(&block_a_hash));
    assert!(core.state().pending_blocks.contains_key(&block_b_hash));
}

// ── B4: two-chain lock promotion ────────────────────────────────

#[test]
fn two_chain_promotes_lock_to_grandparent() {
    // Build genesis → block1 (view 1) → block2 (view 2), then
    // receive a proposal at view 3 whose parent is block2. The
    // two-chain walk reaches block1 as the grandparent; B4
    // promotes the lock to it. On the same step, B5's
    // three-chain walk `block2 → block1 → genesis` fires —
    // consecutive views 2←1←0 — so `Commit(genesis)` is also
    // emitted after B4's `Persist(Locked)`.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let prefix = chain_from_genesis(&genesis, &[1, 2], nid(2));
    let block1 = prefix[0].clone();
    let block2 = prefix[1].clone();
    core.state.insert_pending(block1.clone());
    core.state.insert_pending(block2.clone());

    // block3 extends block2 at view 3. We construct it via a
    // fresh `chain_from_genesis` so it descends from the same
    // block1/block2 we just inserted.
    let full_chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
    let block3 = full_chain[2].clone();
    let block3_hash = block3.hash();
    let justify = dummy_qc(View(2), block2.hash());
    let signed = signed_proposal(block3, justify.clone(), nid(2));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    let expected_lock = Locked {
        view: View(1),
        height: Height(1),
        block_hash: block1.hash(),
    };
    // Emission order: B2/B3 vote-prep persists (VotedInView,
    // HighQc), then B4 (Persist(Locked)), then B3's deferred
    // Broadcast(Vote), then B5 (Commit(genesis)). The Locked
    // persist precedes the Vote broadcast so the integration
    // layer's persist-before-send discipline flushes the new
    // lock to disk before the vote leaves the wire — the
    // Tendermint amnesia hole closed by audit finding 4-1
    // (#405).
    assert_eq!(
        actions,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(3) }),
            Action::Persist(StateUpdate::HighQc(justify)),
            Action::Persist(StateUpdate::Locked(expected_lock)),
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(3),
                block_hash: block3_hash,
            })),
            Action::Commit(genesis.clone()),
        ],
        "B2/B3/B4/B5 emissions in order",
    );
    assert_eq!(core.state().locked, Some(expected_lock));
    // Genesis was committed → pruned from pending_blocks.
    assert!(!core.state().pending_blocks.contains_key(&genesis.hash()));
    // Above the commit height survives.
    assert!(core.state().pending_blocks.contains_key(&block1.hash()));
    assert!(core.state().pending_blocks.contains_key(&block2.hash()));
}

#[test]
fn lock_persist_precedes_vote_broadcast_for_same_proposal() {
    // Audit invariant I4 / audit finding 4-1 (#405): when a single
    // `step()` produces both `Persist(StateUpdate::Locked)` (B4) and
    // `Broadcast(ConsensusMsg::Vote)` (B3) for the same proposal,
    // the Locked persist must come first. The integration layer
    // flushes every preceding `Persist` before each non-`Persist`
    // action, so this ordering is what guarantees the lock hits
    // disk before the vote leaves the wire — the Tendermint
    // amnesia hole closes only if both fragments hold.
    //
    // The shape mirrors `two_chain_promotes_lock_to_grandparent`,
    // but the assertion is structural rather than positional so
    // it survives unrelated additions to the action vector.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let prefix = chain_from_genesis(&genesis, &[1, 2], nid(2));
    let block1 = prefix[0].clone();
    let block2 = prefix[1].clone();
    core.state.insert_pending(block1.clone());
    core.state.insert_pending(block2.clone());

    let full_chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
    let block3 = full_chain[2].clone();
    let justify = dummy_qc(View(2), block2.hash());
    let signed = signed_proposal(block3, justify, nid(2));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    let lock_idx = actions
        .iter()
        .position(|a| matches!(a, Action::Persist(StateUpdate::Locked(_))))
        .expect("two-chain promotion must emit Persist(Locked)");
    let vote_idx = actions
        .iter()
        .position(|a| matches!(a, Action::Broadcast(ConsensusMsg::Vote(_))))
        .expect("safe-to-vote must emit Broadcast(Vote)");
    assert!(
        lock_idx < vote_idx,
        "audit invariant I4 violated: Persist(Locked) at index {lock_idx} must precede \
             Broadcast(Vote) at index {vote_idx}; otherwise a crash between vote-broadcast \
             and lock-persist would leave disk amnesiac. actions = {actions:?}",
    );
}

#[test]
fn two_chain_does_not_move_lock_backward() {
    // Preset the lock at a height strictly above anything the
    // proposal could promote to (it'd only see block1 at height
    // 1). A regression that always promoted would emit a stray
    // `Persist(Locked)` here; a regression that compared by
    // view instead of height could also silently rewrite the
    // lock.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let prefix = chain_from_genesis(&genesis, &[1, 2], nid(2));
    core.state.insert_pending(prefix[0].clone());
    core.state.insert_pending(prefix[1].clone());

    let preset = Locked {
        view: View(99),
        height: Height(99),
        block_hash: [0xAB; 32],
    };
    core.state.locked = Some(preset);

    // Proposal at view 100 extending block2; b' is block1 at
    // height 1 — strictly below the current lock at height 99.
    let block3 = Block {
        header: BlockHeader {
            parent_hash: prefix[1].hash(),
            height: Height(3),
            view: View(100),
            proposer: nid(2),
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    };
    let justify = dummy_qc(View(2), prefix[1].hash());
    let signed = signed_proposal(block3, justify, nid(2));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::Persist(StateUpdate::Locked(_)))),
        "lock must not move backward: {actions:?}",
    );
    assert_eq!(core.state().locked, Some(preset), "state.locked untouched",);
}

// ── B5: three-chain commit + prune ──────────────────────────────

#[test]
fn three_chain_commits_great_grandparent_and_prunes_below() {
    // Build a 4-deep chain past genesis: `v1, v2, v3, v4`. Pre-load
    // all of them into `pending_blocks`, then send a proposal at
    // view 5 whose parent is v4 and whose justify is QC(v4). The
    // three-chain walk from the justify (`v4 → v3 → v2`) is
    // strictly consecutive, so B5 commits v2 and prunes everything
    // at height ≤ 2.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let chain = chain_from_genesis(&genesis, &[1, 2, 3, 4], nid(2));
    for block in &chain {
        core.state.insert_pending(block.clone());
    }
    let block_v1 = chain[0].clone();
    let block_v2 = chain[1].clone();
    let block_v3 = chain[2].clone();
    let block_v4 = chain[3].clone();

    let full = chain_from_genesis(&genesis, &[1, 2, 3, 4, 5], nid(2));
    let block_v5 = full[4].clone();
    let justify = dummy_qc(View(4), block_v4.hash());
    let signed = signed_proposal(block_v5.clone(), justify, nid(2));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    // Exactly one Commit, and it's over v2 — the QC's
    // great-grandparent. Not genesis (that would be the
    // great-great-grandparent, outside the predicate's walk) and
    // not v3 (that's only the grandparent).
    let commits: Vec<&Block> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Commit(b) => Some(b),
            _ => None,
        })
        .collect();
    assert_eq!(commits.len(), 1, "exactly one Commit action: {actions:?}",);
    assert_eq!(commits[0], &block_v2);

    // Pruning removes every entry at height ≤ 2: genesis (h=0),
    // v1 (h=1), v2 (h=2, the committed block itself).
    let pending = &core.state().pending_blocks;
    assert!(!pending.contains_key(&genesis.hash()));
    assert!(!pending.contains_key(&block_v1.hash()));
    assert!(!pending.contains_key(&block_v2.hash()));
    // Everything strictly above the commit survives — future
    // two-chain / three-chain walks on subsequent proposals will
    // need these.
    assert!(pending.contains_key(&block_v3.hash()));
    assert!(pending.contains_key(&block_v4.hash()));
    assert!(pending.contains_key(&block_v5.hash()));
}

#[test]
fn three_chain_does_not_fire_on_view_gap() {
    // Chain with a view gap: views 1, 2, 5 past genesis. When the
    // dispatcher walks `b3 → b2 → b1` starting from a QC(v=5),
    // the check `b2.view + 1 == b3.view` fails (v=2 + 1 ≠ 5).
    // `three_chain_commit` returns None, dispatch emits no
    // `Commit`, and `pending_blocks` is not pruned — genesis in
    // particular stays. Appendix B.1 ("Why direct parent") makes
    // this the one arm of `update` that must remain strict.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let chain = chain_from_genesis(&genesis, &[1, 2, 5], nid(2));
    for block in &chain {
        core.state.insert_pending(block.clone());
    }

    // Proposal at view 6, parent=v5, justify=QC(v5).
    let full = chain_from_genesis(&genesis, &[1, 2, 5, 6], nid(2));
    let block_v6 = full[3].clone();
    let justify = dummy_qc(View(5), chain[2].hash());
    let signed = signed_proposal(block_v6, justify, nid(2));

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed),
    ));

    assert!(
        !actions.iter().any(|a| matches!(a, Action::Commit(_))),
        "view gap must suppress commit: {actions:?}",
    );
    // Genesis is still in pending_blocks because no prune ran.
    assert!(core.state().pending_blocks.contains_key(&genesis.hash()));
}

// ── D2: happy-path three consecutive proposals → Commit ─────────

#[test]
fn three_consecutive_proposals_commit_block_at_view_zero() {
    // End-to-end happy path from #93's verification list: feed the
    // core three proposals at views 1, 2, 3 through distinct
    // `step()` calls. On the third, B5 commits the "block at view
    // 0" — genesis — per the Chained HotStuff three-chain rule.
    // Lock promotion fires for the first time on the third
    // proposal (the grandparent finally becomes visible). The
    // first two proposals emit only vote + high_qc adoption.
    //
    // This is the integration shape that exercises state
    // accumulating across multiple `step` invocations — each
    // unit test above holds one step; D2 is the only test that
    // pins the cross-step behavior end-to-end.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
    let block_v1 = chain[0].clone();
    let block_v2 = chain[1].clone();
    let block_v3 = chain[2].clone();

    // ── Step 1 — proposal at view 1, parent=genesis ────────────
    let justify_v0 = dummy_qc(View(0), genesis.hash());
    let signed_v1 = signed_proposal(block_v1.clone(), justify_v0.clone(), nid(2));
    let step1 = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_v1),
    ));

    // B4 skips (grandparent is genesis's [0; 32] sentinel).
    // B5 skips (great-grandparent missing).
    assert_eq!(
        step1,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(1) }),
            Action::Persist(StateUpdate::HighQc(justify_v0)),
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(1),
                block_hash: block_v1.hash(),
            })),
        ],
        "first proposal: vote + high_qc only",
    );
    assert!(core.state().locked.is_none());
    assert_eq!(core.state().last_voted_view, View(1));

    // ── Step 2 — proposal at view 2, parent=block_v1 ───────────
    let justify_v1 = dummy_qc(View(1), block_v1.hash());
    let signed_v2 = signed_proposal(block_v2.clone(), justify_v1.clone(), nid(2));
    let step2 = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_v2),
    ));

    // B4: b'' = block_v1 (h=1), b' = genesis (h=0). Candidate at
    // height 0 doesn't beat the `None → 0` baseline, so no
    // promote. B5: walk hits genesis as b2 (h=0) and the
    // sentinel as b1 — returns None.
    assert_eq!(
        step2,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(2) }),
            Action::Persist(StateUpdate::HighQc(justify_v1)),
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(2),
                block_hash: block_v2.hash(),
            })),
        ],
        "second proposal: still vote + high_qc only",
    );
    assert!(core.state().locked.is_none());
    assert_eq!(core.state().last_voted_view, View(2));

    // ── Step 3 — proposal at view 3, parent=block_v2 ───────────
    let justify_v2 = dummy_qc(View(2), block_v2.hash());
    let signed_v3 = signed_proposal(block_v3.clone(), justify_v2.clone(), nid(2));
    let step3 = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_v3),
    ));

    // B4 fires: b'' = v2 (h=2), b' = v1 (h=1). Current lock
    // baseline is 0, so candidate h=1 wins. Persist(Locked(v1)).
    // B5 fires: walk v2 → v1 → genesis with consecutive views
    // 2,1,0. Commit genesis; prune height ≤ 0.
    //
    // Persist(Locked) lands before the deferred Broadcast(Vote)
    // — see the deferral comment in `on_proposal_received` and
    // audit finding 4-1 (#405).
    let expected_lock = Locked {
        view: View(1),
        height: Height(1),
        block_hash: block_v1.hash(),
    };
    assert_eq!(
        step3,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(3) }),
            Action::Persist(StateUpdate::HighQc(justify_v2)),
            Action::Persist(StateUpdate::Locked(expected_lock)),
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(3),
                block_hash: block_v3.hash(),
            })),
            Action::Commit(genesis.clone()),
        ],
        "third proposal: vote + high_qc + lock promote + Commit(genesis)",
    );
    assert_eq!(core.state().last_voted_view, View(3));
    assert_eq!(core.state().locked, Some(expected_lock));
    // Genesis pruned; v1, v2, v3 remain.
    let pending = &core.state().pending_blocks;
    assert!(!pending.contains_key(&genesis.hash()));
    assert!(pending.contains_key(&block_v1.hash()));
    assert!(pending.contains_key(&block_v2.hash()));
    assert!(pending.contains_key(&block_v3.hash()));
}

// ── C1/C2: VoteReceived leader path ─────────────────────────────

#[test]
fn non_leader_aggregates_vote_silently_without_proposing() {
    // self = nid(1). Vote at view 2 → next view = 3. Leader of
    // view 3 = validators[3 % 4] = validators[3] = nid(4), not
    // nid(1).
    //
    // Pre-#124 this node dropped the vote outright. After #124
    // every replica aggregates into its local bucket (so QC
    // formation survives the next leader being crashed — #124),
    // but only the next-view leader broadcasts a follow-up
    // proposal. At sub-quorum the non-leader emits no actions
    // but records the vote in its bucket.
    let mut core = make_core(1);
    let block_hash: BlockHash = [0xAA; 32];
    let vote = signed_vote(2, block_hash, nid(2));

    let actions = core.step(Event::VoteReceived(bls_vote_from_signed(vote)));

    assert!(actions.is_empty(), "sub-quorum vote is silent: {actions:?}");
    let bucket = core
        .vote_bucket
        .get(&(View(2), block_hash))
        .expect("non-leader still accumulates into its local bucket");
    assert_eq!(
        bucket.signer_count(),
        1,
        "bucket must record the vote even when self isn't the next leader",
    );
}

#[test]
fn subquorum_votes_accumulate_without_actions() {
    // self = nid(1), leader of view 4. Feed two valid votes at
    // view 3 (quorum over n=4 is 3). The bucket should grow to
    // two signatures, but neither `step` call produces any
    // actions — C2's first-crosses-threshold gate only fires on
    // the transition to quorum, which we haven't reached.
    let mut core = make_core(1);
    let block_hash: BlockHash = [0xAA; 32];

    let step1 = core.step(Event::VoteReceived(bls_vote(3, block_hash, nid(2))));
    assert!(step1.is_empty(), "first sub-quorum vote is silent");

    let step2 = core.step(Event::VoteReceived(bls_vote(3, block_hash, nid(3))));
    assert!(step2.is_empty(), "second sub-quorum vote is silent");

    let bucket = core
        .vote_bucket
        .get(&(View(3), block_hash))
        .expect("bucket keyed by (view, block_hash) must exist after two votes");
    assert_eq!(bucket.signer_count(), 2, "both signatures recorded",);
    assert!(
        !bucket.has_quorum(&core.state.validator_set),
        "2 of 4 is below the quorum threshold of 3",
    );
}

#[test]
fn quorum_emits_high_qc_persist_then_broadcast_proposal() {
    // self = nid(1), leader of view 4. Install `block_v3` into
    // `pending_blocks` so the parent lookup at quorum time
    // succeeds. Feed three votes at view 3 — the threshold over
    // n=4 — and assert the third one emits, in order:
    //   1. Persist(HighQc(formed_qc))
    //   2. Broadcast(Proposal { block: new_v4, justify: formed_qc })
    // where `new_v4` is what the `TestBlockBuilder` stamps over
    // block_v3 at view 4.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let block_v3 = chain_from_genesis(&genesis, &[3], nid(2))[0].clone();
    let block_v3_hash = block_v3.hash();
    core.state.insert_pending(block_v3.clone());

    // First two votes accumulate silently.
    let step1 = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(2))));
    let step2 = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(3))));
    assert!(step1.is_empty(), "first sub-quorum vote silent: {step1:?}");
    assert!(step2.is_empty(), "second sub-quorum vote silent: {step2:?}");

    // Third vote crosses the threshold. Reconstruct the expected
    // QC by folding the same BLS partials in the same (bitmap) order
    // the dispatcher would — validator indices 1, 2, 3 for nid(2),
    // nid(3), nid(4).
    let mut expected_qc = QuorumCertificate::new_bls(3, block_v3_hash, 4);
    expected_qc.add_bls_partial(1, bls_partial(View(3), block_v3_hash, nid(2)));
    expected_qc.add_bls_partial(2, bls_partial(View(3), block_v3_hash, nid(3)));
    expected_qc.add_bls_partial(3, bls_partial(View(3), block_v3_hash, nid(4)));

    // The builder extends block_v3 (height 1) with an empty-commands
    // child at height 2, view 4, proposer nid(1).
    let expected_new_block = Block {
        header: BlockHeader {
            parent_hash: block_v3_hash,
            height: block_v3.header.height + 1,
            view: View(4),
            proposer: nid(1),
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    };

    let step3 = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(4))));

    // #606: the quorum transition now emits the HighQc persist and a
    // `BuildProposal` action. The `Persist(ProposedInView)` + Broadcast
    // come from `proposal_built`, which the integration layer (here,
    // simulated below) calls once it has built the block.
    assert_eq!(
        step3,
        vec![
            Action::Persist(StateUpdate::HighQc(expected_qc.clone())),
            Action::BuildProposal {
                view: View(4),
                high_qc: expected_qc.clone(),
                parent: block_v3.clone(),
            },
        ],
        "quorum transition emits HighQc persist + BuildProposal",
    );
    // Simulate the integration layer fulfilling BuildProposal.
    let built = core
        .build_proposal(View(4), &expected_qc, &block_v3)
        .expect("builder succeeds");
    assert_eq!(built, expected_new_block);
    assert_eq!(
        core.proposal_built(View(4), built, expected_qc.clone()),
        vec![
            Action::Persist(StateUpdate::ProposedInView { view: View(4) }),
            Action::Broadcast(ConsensusMsg::Proposal(Proposal {
                block: expected_new_block,
                justify: expected_qc.clone(),
            })),
        ],
        "proposal_built emits ProposedInView persist then Broadcast(Proposal)",
    );
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.inner()),
        Some(&expected_qc)
    );
    assert_eq!(core.proposed_in_view(), View(4));
}

// ── BLS QC formation (#354 step 2) ──────────────────────────────

#[test]
fn bls_quorum_emits_high_qc_with_real_aggregate_that_verifies() {
    // Self = nid(1), leader of view 4. The core is configured for
    // `bls_aggregated`, so each Vote we feed must carry a real BLS
    // partial under the voter's BLS key. After three valid votes
    // (the n=4 quorum) the formed QC must carry a non-sentinel
    // aggregate that verifies via `verify_aggregate_bls` against
    // the genesis BLS pubkey table — the same path the dispatch
    // verifier uses on inbound proposals.
    use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, BlsSecretKey};
    use boule_core::crypto::signed::preimage;

    let validators_set = validators();
    // Generate one BLS keypair per validator, deterministic in
    // the validator's NodeId so the test is reproducible.
    let bls_keys: Vec<(BlsSecretKey, BlsPublicKey)> = validators_set
        .iter()
        .enumerate()
        .map(|(i, validator_id)| {
            let mut ikm = validator_id.into_node_id();
            ikm[0] ^= i as u8;
            BlsAggregated::keygen(&ikm).expect("BLS keygen for test")
        })
        .collect();
    let genesis = Block::genesis([0; 32], [0; 32]);
    let block_v3 = chain_from_genesis(&genesis, &[3], nid(2))[0].clone();
    let block_v3_hash = block_v3.hash();

    let state = HotStuffState::new(validators_set.clone(), Block::genesis([0; 32], [0; 32]));
    let mut core = HotStuffCore::new(nid(1), state)
        .with_signature_scheme(SignatureSchemeChoice::BlsAggregated);
    core.state.insert_pending(block_v3.clone());

    // Build one BLS partial per voter at indices 1, 2, 3
    // (validators nid(2..4)) over the canonical Vote pre-image.
    let vote = Vote {
        view: View(3),
        block_hash: block_v3_hash,
    };
    let preimg = preimage::<Vote>(&vote, &boule_core::crypto::signed::ChainId::TEST).unwrap();
    let voters = [(1, nid(2)), (2, nid(3)), (3, nid(4))];

    let mut step_actions = Vec::new();
    for (idx, signer_id) in voters.iter() {
        let partial = BlsAggregated::sign_partial(&bls_keys[*idx].0, &preimg).unwrap();
        let signed = Signed {
            payload: vote.clone(),
            signer: *signer_id,
            sig: [signer_id[0]; 64],
        };
        step_actions = core.step(Event::VoteReceived(VoteVariant::Bls {
            signed: crate::dispatch::Verified::unchecked(signed),
            partial,
        }));
    }

    // Quorum-emit branch: Persist(HighQc(_)) + Broadcast(Proposal(_))
    let formed_qc = match step_actions.first() {
        Some(Action::Persist(StateUpdate::HighQc(qc))) => qc.clone(),
        other => panic!("expected HighQc persist as first action, got {other:?}"),
    };
    assert!(formed_qc.is_bls(), "formed QC must be BLS-flavored");
    assert_eq!(formed_qc.signer_count(), 3, "all three partials folded");
    assert!(formed_qc.is_well_formed(&validators_set));

    // The load-bearing assertion: the formed BLS aggregate
    // verifies against the per-validator BLS pubkey table at
    // view 3. This is what the dispatch verifier runs on every
    // inbound proposal whose `justify` is a BLS QC.
    let pubkeys: Vec<BlsPublicKey> = bls_keys.iter().map(|(_, pk)| *pk).collect();
    formed_qc
        .verify_aggregate_bls(&preimg, &pubkeys)
        .expect("real BLS aggregate must verify under genesis pubkeys");
}

// The pre-#372 defense-in-depth check ("BLS chain + missing
// partial → drop the vote") and its test
// (`bls_vote_without_partial_is_dropped_silently`) were removed
// when the tuple `Event::VoteReceived(_, Option<BlsPartialSig>)`
// was replaced by [`VoteVariant`]: a BLS-flavored vote that lacks
// its partial is no longer constructible, so there is nothing for
// the safety core to defend against at runtime.

// ── D8: PacemakerAdvance base contract ──────────────────────────

#[test]
fn pacemaker_advance_updates_view_and_broadcasts_new_view_when_high_qc_known() {
    let mut core = make_core(1);
    assert_eq!(core.state().current_view, View(0));

    // Early: no high_qc yet → view updates but we skip the
    // broadcast. The skip window only exists between construction
    // and the first proposal landing.
    let early = core.step(Event::PacemakerAdvance(View(1)));
    assert!(
        early.is_empty(),
        "no high_qc yet → no NewView broadcast: {early:?}",
    );
    assert_eq!(core.state().current_view, View(1));

    // Seed a high_qc as if a proposal had adopted one.
    let qc = dummy_qc(View(5), [0xAA; 32]);
    core.state.high_qc = Some(VerifiedQc::unchecked(qc.clone()));

    // Later PacemakerAdvance → view updates AND the broadcast
    // carries the current high_qc.
    let later = core.step(Event::PacemakerAdvance(View(7)));
    assert_eq!(
        later,
        vec![Action::Broadcast(ConsensusMsg::NewView(NewView {
            high_qc: qc,
        }))],
    );
    assert_eq!(core.state().current_view, View(7));
}

// ── #243: leader catches up via block-sync, then proposes ───────

/// Issue #243 regression: a post-restart leader whose `high_qc`
/// references a block missing from `pending_blocks` cannot propose
/// when `become_leader` first fires. Block-sync brings the parent
/// in later (via `insert_pending_block` + `PacemakerAdvance`), but
/// the safety core never re-attempts the proposal — the leader
/// stays silent for the entire view, which view-changes around it
/// only after the pacemaker timeout (a 200ms→2s budget on tight
/// pacemaker settings; well within the 60s recovery budget the
/// testnet sweep observed wedging at ~10%).
///
/// Without the fix this test fails on the second
/// `PacemakerAdvance(view=5)` assertion: the leader emits a
/// `NewView` broadcast but no `Proposal`.
#[test]
fn leader_proposes_after_block_sync_delivers_missing_high_qc_parent() {
    // self = nid(2). Round-robin leader of view 5 = validators[5 %
    // 4] = validators[1] = nid(2), so we own the propose path for
    // view 5.
    let mut core = make_core(2);
    let genesis = Block::genesis([0; 32], [0; 32]);
    // Build a chain so we have a concrete `high_qc` target block
    // to point at without inserting it into `pending_blocks`.
    let chain = chain_from_genesis(&genesis, &[1, 2, 3, 4], nid(1));
    let high_qc_block = chain[3].clone(); // view 4, height 4
    let high_qc_hash = high_qc_block.hash();
    let high_qc = dummy_qc(View(4), high_qc_hash);

    // Mimic the post-restart wedge: NewView from a peer adopts a
    // fresh high_qc, but block-sync hasn't delivered the block
    // yet. We seed the inflight tracker the way the NewView path
    // would (via #240), so PacemakerAdvance below isn't a no-op
    // on the retry side.
    core.state.high_qc = Some(VerifiedQc::unchecked(high_qc.clone()));
    core.block_sync_inflight.insert(
        high_qc_hash,
        BlockSyncInflight {
            original_sender: nid(3),
            attempts: 1,
            last_asked_view: View(0),
            expected_height: Height(0),
        },
    );

    // First PacemakerAdvance: pacemaker has just lifted us to view
    // 5. The high_qc block is missing, so the proposal can't fire
    // yet. The actions must include NewView (we have a high_qc to
    // advertise) and a block-sync retry (because we have an
    // outstanding inflight entry the pacemaker drives).
    let advance_to_5 = core.step(Event::PacemakerAdvance(View(5)));
    let proposed_now = advance_to_5
        .iter()
        .any(|a| matches!(a, Action::BuildProposal { .. }));
    assert!(
        !proposed_now,
        "before block-sync delivers high_qc parent, leader must not propose: {advance_to_5:?}",
    );

    // BecomeLeader is the integration layer's follow-up after the
    // AdvanceToView pacemaker action. With the parent still
    // missing it produces no proposal — pre-fix behaviour, kept
    // as an explicit assertion so the regression couldn't quietly
    // shift the symptom from "never proposes" to "proposes
    // garbage".
    let become_leader_actions = core.become_leader(5);
    let proposed_in_become_leader = become_leader_actions
        .iter()
        .any(|a| matches!(a, Action::BuildProposal { .. }));
    assert!(
        !proposed_in_become_leader,
        "become_leader must not propose while high_qc parent is missing: {become_leader_actions:?}",
    );

    // Block-sync response: the missing high_qc block lands in
    // `pending_blocks` via the integration layer's
    // `Dispatch::ReceiveBlock` path.
    core.insert_pending_block(high_qc_block.clone());

    // The integration layer feeds a fresh `PacemakerAdvance` for
    // the same view after `insert_pending_block` (see
    // `node.rs::Dispatch::ReceiveBlock`). Now that the parent is
    // available the safety core MUST broadcast the leader's
    // proposal — this is the recovery path issue #243 needs.
    let recovery = core.step(Event::PacemakerAdvance(View(5)));
    // #606: the leader emits BuildProposal; simulate the integration layer
    // building + finalizing to get the actual proposal — this also sets
    // the per-view double-propose guard the idempotency check below relies on.
    let (bp_view, bp_high_qc, bp_parent) = recovery
        .iter()
        .find_map(|a| match a {
            Action::BuildProposal {
                view,
                high_qc,
                parent,
            } => Some((*view, high_qc.clone(), parent.clone())),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "issue #243: leader must re-attempt the proposal after \
                     block-sync brings in the missing high_qc parent. actions={recovery:?}"
            )
        });
    let built = core
        .build_proposal(bp_view, &bp_high_qc, &bp_parent)
        .expect("builder succeeds once the parent is present");
    let proposal = core
        .proposal_built(bp_view, built, bp_high_qc)
        .into_iter()
        .find_map(|a| match a {
            Action::Broadcast(ConsensusMsg::Proposal(p)) => Some(p),
            _ => None,
        })
        .expect("proposal_built emits Broadcast(Proposal)");
    assert_eq!(
        proposal.block.header.view,
        View(5),
        "proposal must be at the leader's current view"
    );
    assert_eq!(
        proposal.block.header.parent_hash, high_qc_hash,
        "proposal must extend the freshly-arrived high_qc block",
    );
    assert_eq!(
        proposal.block.header.height,
        high_qc_block.header.height + 1,
        "proposal must increment height over the high_qc parent",
    );
    assert_eq!(
        proposal.justify, high_qc,
        "proposal's justify is the adopted high_qc",
    );

    // Idempotency: a second PacemakerAdvance for the same view
    // (e.g. another block-sync response landing) must not
    // re-propose. Re-proposing would split votes across two
    // leader proposals at the same view and is indistinguishable
    // from Byzantine equivocation.
    let dup = core.step(Event::PacemakerAdvance(View(5)));
    let dup_proposed = dup
        .iter()
        .any(|a| matches!(a, Action::BuildProposal { .. }));
    assert!(
        !dup_proposed,
        "leader must propose at most once per view; got {dup:?}",
    );
}

// ── C3: NewViewReceived ────────────────────────────────────────

#[test]
fn newview_adopts_fresher_high_qc_and_ignores_stale() {
    let mut core = make_core(1);
    // Use the genesis hash for the QC's `block_hash` so the
    // adoption path doesn't fall through to the #240 block-sync
    // branch — that branch is exercised in
    // `newview_with_unknown_block_hash_seeds_block_sync` below.
    // This test focuses purely on the adoption / strict-greater
    // gating that pre-dated #240.
    let block_hash = core.state().genesis_hash;

    // Empty `high_qc` → any incoming QC is strictly fresher and
    // adopted. Emission: single `Persist(HighQc(qc))`.
    let qc_v5 = dummy_qc(View(5), block_hash);
    let fresh = core.step(Event::NewViewReceived(
        crate::dispatch::Verified::unchecked(signed_newview(qc_v5.clone(), nid(2))),
    ));
    assert_eq!(
        fresh,
        vec![Action::Persist(StateUpdate::HighQc(qc_v5.clone()))],
    );
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.inner()),
        Some(&qc_v5)
    );

    // Same view — `should_update_high_qc` requires strictly
    // greater, so no action, no state change.
    let qc_v5_alt = dummy_qc(View(5), [0x22; 32]);
    let same = core.step(Event::NewViewReceived(
        crate::dispatch::Verified::unchecked(signed_newview(qc_v5_alt, nid(3))),
    ));
    assert!(same.is_empty(), "same-view NewView is a no-op: {same:?}");
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.inner()),
        Some(&qc_v5)
    );

    // Strictly older — dropped.
    let qc_v3 = dummy_qc(View(3), [0x33; 32]);
    let stale = core.step(Event::NewViewReceived(
        crate::dispatch::Verified::unchecked(signed_newview(qc_v3, nid(4))),
    ));
    assert!(stale.is_empty(), "stale NewView is a no-op: {stale:?}");
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.inner()),
        Some(&qc_v5)
    );

    // Strictly newer over the genesis hash again — adopted,
    // overwriting the previous, still no block-sync (block known).
    let qc_v9 = dummy_qc(View(9), block_hash);
    let newer = core.step(Event::NewViewReceived(
        crate::dispatch::Verified::unchecked(signed_newview(qc_v9.clone(), nid(2))),
    ));
    assert_eq!(
        newer,
        vec![Action::Persist(StateUpdate::HighQc(qc_v9.clone()))],
    );
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.inner()),
        Some(&qc_v9)
    );
}

/// Issue #240: a `NewView` whose adopted `high_qc` references a
/// block we don't have must seed a `RequestBlock` so the
/// integration layer can fetch it. Without this trigger, a
/// replica whose gossip mesh missed the originating proposal
/// would lift its view from NewView traffic alone but never see
/// the block, leaving `last_committed_height` parked while the
/// cluster advances heights without it.
#[test]
fn newview_with_unknown_block_hash_seeds_block_sync() {
    let mut core = make_core(1);
    let unknown_hash: BlockHash = [0xC0; 32];
    let qc_v7 = dummy_qc(View(7), unknown_hash);
    let sender = nid(2);

    let actions = core.step(Event::NewViewReceived(
        crate::dispatch::Verified::unchecked(signed_newview(qc_v7.clone(), sender)),
    ));

    assert_eq!(
        actions,
        vec![
            Action::Persist(StateUpdate::HighQc(qc_v7.clone())),
            Action::RequestBlock {
                hash: unknown_hash,
                peer: sender,
                expected_height: Height(0),
                reason: BlockSyncReason::UnknownHighQcOnNewView,
            },
        ],
        "NewView adopting a fresh high_qc over an unknown block must persist + request the block",
    );
    assert_eq!(
        core.state().high_qc.as_ref().map(|q| q.inner()),
        Some(&qc_v7)
    );
    assert!(
        core.block_sync_inflight.contains_key(&unknown_hash),
        "in-flight retry tracker must be installed so PacemakerAdvance can drive retries",
    );
}

/// Companion to the previous test: when the QC's block IS in
/// `pending_blocks`, the NewView path must NOT emit a
/// `RequestBlock`. The block-sync trigger is gated on the block
/// genuinely missing.
#[test]
fn newview_with_known_block_hash_does_not_request_block() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let block_v1 = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
    let block_v1_hash = block_v1.hash();
    core.state.insert_pending(block_v1);

    let qc_v1 = dummy_qc(View(1), block_v1_hash);
    let actions = core.step(Event::NewViewReceived(
        crate::dispatch::Verified::unchecked(signed_newview(qc_v1.clone(), nid(2))),
    ));

    assert_eq!(
        actions,
        vec![Action::Persist(StateUpdate::HighQc(qc_v1))],
        "NewView whose QC block is already in pending_blocks must not fire block-sync",
    );
    assert!(
        !core.block_sync_inflight.contains_key(&block_v1_hash),
        "no in-flight tracker should be installed when the block is known",
    );
}

#[test]
fn post_quorum_votes_do_not_rebroadcast() {
    // Form the QC with 3 votes as before, then feed two additional
    // votes: (a) from `nid(1)` — a new signer not yet in the QC
    // — and (b) a duplicate from `nid(2)` — already in the QC.
    // Neither step may re-fire the `Broadcast(Proposal)` — C2's
    // first-crosses-threshold gate already fired, and `has_quorum`
    // stays true forever after.
    //
    // The bucket is intentionally not cleared on quorum, so these
    // late deliveries land in it as idempotent sinks rather than
    // re-materializing an empty QC and re-firing.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let block_v3 = chain_from_genesis(&genesis, &[3], nid(2))[0].clone();
    let block_v3_hash = block_v3.hash();
    core.state.insert_pending(block_v3.clone());

    // Drive to quorum: first three votes.
    let _ = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(2))));
    let _ = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(3))));
    let _ = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(4))));

    // Late vote from a new signer — still a no-op at the dispatch
    // surface even though the bucket grows to 4 sigs.
    let step_late_new = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(1))));
    assert!(
        step_late_new.is_empty(),
        "late vote from new signer must not re-broadcast: {step_late_new:?}",
    );

    // Duplicate vote from an existing signer — `add_signature` is
    // a no-op on the set-bit; dispatch also early-returns.
    let step_dup = core.step(Event::VoteReceived(bls_vote(3, block_v3_hash, nid(2))));
    assert!(
        step_dup.is_empty(),
        "duplicate vote must not re-broadcast: {step_dup:?}",
    );

    // Bucket should now carry all four validator signatures
    // (added by nid(2), nid(3), nid(4), nid(1)), and still be at
    // quorum. The duplicate didn't bump the count.
    let bucket = core
        .vote_bucket
        .get(&(View(3), block_v3_hash))
        .expect("bucket keyed by (3, block_v3_hash) must still exist");
    assert_eq!(bucket.signer_count(), 4);
    assert!(bucket.has_quorum(&core.state.validator_set));
}

#[test]
fn vote_from_non_validator_signer_is_dropped() {
    // self = nid(1) is the leader of view 4 (4 % 4 = 0), so a
    // vote at view 3 would normally accumulate. But this vote
    // comes from `nid(99)` — not in the validator set. C1b
    // drops because `ValidatorSet::index_of` returns None, and
    // without an index we have no slot in the `SignerBitmap` to
    // record the signature.
    let mut core = make_core(1);
    let vote = signed_vote(3, [0xAA; 32], nid(99));

    let actions = core.step(Event::VoteReceived(bls_vote_from_signed(vote)));

    assert!(
        actions.is_empty(),
        "non-validator signer drops: {actions:?}",
    );
    assert!(
        core.vote_bucket.is_empty(),
        "bucket must not grow on unknown signer",
    );
}

// ── #270: vote validation across a reconfig boundary ────────────────

/// A vote at `vote.view >= v_eff` signed by a validator who is in
/// the *old* set but not in the post-boundary set must be dropped:
/// the safety core looks up `set_at(vote.view)`, which returns the
/// new set, and the old-only signer has no index there.
#[test]
fn vote_at_v_eff_signed_by_old_set_only_member_is_dropped() {
    let mut core = make_core(1);
    // Old genesis set is `[nid(1), nid(2), nid(3), nid(4)]` from
    // `validators()`. Boundary at v_eff = 5 swaps in a new set
    // that drops nid(4) and adds nid(5) + nid(6) to keep size 5.
    let v_eff: View = View(5);
    let new_set = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(5), vid(6)]);
    core.state
        .validator_history
        .insert_boundary(v_eff, new_set)
        .unwrap();

    // Vote at view = v_eff signed by the old-only member.
    let vote = signed_vote(v_eff, [0xAA; 32], nid(4));
    let actions = core.step(Event::VoteReceived(bls_vote_from_signed(vote)));

    assert!(
        actions.is_empty(),
        "old-set-only signer at v_eff must drop: {actions:?}",
    );
    assert!(
        core.vote_bucket.is_empty(),
        "bucket must not grow when signer is outside set_at(vote.view)",
    );
}

/// A vote at `vote.view < v_eff` signed by a validator who is only
/// in the *new* set is dropped: `set_at(vote.view)` returns the
/// pre-boundary genesis set, and the new-only signer has no index.
/// Confirms that historical votes are not retroactively re-validated
/// against the post-boundary committee.
#[test]
fn vote_before_boundary_signed_by_new_set_only_member_is_dropped() {
    let mut core = make_core(1);
    let v_eff: View = View(5);
    let new_set = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5)]);
    core.state
        .validator_history
        .insert_boundary(v_eff, new_set)
        .unwrap();

    // Vote at view = v_eff - 1 signed by the new-only member.
    let vote = signed_vote(v_eff - 1, [0xBB; 32], nid(5));
    let actions = core.step(Event::VoteReceived(bls_vote_from_signed(vote)));

    assert!(
        actions.is_empty(),
        "new-set-only signer at v_eff - 1 must drop: {actions:?}",
    );
    assert!(
        core.vote_bucket.is_empty(),
        "bucket must not grow when signer is outside set_at(vote.view)",
    );
}

/// Sanity: a vote at `vote.view >= v_eff` signed by someone *only*
/// in the new set lands in the bucket correctly. This verifies the
/// positive side — the historical lookup picks the right set
/// rather than the wrong one in both directions.
#[test]
fn vote_at_v_eff_signed_by_new_set_only_member_lands_in_bucket() {
    let mut core = make_core(1);
    let v_eff: View = View(5);
    let new_set = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(7)]);
    core.state
        .validator_history
        .insert_boundary(v_eff, new_set)
        .unwrap();

    let block_hash: BlockHash = [0xCC; 32];
    let vote = signed_vote(v_eff, block_hash, nid(7));
    let _ = core.step(Event::VoteReceived(bls_vote_from_signed(vote)));

    let bucket = core
        .vote_bucket
        .get(&(v_eff, block_hash))
        .expect("bucket keyed by (view, block_hash) must exist after the vote landed");
    assert_eq!(bucket.signer_count(), 1);
}

// ── #394: post-rotation vote resolution ─────────────────────────────

/// Post-rotation regression: a vote signed under a freshly-rotated
/// active key arrives wrapped in a [`crate::dispatch::Verified`] envelope whose
/// `signer_validator_id` is the validator's stable id (resolved by
/// dispatch via [`ValidatorKeyHistory::validator_for`]). The safety
/// core must use the stamped id for the bitmap-index lookup —
/// re-deriving `ValidatorId::from_genesis_pubkey(signed.signer)`
/// from the post-rotation wire bytes (the pre-#394 behaviour) would
/// silently drop the vote because the rotated pubkey's bytes no
/// longer match the validator's stable id.
///
/// The dispatch-layer rotation tests (e.g.
/// `vote_after_rotation_signed_with_new_key_accepted` in
/// `dispatch::tests`) cover the resolve-and-stamp side; this test
/// pins the safety-core read of the stamped id.
#[test]
fn vote_signed_under_rotated_key_with_stamped_stable_id_folds_into_bucket() {
    // Validator set is the canonical four, identified by the
    // genesis pubkey bytes (vid(1..=4)).
    let mut core = make_core(1);
    let view: View = View(1);
    let block_hash: BlockHash = [0xAB; 32];

    // Simulate the post-rotation wire pubkey: distinct bytes that
    // are NOT in the validator set (so a naive
    // `from_genesis_pubkey(rotated_pk)` would fail the bitmap
    // lookup).
    let rotated_pk = nid(0xEE);
    assert!(
        validators().index_of(&vid(0xEE)).is_none(),
        "test setup invariant: rotated pubkey bytes must not coincide \
             with any validator stable id",
    );
    let signed = signed_vote(view, block_hash, rotated_pk);

    // Dispatch would resolve `rotated_pk` to vid(2) via
    // `ValidatorKeyHistory::validator_for` and stamp it on the
    // envelope. Simulate that stamping directly here.
    let stable_id = vid(2);
    let actions = core.step(Event::VoteReceived(bls_vote_from_signed_with_signer(
        signed, stable_id,
    )));

    let bucket = core.vote_bucket.get(&(view, block_hash)).expect(
        "post-rotation vote must contribute to the bitmap when the \
                     stamped ValidatorId is in the validator set (#394)",
    );
    assert_eq!(
        bucket.signer_count(),
        1,
        "exactly the rotated voter's bit should be set",
    );
    // Sub-quorum (1 / 4) → no actions.
    assert!(actions.is_empty());
}

/// Pre-#394 behaviour control: with the old code, the safety core
/// would derive its bitmap key from `signed.signer` bytes via
/// `ValidatorId::from_genesis_pubkey`. Stamping a `ValidatorId`
/// whose bytes are the rotated pubkey (not the stable id) — the
/// pre-fix derivation — reproduces the silent drop. Pins that the
/// fix is strictly a stamping concern: the safety core's lookup
/// logic is unchanged, only what it looks up has moved from
/// re-derived bytes to the dispatch-resolved stable id.
#[test]
fn vote_with_unresolved_validator_id_drops_silently() {
    let mut core = make_core(1);
    let view: View = View(1);
    let block_hash: BlockHash = [0xAB; 32];

    let rotated_pk = nid(0xEE);
    let signed = signed_vote(view, block_hash, rotated_pk);
    // Stamp the *wrong* id — the wire pubkey bytes, which is what
    // `from_genesis_pubkey(signed.signer)` produced before #394.
    let pre_fix_id = crate::validator_set::ValidatorId::from_genesis_pubkey(rotated_pk);

    let actions = core.step(Event::VoteReceived(bls_vote_from_signed_with_signer(
        signed, pre_fix_id,
    )));

    assert!(
        core.vote_bucket.is_empty(),
        "vote with unresolved validator id must drop — same path that \
             pre-#394 silently masked rotated votes",
    );
    assert!(actions.is_empty());
}

// ── #409: vote-equivocation detection (audit finding 3-1) ──────────

/// Two votes from the same stable signer at the same view for two
/// distinct `block_hash` values must produce
/// [`Action::EquivocationEvidence`] on the second arrival; the
/// second partial must NOT be folded into the second bucket
/// (otherwise a Byzantine voter contributing to two buckets at the
/// same view could help form QCs on conflicting blocks). The first
/// vote lands normally.
#[test]
fn second_vote_at_same_view_for_different_block_emits_equivocation_evidence() {
    let mut core = make_core(1);
    let view: View = View(3);
    let block_a: BlockHash = [0xAA; 32];
    let block_b: BlockHash = [0xBB; 32];

    let first = core.step(Event::VoteReceived(bls_vote(view, block_a, nid(2))));
    assert!(
        first.is_empty(),
        "first vote sub-quorum: no actions expected, got {first:?}",
    );
    let bucket_a = core
        .vote_bucket
        .get(&(view, block_a))
        .expect("first vote lands in its bucket");
    assert_eq!(bucket_a.signer_count(), 1);

    let second = core.step(Event::VoteReceived(bls_vote(view, block_b, nid(2))));
    assert_eq!(
        second,
        vec![Action::EquivocationEvidence {
            voter: vid(2),
            view,
            block_a,
            block_b,
        }],
        "conflicting vote at same view must emit EquivocationEvidence",
    );

    // The second bucket must not exist — the conflicting partial is
    // dropped before fold.
    assert!(
        !core.vote_bucket.contains_key(&(view, block_b)),
        "conflicting vote must not seed a second bucket",
    );
    // The original bucket is unchanged.
    let bucket_a_after = core
        .vote_bucket
        .get(&(view, block_a))
        .expect("original bucket survives");
    assert_eq!(bucket_a_after.signer_count(), 1);
}

/// A duplicate of the same `(signer, view, block_hash)` is
/// idempotent: no equivocation emitted, the bucket's signer-count
/// is unchanged (the underlying `add_signature` ignores set bits).
#[test]
fn duplicate_vote_for_same_block_does_not_emit_equivocation_evidence() {
    let mut core = make_core(1);
    let view: View = View(3);
    let block_hash: BlockHash = [0xAA; 32];

    let _ = core.step(Event::VoteReceived(bls_vote(view, block_hash, nid(2))));
    let again = core.step(Event::VoteReceived(bls_vote(view, block_hash, nid(2))));
    assert!(again.is_empty(), "duplicate vote is a no-op, got {again:?}",);
    let bucket = core
        .vote_bucket
        .get(&(view, block_hash))
        .expect("bucket exists");
    assert_eq!(
        bucket.signer_count(),
        1,
        "duplicate must not double-count signer",
    );
}

/// Distinct signers voting for distinct blocks at the same view do
/// not trigger equivocation — the dedup key includes the signer.
/// A four-validator network where two validators each vote for a
/// different fork must produce two buckets, not equivocation
/// evidence.
#[test]
fn votes_from_distinct_signers_for_distinct_blocks_do_not_emit_evidence() {
    let mut core = make_core(1);
    let view: View = View(3);
    let block_a: BlockHash = [0xAA; 32];
    let block_b: BlockHash = [0xBB; 32];

    let one = core.step(Event::VoteReceived(bls_vote(view, block_a, nid(2))));
    let two = core.step(Event::VoteReceived(bls_vote(view, block_b, nid(3))));
    assert!(one.is_empty() && two.is_empty(), "sub-quorum, no actions");

    // Two distinct buckets, each with one signer.
    assert_eq!(
        core.vote_bucket
            .get(&(view, block_a))
            .map(|q| q.signer_count()),
        Some(1),
    );
    assert_eq!(
        core.vote_bucket
            .get(&(view, block_b))
            .map(|q| q.signer_count()),
        Some(1),
    );
}

/// The same signer voting at *different* views for different
/// blocks is normal HotStuff progress, not equivocation: the
/// per-view dedup key separates them.
#[test]
fn same_signer_at_different_views_does_not_emit_evidence() {
    let mut core = make_core(1);
    let block_a: BlockHash = [0xAA; 32];
    let block_b: BlockHash = [0xBB; 32];

    let v3 = core.step(Event::VoteReceived(bls_vote(3, block_a, nid(2))));
    let v4 = core.step(Event::VoteReceived(bls_vote(4, block_b, nid(2))));
    assert!(v3.is_empty() && v4.is_empty(), "sub-quorum, no actions");
}

/// Memory bound (acceptance criterion): the dedup map is GC'd in
/// `evict_vote_buckets_below`, which fires on `PacemakerAdvance`.
/// After advancing past the recorded view, a previously-seen
/// `(signer, view)` pair no longer detects equivocation — the
/// entry has been swept out alongside the matching `vote_bucket`
/// entry. (The trade-off is fine: a vote_bucket entry below
/// `gc_below` cannot feed a fresher high_qc anyway, so retaining
/// dedup state for it is not load-bearing — and a future vote at
/// the same long-past view would also be dropped on the
/// `view < gc_below` cleanup that follows.)
#[test]
fn pacemaker_advance_garbage_collects_vote_dedupe() {
    let mut core = make_core(1);
    let view: View = View(3);
    let block_a: BlockHash = [0xAA; 32];

    let _ = core.step(Event::VoteReceived(bls_vote(view, block_a, nid(2))));
    assert!(core.vote_dedupe.contains_key(&(view, vid(2))));

    // Advance past `view` — this should sweep both the bucket and
    // the dedup entry.
    let _ = core.step(Event::PacemakerAdvance(view + 1));
    assert!(
        !core.vote_dedupe.contains_key(&(view, vid(2))),
        "vote_dedupe entry must be GC'd alongside its vote_bucket",
    );
    assert!(
        !core.vote_bucket.contains_key(&(view, block_a)),
        "matching vote_bucket entry must be GC'd",
    );
}

/// Deterministic emission order: `EquivocationEvidence` is the
/// only action emitted for the conflicting vote (no `Persist`,
/// `Broadcast`, or other side effect). Pins the contract that the
/// integration layer's match arm sees a one-element vec for each
/// detection.
#[test]
fn equivocation_evidence_is_the_only_emitted_action_on_conflict() {
    let mut core = make_core(1);
    let view: View = View(3);
    let block_a: BlockHash = [0xAA; 32];
    let block_b: BlockHash = [0xBB; 32];

    let _ = core.step(Event::VoteReceived(bls_vote(view, block_a, nid(2))));
    let actions = core.step(Event::VoteReceived(bls_vote(view, block_b, nid(2))));
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], Action::EquivocationEvidence { .. }));
}

// ── L5-1: proposal-equivocation detection (sibling of vote dedupe) ──

/// Build a fork-at-`view` whose `state_commitment` byte differs by
/// `tag`, so two calls with distinct `tag` values produce two
/// blocks with the same `(view, parent_hash, height)` triple but
/// different `block_hash`. Models the on-the-wire shape of a
/// Byzantine leader broadcasting two distinct proposals at the
/// same view.
fn fork_at_view(parent_hash: BlockHash, view: impl Into<View>, proposer: NodeId, tag: u8) -> Block {
    let view = view.into();
    Block {
        header: BlockHeader {
            parent_hash,
            height: Height(1),
            view,
            proposer,
            state_commitment: [tag; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    }
}

/// Two distinct proposals from the same stable leader at the same
/// view for two distinct `block_hash` values must produce
/// [`Action::ProposalEquivocationEvidence`] on the second arrival.
/// Both forks are still admitted into `pending_blocks` — the
/// detector is informational, not a drop. Acceptance criterion
/// from issue #506.
#[test]
fn second_proposal_at_same_view_for_different_block_emits_proposal_equivocation_evidence() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());

    let block_a = fork_at_view(genesis.hash(), 1, nid(2), 0xAA);
    let block_b = fork_at_view(genesis.hash(), 1, nid(2), 0xBB);
    let block_a_hash = block_a.hash();
    let block_b_hash = block_b.hash();
    assert_ne!(
        block_a_hash, block_b_hash,
        "fork_at_view tag must perturb the block hash",
    );

    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_a, justify.clone(), nid(2))),
    ));
    assert_eq!(
        core.proposal_dedupe.get(&(View(1), vid(2))),
        Some(&block_a_hash),
        "first proposal must record the leader's block_hash",
    );

    let actions = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_b, justify, nid(2))),
    ));

    // Evidence is emitted *first*, before any side effects of the
    // fork's normal processing. The integration layer's match arm
    // sees the equivocation up-front.
    assert!(
        matches!(
            actions.first(),
            Some(Action::ProposalEquivocationEvidence {
                leader,
                view,
                block_a,
                block_b,
            }) if *leader == vid(2)
                && *view == View(1)
                && *block_a == block_a_hash
                && *block_b == block_b_hash,
        ),
        "first emitted action must be ProposalEquivocationEvidence: {actions:?}",
    );
    // Fork still admitted — both forks land in pending_blocks.
    assert!(core.state().pending_blocks.contains_key(&block_b_hash));
    // Recorded hash stays the *first* sighting; a third fork would
    // also be measured against block_a.
    assert_eq!(
        core.proposal_dedupe.get(&(View(1), vid(2))),
        Some(&block_a_hash),
        "dedupe map must not overwrite on conflict — slashing pipeline \
             relies on the first sighting being canonical",
    );
}

/// A duplicate of the same `(leader, view, block_hash)` is
/// idempotent: no equivocation emitted, downstream actions match
/// what an honest re-delivery (e.g. a parked-proposal un-park or
/// a duplicate frame) would produce.
#[test]
fn duplicate_proposal_for_same_block_does_not_emit_proposal_equivocation_evidence() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());
    let block = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();

    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(
            block.clone(),
            justify.clone(),
            nid(2),
        )),
    ));
    let again = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block, justify, nid(2))),
    ));
    assert!(
        !again
            .iter()
            .any(|a| matches!(a, Action::ProposalEquivocationEvidence { .. })),
        "duplicate proposal must not emit equivocation evidence: {again:?}",
    );
}

/// Distinct leaders proposing distinct blocks at the same view do
/// not trigger equivocation — the dedup key includes the leader.
/// Concretely: a Byzantine fork attempt where two *different*
/// validators each propose at the same view is not the shape we're
/// detecting (only the safety-rule path catches that).
#[test]
fn proposals_from_distinct_leaders_for_distinct_blocks_do_not_emit_evidence() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());
    let block_a = fork_at_view(genesis.hash(), 1, nid(2), 0xAA);
    let block_b = fork_at_view(genesis.hash(), 1, nid(3), 0xBB);

    let one = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_a, justify.clone(), nid(2))),
    ));
    let two = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_b, justify, nid(3))),
    ));
    for actions in [&one, &two] {
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::ProposalEquivocationEvidence { .. })),
            "distinct leaders must not trip proposal-equivocation: {actions:?}",
        );
    }
}

/// The same leader proposing at *different* views for different
/// blocks is normal HotStuff progress, not equivocation: the
/// per-view dedup key separates them.
#[test]
fn same_leader_at_different_views_does_not_emit_proposal_evidence() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());

    // View 1 is leader nid(2) under round-robin; view 5 is also
    // nid(2) (4-validator wrap-around). Two distinct proposals
    // from the same leader at distinct views produce no evidence.
    let block_v1 = fork_at_view(genesis.hash(), 1, nid(2), 0xAA);
    let block_v5 = fork_at_view(genesis.hash(), 5, nid(2), 0xBB);

    let v1 = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_v1, justify.clone(), nid(2))),
    ));
    let v5 = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_v5, justify, nid(2))),
    ));
    for actions in [&v1, &v5] {
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::ProposalEquivocationEvidence { .. })),
            "same leader at distinct views must not trip equivocation: {actions:?}",
        );
    }
}

/// Memory bound: the proposal-dedupe map is GC'd in
/// [`HotStuffCore::evict_vote_buckets_below`], which fires on
/// `PacemakerAdvance`. After advancing past the recorded view, a
/// previously-seen `(leader, view)` pair no longer detects
/// equivocation — the entry has been swept out alongside the
/// matching `vote_bucket` entry. Mirrors the
/// `vote_dedupe` GC test exactly.
#[test]
fn pacemaker_advance_garbage_collects_proposal_dedupe() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let justify = dummy_qc(View(0), genesis.hash());
    let view: View = View(1);
    let block = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();

    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block, justify, nid(2))),
    ));
    assert!(core.proposal_dedupe.contains_key(&(view, vid(2))));

    let _ = core.step(Event::PacemakerAdvance(view + 1));
    assert!(
        !core.proposal_dedupe.contains_key(&(view, vid(2))),
        "proposal_dedupe entry must be GC'd alongside its vote_bucket",
    );
}

/// Idempotency under un-park: a parked proposal whose parent
/// arrives later is re-dispatched through `on_proposal_received`
/// from `on_pacemaker_advance`. The re-dispatch hits the dedupe
/// map with the same `(view, leader, block_hash)` it inserted on
/// first arrival, so no spurious evidence fires. Without this
/// guarantee every parked-then-re-delivered honest proposal would
/// look like equivocation against itself.
#[test]
fn parked_proposal_redispatch_does_not_self_trigger_equivocation_evidence() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let parent = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
    let parent_hash = parent.hash();
    let child = Block {
        header: BlockHeader {
            parent_hash,
            height: Height(2),
            view: View(2),
            proposer: nid(3),
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        },
        commands: Vec::new(),
    };
    let child_hash = child.hash();
    let parent_qc = dummy_qc(View(1), parent_hash);
    let signed_child = signed_proposal(child, parent_qc, nid(3));

    // Phase 1: child arrives with parent missing → parks. Dedupe
    // records (view=2, leader=vid(3)) → child_hash.
    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_child),
    ));
    assert!(core.parked_proposals.contains_key(&child_hash));
    assert_eq!(
        core.proposal_dedupe.get(&(View(2), vid(3))),
        Some(&child_hash),
    );

    // Phase 2: out-of-band, parent arrives in pending_blocks.
    core.state.insert_pending(parent);

    // Phase 3: PacemakerAdvance(View(2)) un-parks the child and
    // re-dispatches through `on_proposal_received`. The
    // `evict_vote_buckets_below(2)` sweep that runs first leaves
    // the (view=2, leader=vid(3)) dedupe entry in place
    // (`view >= gc_below`); the un-park itself bypasses
    // [`HotStuffCore::step`] (and therefore `check_proposal_dedupe`
    // entirely), so no spurious evidence fires either way.
    let actions = core.step(Event::PacemakerAdvance(View(2)));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::ProposalEquivocationEvidence { .. })),
        "un-park re-dispatch must not self-trigger evidence: {actions:?}",
    );
    assert_eq!(
        core.proposal_dedupe.get(&(View(2), vid(3))),
        Some(&child_hash),
        "the recorded dedupe entry must survive the un-park unchanged",
    );
}

// ── D7: parked proposal re-dispatch after parent arrives ────────

#[test]
fn parked_proposal_redispatches_on_pacemaker_advance_once_parent_is_present() {
    // Phase 1: receive a proposal for v2 while its parent v1
    // isn't in `pending_blocks` — B1 parks it and emits
    // `RequestBlock(v1_hash, sender)`.
    //
    // Phase 2: simulate v1 arriving via some out-of-band path
    // (e.g., a RequestBlock response handled by the integration
    // layer) by inserting it directly into `pending_blocks`.
    //
    // Phase 3: `PacemakerAdvance(3)` finds v2's parent now
    // present, re-dispatches v2 through `on_proposal_received`,
    // and then broadcasts `NewView` carrying the just-adopted
    // high_qc.
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
    let block_v1 = chain[0].clone();
    let block_v2 = chain[1].clone();
    let block_v2_hash = block_v2.hash();
    let justify_v1 = dummy_qc(View(1), block_v1.hash());

    // Phase 1 — parent missing, proposal parks.
    let initial = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(
            block_v2.clone(),
            justify_v1.clone(),
            nid(2),
        )),
    ));
    assert_eq!(
        initial,
        vec![Action::RequestBlock {
            hash: block_v1.hash(),
            peer: nid(2),
            expected_height: Height(1),
            reason: BlockSyncReason::UnknownParentOnProposal,
        }],
    );
    assert!(core.parked_proposals.contains_key(&block_v2_hash));

    // Phase 2 — parent lands some other way.
    core.state.insert_pending(block_v1.clone());

    // Phase 3 — advance the view; un-park fires.
    let advance = core.step(Event::PacemakerAdvance(View(3)));

    // Re-dispatch of v2 yields the normal B2/B3 actions:
    // VotedInView + HighQc + Broadcast(Vote). B4/B5 skip
    // (grandparent is genesis's sentinel). Then C4's trailing
    // `Broadcast(NewView)` carries the just-adopted high_qc.
    assert_eq!(
        advance,
        vec![
            Action::Persist(StateUpdate::VotedInView { view: View(2) }),
            Action::Persist(StateUpdate::HighQc(justify_v1.clone())),
            Action::Broadcast(ConsensusMsg::Vote(Vote {
                view: View(2),
                block_hash: block_v2_hash,
            })),
            Action::Broadcast(ConsensusMsg::NewView(NewView {
                high_qc: justify_v1,
            })),
        ],
        "un-park re-dispatch + NewView broadcast",
    );
    assert_eq!(core.state().current_view, View(3));
    assert!(
        !core.parked_proposals.contains_key(&block_v2_hash),
        "parked entry removed after successful re-dispatch",
    );
}

/// Issue #178 regression. A proposal whose parent never arrived
/// stays parked across `PacemakerAdvance`. Each subsequent advance
/// must re-emit `Action::RequestBlock(parent_hash, sender)` so the
/// integration layer retries the fetch — without this, a single
/// dropped `BlockRequest` strands the proposal forever and any
/// further consensus progress on this node depends on a peer
/// happening to re-propose a descendant block.
#[test]
fn still_parked_proposal_re_emits_request_block_on_pacemaker_advance() {
    let mut core = make_core(1);
    let genesis = Block::genesis([0; 32], [0; 32]);
    let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
    let block_v1 = chain[0].clone();
    let block_v2 = chain[1].clone();
    let justify_v1 = dummy_qc(View(1), block_v1.hash());

    // Phase 1 — parent missing, proposal parks. Initial RequestBlock fires.
    let initial = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(block_v2.clone(), justify_v1, nid(2))),
    ));
    assert_eq!(
        initial,
        vec![Action::RequestBlock {
            hash: block_v1.hash(),
            peer: nid(2),
            expected_height: Height(1),
            reason: BlockSyncReason::UnknownParentOnProposal,
        }],
    );

    // Phase 2 — parent has NOT arrived yet. PacemakerAdvance must
    // re-emit RequestBlock so the integration layer can retry.
    // No high_qc set → no trailing Broadcast(NewView).
    let advance = core.step(Event::PacemakerAdvance(View(2)));
    assert_eq!(
        advance,
        vec![Action::RequestBlock {
            hash: block_v1.hash(),
            peer: nid(2),
            expected_height: Height(1),
            reason: BlockSyncReason::StillParkedOnPacemakerAdvance,
        }],
        "still-parked proposal must re-fire RequestBlock on PacemakerAdvance",
    );
    assert_eq!(core.state().current_view, View(2));
    assert!(
        core.parked_proposals.contains_key(&block_v2.hash()),
        "proposal stays parked until parent arrives",
    );

    // Phase 3 — parent lands. Next PacemakerAdvance un-parks (no
    // RequestBlock retry, parent now resolved) and the un-parked
    // proposal proceeds through the happy path.
    core.state.insert_pending(block_v1.clone());
    let advance = core.step(Event::PacemakerAdvance(View(3)));
    let has_request_block = advance
        .iter()
        .any(|a| matches!(a, Action::RequestBlock { .. }));
    assert!(
        !has_request_block,
        "no RequestBlock should fire once the parent has arrived; got {advance:?}",
    );
    let has_vote = advance
        .iter()
        .any(|a| matches!(a, Action::Broadcast(ConsensusMsg::Vote(_))));
    assert!(
        has_vote,
        "un-parked proposal must vote on its newly-resolved parent",
    );
}

/// When two proposals are parked at distinct parents, every
/// `PacemakerAdvance` re-emits one `RequestBlock` per still-parked
/// proposal. Sorted-by-`child_hash` iteration keeps replay
/// deterministic.
#[test]
fn multiple_still_parked_proposals_each_get_a_request_block_retry() {
    let mut core = make_core(1);
    let parent_a: BlockHash = [0xAA; 32];
    let parent_b: BlockHash = [0xBB; 32];
    let justify = dummy_qc(View(0), core.state().genesis_hash);

    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(
            orphan_child(parent_a, 1, nid(2)),
            justify.clone(),
            nid(3),
        )),
    ));
    let _ = core.step(Event::ProposalReceived(
        crate::dispatch::Verified::unchecked(signed_proposal(
            orphan_child(parent_b, 2, nid(2)),
            justify,
            nid(4),
        )),
    ));
    assert_eq!(core.parked_proposals.len(), 2);

    let advance = core.step(Event::PacemakerAdvance(View(3)));
    let request_blocks: Vec<_> = advance
        .iter()
        .filter(|a| matches!(a, Action::RequestBlock { .. }))
        .cloned()
        .collect();
    assert_eq!(
        request_blocks.len(),
        2,
        "every still-parked proposal must get a retry RequestBlock; got {advance:?}",
    );
    // Both targets are present. `orphan_child` produces height 1
    // for both children, so both retries carry expected_height = 0.
    assert!(request_blocks.contains(&Action::RequestBlock {
        hash: parent_a,
        peer: nid(3),
        expected_height: Height(0),
        reason: BlockSyncReason::StillParkedOnPacemakerAdvance,
    }));
    assert!(request_blocks.contains(&Action::RequestBlock {
        hash: parent_b,
        peer: nid(4),
        expected_height: Height(0),
        reason: BlockSyncReason::StillParkedOnPacemakerAdvance,
    }));
}

// ── #196: block-sync per-peer fallback + budget ────────────────────
//
// The pacemaker-advance retry loop has its own retry-state
// (`block_sync_inflight`) that lives separately from the
// unbounded "ask the same peer forever" behaviour exercised in
// the tests above. These tests explicitly enable the rotation
// and drop knobs and pin behaviour for the four scenarios
// called out in #196's acceptance criteria.

mod block_sync {
    use super::*;
    use crate::limits::{CacheEvictionCounters, CacheLimits};

    /// Build a core that exercises the #196 retry knobs explicitly.
    /// `per_peer_attempts` and `max_attempts` are the only fields
    /// that vary across these tests; backoff is disabled (0/0)
    /// so each `PacemakerAdvance` is eligible to fire a retry.
    fn make_rotation_core(
        self_byte: u8,
        per_peer_attempts: u32,
        max_attempts: u32,
    ) -> HotStuffCore {
        let mut limits = CacheLimits::unbounded_for_tests();
        limits.block_sync_per_peer_attempts = per_peer_attempts;
        limits.block_sync_max_attempts = max_attempts;
        // Backoff stays at 0/0: rotation cadence is the focus.
        let state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        HotStuffCore::with_limits(
            nid(self_byte),
            state,
            limits,
            CacheEvictionCounters::default(),
        )
    }

    /// Acceptance criterion #1: park a proposal, advance the
    /// pacemaker N times with the original sender silent, assert
    /// the request rotates to a different peer by the Kth
    /// advance.
    ///
    /// `per_peer_attempts = 2` means the original sender gets the
    /// initial probe + one retry, then we rotate. With backoff
    /// disabled, the rotation point is the third RequestBlock
    /// emission — i.e. the 2nd `PacemakerAdvance` after parking.
    #[test]
    fn rotates_to_different_peer_after_per_peer_budget_exhausted() {
        // self = nid(1); validators are [nid(1), nid(2), nid(3), nid(4)].
        // sender = nid(2). Round 1 in the rotation ring (sorted,
        // skipping self) starts at the validator immediately
        // after sender → nid(3).
        let mut core = make_rotation_core(1, /* per_peer = */ 2, /* max = */ 8);
        let parent: BlockHash = [0xAA; 32];
        let child = orphan_child(parent, 1, nid(3));
        let justify = dummy_qc(View(0), core.state().genesis_hash);
        let sender = nid(2);

        // Initial probe: attempts = 1, peer = sender.
        let initial = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(child, justify, sender)),
        ));
        assert_eq!(
            initial,
            vec![Action::RequestBlock {
                hash: parent,
                peer: sender,
                expected_height: Height(0),
                reason: BlockSyncReason::UnknownParentOnProposal,
            }],
        );

        // Advance #1: attempts = 1 → 2, still round 0, peer = sender.
        let advance_one = core.step(Event::PacemakerAdvance(View(1)));
        let req_one = advance_one
            .iter()
            .find_map(|a| match a {
                Action::RequestBlock { peer, .. } => Some(*peer),
                _ => None,
            })
            .expect("retry must fire on the first advance");
        assert_eq!(
            req_one, sender,
            "the per-peer budget hasn't been spent yet; retry must still go to the original sender",
        );

        // Advance #2: attempts = 2 → 3, round transitions to 1 →
        // peer rotates to the next validator (nid(3)).
        let advance_two = core.step(Event::PacemakerAdvance(View(2)));
        let req_two = advance_two
            .iter()
            .find_map(|a| match a {
                Action::RequestBlock { peer, .. } => Some(*peer),
                _ => None,
            })
            .expect("retry must fire on the second advance");
        assert_ne!(
            req_two, sender,
            "by the K-th advance (per_peer_attempts = 2), the retry must rotate off the original sender",
        );
        assert_eq!(
            req_two,
            nid(3),
            "rotation steps through the validator ring sorted-and-skipping-self; nid(3) is next after nid(2)",
        );
    }

    /// Acceptance criterion #2: park a proposal, parent arrives,
    /// assert the in-flight retry entry is cleared. Two arrival
    /// paths must both clear: `insert_pending_block` (the
    /// integration-layer hand-off after a `BlockResponse`) and
    /// the un-parking branch of `on_pacemaker_advance` (when the
    /// parent landed via a freshly-arrived proposal).
    #[test]
    fn parent_arrival_via_insert_pending_block_clears_inflight_entry() {
        let mut core = make_rotation_core(1, 2, 8);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
        let parent_block = chain[0].clone();
        let child_block = chain[1].clone();
        let justify_v1 = dummy_qc(View(1), parent_block.hash());

        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(child_block, justify_v1, nid(2))),
        ));
        assert!(
            core.block_sync_inflight.contains_key(&parent_block.hash()),
            "in-flight entry must be installed on the initial probe",
        );

        // Integration-layer hand-off: BlockResponse arrives.
        core.insert_pending_block(parent_block.clone());
        assert!(
            !core.block_sync_inflight.contains_key(&parent_block.hash()),
            "in-flight entry must be cleared once the parent has landed in pending_blocks",
        );
    }

    /// The same clearing must happen when the parent arrives via
    /// a freshly-received proposal of its own (so the un-parking
    /// branch of `on_pacemaker_advance` walks the parked map and
    /// re-dispatches). The test parks a grandchild whose
    /// grandparent arrives first, then the parent: the parent's
    /// in-flight entry must clear when its proposal is processed
    /// (B2 path), not just when `PacemakerAdvance` re-runs.
    #[test]
    fn parent_arrival_via_proposal_clears_inflight_entry() {
        let mut core = make_rotation_core(1, 2, 8);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
        let parent_block = chain[0].clone();
        let child_block = chain[1].clone();
        let justify_v0 = dummy_qc(View(0), genesis.hash());
        let justify_v1 = dummy_qc(View(1), parent_block.hash());

        // Park the child; in-flight entry installed for the
        // missing parent_block hash.
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                child_block.clone(),
                justify_v1,
                nid(2),
            )),
        ));
        assert!(core.block_sync_inflight.contains_key(&parent_block.hash()));

        // The parent itself arrives (via proposal, not via
        // BlockResponse). It traverses the B2 happy-path branch,
        // which inserts the block into pending_blocks and clears
        // the corresponding in-flight entry.
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                parent_block.clone(),
                justify_v0,
                nid(2),
            )),
        ));
        assert!(
            !core.block_sync_inflight.contains_key(&parent_block.hash()),
            "in-flight entry must clear when the parent's own proposal is processed",
        );
    }

    /// Total budget exhaustion: after `max_attempts`
    /// `RequestBlock`s, the next pacemaker advance drops every
    /// parked proposal whose parent is exhausted, ticks
    /// `block_sync_dropped`, and tears down the in-flight entry.
    #[test]
    fn drops_parked_proposal_after_max_attempts_exhausted() {
        // per_peer = 2, max = 4 → after 4 RequestBlock emissions
        // the budget is spent. With backoff disabled, that's the
        // initial probe + 3 PacemakerAdvances.
        let mut core = make_rotation_core(1, 2, 4);
        let parent: BlockHash = [0xAA; 32];
        let child = orphan_child(parent, 1, nid(3));
        let child_hash = child.hash();
        let justify = dummy_qc(View(0), core.state().genesis_hash);
        let sender = nid(2);

        // Initial probe (attempt 1).
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(child, justify, sender)),
        ));
        assert_eq!(core.block_sync_inflight.len(), 1);

        // Advances 1..=3 fire attempts 2..=4.
        for v in 1..=3u64 {
            let advance = core.step(Event::PacemakerAdvance(View(v)));
            let request_count = advance
                .iter()
                .filter(|a| matches!(a, Action::RequestBlock { .. }))
                .count();
            assert_eq!(
                request_count, 1,
                "advance {v} must fire one retry while the budget is unspent",
            );
        }
        assert!(
            core.parked_proposals.contains_key(&child_hash),
            "parked proposal must still be present while budget is unspent",
        );
        assert_eq!(core.eviction_counters().block_sync_dropped(), 0);

        // Advance 4: attempts has reached `max_attempts (=4)`.
        // The retry loop must drop the parked proposal and tick
        // the counter; no RequestBlock emission this round.
        let drop_advance = core.step(Event::PacemakerAdvance(View(4)));
        assert!(
            !drop_advance
                .iter()
                .any(|a| matches!(a, Action::RequestBlock { .. })),
            "exhausted-budget advance must not emit another RequestBlock; got {drop_advance:?}",
        );
        assert!(
            !core.parked_proposals.contains_key(&child_hash),
            "parked proposal whose parent's retry budget is exhausted must be dropped",
        );
        assert!(
            !core.block_sync_inflight.contains_key(&parent),
            "in-flight entry must be torn down once the parked proposal is dropped",
        );
        assert_eq!(
            core.eviction_counters().block_sync_dropped(),
            1,
            "block_sync_dropped counter must tick once per dropped parked proposal",
        );
    }

    /// Backoff suppression: with a non-zero initial backoff, a
    /// `PacemakerAdvance` whose view-gap is shorter than
    /// `backoff(attempts)` must not re-emit a RequestBlock. This
    /// is the per-peer rate-limiting half of the issue —
    /// without it, the same peer is asked on every advance.
    #[test]
    fn backoff_suppresses_retry_within_window() {
        // Tight, predictable schedule: initial = 2, max = 2 →
        // backoff is always 2 views. per_peer = MAX so peer
        // never rotates and we can pin behaviour to a single
        // dimension (timing).
        let mut limits = CacheLimits::unbounded_for_tests();
        limits.block_sync_initial_backoff_views = 2;
        limits.block_sync_max_backoff_views = 2;
        let state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        let mut core =
            HotStuffCore::with_limits(nid(1), state, limits, CacheEvictionCounters::default());

        let parent: BlockHash = [0xCC; 32];
        let child = orphan_child(parent, 5, nid(3));
        let justify = dummy_qc(View(0), core.state().genesis_hash);
        let sender = nid(2);

        // Initial probe at view 0; last_asked_view = 0.
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(child, justify, sender)),
        ));

        // Advance to view 1 — only one view has elapsed; backoff
        // requires two. No RequestBlock this round.
        let suppressed = core.step(Event::PacemakerAdvance(View(1)));
        assert!(
            !suppressed
                .iter()
                .any(|a| matches!(a, Action::RequestBlock { .. })),
            "advance within the backoff window must not re-emit a RequestBlock; got {suppressed:?}",
        );

        // Advance to view 2 — two views have elapsed; backoff
        // satisfied. RequestBlock fires.
        let firing = core.step(Event::PacemakerAdvance(View(2)));
        assert_eq!(
            firing
                .iter()
                .filter(|a| matches!(a, Action::RequestBlock { .. }))
                .count(),
            1,
            "advance once the backoff has elapsed must re-emit exactly one RequestBlock; got {firing:?}",
        );
    }

    /// Re-delivery of the same orphan proposal within the
    /// backoff window must be suppressed (unlike pre-#196 where
    /// every re-delivery emitted a duplicate RequestBlock). The
    /// safety core's own retry loop is now authoritative for
    /// throttling.
    #[test]
    fn redelivery_within_backoff_window_is_suppressed() {
        let mut limits = CacheLimits::unbounded_for_tests();
        limits.block_sync_initial_backoff_views = 4;
        limits.block_sync_max_backoff_views = 4;
        let state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        let mut core =
            HotStuffCore::with_limits(nid(1), state, limits, CacheEvictionCounters::default());

        let parent: BlockHash = [0xDD; 32];
        let child = orphan_child(parent, 7, nid(3));
        let justify = dummy_qc(View(0), core.state().genesis_hash);
        let signed = signed_proposal(child, justify, nid(2));

        // First delivery: initial probe fires.
        let first = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed.clone()),
        ));
        assert_eq!(first.len(), 1);

        // Re-delivery at the same view (backoff is 4 views, 0
        // elapsed): suppressed.
        let second = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed),
        ));
        assert!(
            second.is_empty(),
            "re-delivery within the backoff window must not refire RequestBlock; got {second:?}",
        );
        assert_eq!(core.parked_proposals.len(), 1);
        // attempts must still be 1 — re-delivery did not consume
        // budget.
        assert_eq!(
            core.block_sync_inflight.get(&parent).map(|i| i.attempts),
            Some(1),
        );
    }

    /// Direct unit on `pick_block_sync_peer`: rotation order is
    /// validator-set sorted, starts after the original sender,
    /// skips `self_id`, and wraps once the ring is exhausted.
    /// This makes the rotation behaviour testable without
    /// having to drive a fully-instrumented pacemaker.
    #[test]
    fn pick_block_sync_peer_rotates_validator_ring_skipping_self() {
        let validators = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)]);
        let self_id = nid(1);
        let sender = nid(2);
        // per_peer = 1 forces a fresh round on every increment.
        // Round 0 = sender (nid(2)), round 1 = ring[0] (nid(3)),
        // round 2 = ring[1] (nid(4)), round 3 = ring[2] (nid(2)),
        // round 4 wraps back to ring[0] (nid(3)), …
        let attempts_to_peer = |attempts: u32| {
            pick_block_sync_peer(
                sender,
                attempts,
                /* per_peer = */ 1,
                &validators,
                self_id,
            )
        };
        assert_eq!(attempts_to_peer(0), sender, "round 0 → sender");
        assert_eq!(
            attempts_to_peer(1),
            nid(3),
            "round 1 → first non-self peer after sender"
        );
        assert_eq!(attempts_to_peer(2), nid(4));
        assert_eq!(
            attempts_to_peer(3),
            sender,
            "ring wraps back to sender after exhaustion"
        );
        assert_eq!(attempts_to_peer(4), nid(3), "wrap loops around the ring");
    }

    /// Issue #240: once the integration layer hands us the
    /// requested block via `insert_pending_block`, the in-flight
    /// retry tracker keyed on the NewView-seeded hash must clear.
    /// Mirrors the proposal-driven `parent_arrival_via_*` tests.
    #[test]
    fn high_qc_block_arrival_via_insert_pending_block_clears_inflight_entry() {
        let mut core = make_rotation_core(1, 2, 8);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let block_v3 = chain_from_genesis(&genesis, &[3], nid(2))[0].clone();
        let block_v3_hash = block_v3.hash();
        let qc_v3 = dummy_qc(View(3), block_v3_hash);

        let _ = core.step(Event::NewViewReceived(
            crate::dispatch::Verified::unchecked(signed_newview(qc_v3, nid(2))),
        ));
        assert!(
            core.block_sync_inflight.contains_key(&block_v3_hash),
            "in-flight entry must be installed on the NewView-driven initial probe",
        );

        core.insert_pending_block(block_v3);
        assert!(
            !core.block_sync_inflight.contains_key(&block_v3_hash),
            "in-flight entry must clear once the high_qc's referenced block has landed",
        );
    }

    /// Issue #240, retry leg: a NewView seeds an in-flight entry
    /// for an unknown high_qc block_hash. With no parked
    /// proposals depending on that hash, the parked-proposals
    /// loop alone wouldn't drive retries. `on_pacemaker_advance`
    /// must include the high_qc parent in its retry set so the
    /// existing rotation/budget machinery applies.
    #[test]
    fn pacemaker_advance_retries_unknown_high_qc_block_with_no_parked_proposals() {
        // self = nid(1); per_peer = 1 forces rotation on every
        // attempt so the test can pin the rotation cycle. Backoff
        // disabled so each PacemakerAdvance is eligible to fire.
        let mut core = make_rotation_core(1, /* per_peer = */ 1, /* max = */ 4);
        let unknown: BlockHash = [0xC0; 32];
        let qc = dummy_qc(View(7), unknown);
        let sender = nid(2);

        // Seed via NewView: initial probe lands at the sender,
        // attempts = 1.
        let initial = core.step(Event::NewViewReceived(
            crate::dispatch::Verified::unchecked(signed_newview(qc, sender)),
        ));
        assert_eq!(
            initial
                .iter()
                .filter(|a| matches!(a, Action::RequestBlock { .. }))
                .count(),
            1,
            "NewView with unknown block must seed exactly one RequestBlock; got {initial:?}",
        );
        assert_eq!(
            core.block_sync_inflight.get(&unknown).map(|e| e.attempts),
            Some(1),
        );
        assert!(
            core.parked_proposals.is_empty(),
            "this test specifically covers the no-parked-proposals path; \
                 parked_proposals must remain empty",
        );

        // Advance #1: per_peer=1 → rotation steps off sender to
        // nid(3) (ring[0] after sender, skipping self=nid(1)).
        let advance_one = core.step(Event::PacemakerAdvance(View(1)));
        let req_one = advance_one
            .iter()
            .find_map(|a| match a {
                Action::RequestBlock { peer, .. } => Some(*peer),
                _ => None,
            })
            .expect("retry must fire on advance #1");
        assert_eq!(req_one, nid(3));
    }

    /// Issue #240: budget exhaustion on a NewView-seeded entry
    /// must tear down the in-flight tracker even when no parked
    /// proposals depend on the missing parent. Otherwise
    /// `block_sync_inflight` leaks: every distinct high_qc whose
    /// block we never receive would consume a slot forever.
    #[test]
    fn pacemaker_advance_drops_exhausted_high_qc_inflight_entry_with_no_parked_proposals() {
        // per_peer = 4, max = 4 — initial probe + 3 advances and
        // we are at the budget. The 4th advance must clean up.
        let mut core = make_rotation_core(1, /* per_peer = */ 4, /* max = */ 4);
        let unknown: BlockHash = [0xD0; 32];
        let qc = dummy_qc(View(11), unknown);
        let sender = nid(2);

        // Seed: attempts goes 0 → 1.
        let _ = core.step(Event::NewViewReceived(
            crate::dispatch::Verified::unchecked(signed_newview(qc, sender)),
        ));
        assert_eq!(core.block_sync_inflight.len(), 1);

        // Advances 1..=3: attempts climbs 1 → 4.
        for v in 1..=3u64 {
            let advance = core.step(Event::PacemakerAdvance(View(v)));
            assert_eq!(
                advance
                    .iter()
                    .filter(|a| matches!(a, Action::RequestBlock { .. }))
                    .count(),
                1,
                "advance {v} must fire one retry while the budget is unspent",
            );
        }
        assert!(core.block_sync_inflight.contains_key(&unknown));

        // Advance #4: attempts has reached `max_attempts (=4)`.
        // No parked proposals depend on `unknown`, so
        // `drop_parked_for_parent` evicts zero parked entries
        // (the counter does NOT tick — it counts dropped parked
        // proposals, not exhausted in-flight slots) but still
        // tears the in-flight entry down.
        let drop_advance = core.step(Event::PacemakerAdvance(View(4)));
        assert!(
            !drop_advance
                .iter()
                .any(|a| matches!(a, Action::RequestBlock { .. })),
            "exhausted-budget advance must not emit another RequestBlock; got {drop_advance:?}",
        );
        assert!(
            !core.block_sync_inflight.contains_key(&unknown),
            "in-flight entry must be torn down once the high_qc-driven retry budget is spent, \
                 even with no parked proposals on hand",
        );
        assert_eq!(
            core.eviction_counters().block_sync_dropped(),
            0,
            "block_sync_dropped counts dropped parked proposals; \
                 this path drops zero parked proposals (none depended on the missing parent)",
        );
    }

    /// `block_sync_backoff_views` schedule: zero on attempts == 0
    /// (no probe yet), exponential thereafter, capped at `max`.
    /// `initial == 0` short-circuits to `0` for every input.
    #[test]
    fn block_sync_backoff_views_doubles_and_saturates() {
        // initial = 1, max = 8 → 1, 2, 4, 8, 8, 8, …
        assert_eq!(block_sync_backoff_views(0, 1, 8), 0);
        assert_eq!(block_sync_backoff_views(1, 1, 8), 1);
        assert_eq!(block_sync_backoff_views(2, 1, 8), 2);
        assert_eq!(block_sync_backoff_views(3, 1, 8), 4);
        assert_eq!(block_sync_backoff_views(4, 1, 8), 8);
        assert_eq!(block_sync_backoff_views(5, 1, 8), 8);
        assert_eq!(block_sync_backoff_views(64, 1, 8), 8);
        // initial = 0 disables backoff entirely (`unbounded_for_tests`).
        assert_eq!(block_sync_backoff_views(1, 0, 0), 0);
        assert_eq!(block_sync_backoff_views(99, 0, 0), 0);
    }

    // ── #512: dedicated retry timer ─────────────────────────────────────
    //
    // The wall-clock retry timer fires `step_block_sync_retry_tick`
    // independent of the pacemaker. Its emission rules differ from
    // the pacemaker-driven path in one place: the view-elapsed
    // backoff gate is bypassed, since cadence is enforced
    // externally by [`BlockSyncRetryTimer`]. The per-parent
    // attempt budget and per-peer rotation budget still apply.

    /// A retry tick on an idle core (no inflight) is a no-op.
    #[test]
    fn block_sync_retry_tick_is_noop_when_no_inflight() {
        let mut core = make_core(1);
        assert!(!core.has_any_block_sync_inflight());
        let actions = core.step_block_sync_retry_tick();
        assert!(actions.is_empty());
        assert!(!core.has_any_block_sync_inflight());
    }

    /// Single inflight entry → retry tick emits exactly one
    /// `RequestBlock(RetryTimerTick)`. Crucially the same
    /// `current_view` is used as on the parking step: the
    /// view-elapsed backoff guard does NOT block the emission, so
    /// a single-shot loss recovers within the timer's wall-clock
    /// schedule rather than waiting for the next pacemaker tick.
    #[test]
    fn block_sync_retry_tick_emits_when_view_unchanged() {
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
        let block_v1 = chain[0].clone();
        let block_v2 = chain[1].clone();
        let justify_v1 = dummy_qc(View(1), block_v1.hash());

        // Park v2 — fires the initial RequestBlock(UnknownParentOnProposal).
        let initial = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                block_v2.clone(),
                justify_v1,
                nid(2),
            )),
        ));
        assert_eq!(initial.len(), 1);
        assert!(matches!(initial[0], Action::RequestBlock { .. }));
        let view_at_park = core.state().current_view;

        // Wall-clock retry tick at the **same view** as the park —
        // the pacemaker has not advanced yet. The view-based
        // pacemaker-driven path's `should_retry_block_sync` would
        // suppress this (elapsed views < backoff); the dedicated
        // retry tick must emit anyway.
        assert!(core.has_any_block_sync_inflight());
        let retry = core.step_block_sync_retry_tick();
        assert_eq!(retry.len(), 1, "retry tick must emit one RequestBlock");
        assert!(matches!(
            retry[0],
            Action::RequestBlock {
                hash: _,
                peer: _,
                expected_height: _,
                reason: BlockSyncReason::RetryTimerTick,
            }
        ));
        assert_eq!(
            core.state().current_view,
            view_at_park,
            "retry tick must not advance the view",
        );
        assert!(
            core.has_any_block_sync_inflight(),
            "inflight tracker remains until the parent arrives",
        );
    }

    /// Once the per-parent attempt budget is spent, the retry tick
    /// drops the parked proposals and clears the inflight entry —
    /// matches the pacemaker-driven path's exhaustion behaviour.
    #[test]
    fn block_sync_retry_tick_drops_parked_when_budget_exhausted() {
        // max_attempts = 1: the initial probe consumes the entire
        // per-parent budget, so the next tick has nothing left to
        // try and must drop the parked proposal.
        let mut core = make_rotation_core(1, /* per_peer = */ 1, /* max = */ 1);
        let parent: BlockHash = [0xCD; 32];
        let child = orphan_child(parent, 1, nid(3));
        let justify = dummy_qc(View(0), core.state().genesis_hash);
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(child, justify, nid(2))),
        ));
        assert!(core.has_any_block_sync_inflight());
        assert_eq!(core.parked_proposals.len(), 1);

        // Budget already spent on the initial probe (max_attempts = 1).
        // The tick must drop the parked proposal and clear inflight,
        // emitting no further RequestBlock.
        let retry = core.step_block_sync_retry_tick();
        assert!(
            retry.is_empty(),
            "no RequestBlock on the budget-exhausted path; got {retry:?}",
        );
        assert!(!core.has_any_block_sync_inflight());
        assert!(core.parked_proposals.is_empty());
    }
}

// ── D9: replay determinism ─────────────────────────────────────

#[test]
fn replay_is_deterministic_over_a_mixed_trace() {
    // Two freshly-constructed cores fed the same event trace
    // through `replay` must produce byte-identical outputs. This
    // is the property the integration layer (#24) relies on to
    // turn a failing sim trace into a reproducible regression,
    // and the one the E-series property test will stress under
    // arbitrary interleavings.
    //
    // The trace hits every dispatch branch: PacemakerAdvance,
    // ProposalReceived, VoteReceived, NewViewReceived. It also
    // drives a commit and a quorum-triggered broadcast, so the
    // action vectors across steps vary in shape.
    fn build_trace() -> Vec<Event> {
        let genesis = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
        let block_v1_hash = chain[0].hash();
        let block_v2_hash = chain[1].hash();
        let block_v3_hash = chain[2].hash();

        vec![
            Event::PacemakerAdvance(View(1)),
            Event::ProposalReceived(crate::dispatch::Verified::unchecked(signed_proposal(
                chain[0].clone(),
                dummy_qc(View(0), genesis.hash()),
                nid(2),
            ))),
            Event::ProposalReceived(crate::dispatch::Verified::unchecked(signed_proposal(
                chain[1].clone(),
                dummy_qc(View(1), block_v1_hash),
                nid(2),
            ))),
            Event::ProposalReceived(crate::dispatch::Verified::unchecked(signed_proposal(
                chain[2].clone(),
                dummy_qc(View(2), block_v2_hash),
                nid(2),
            ))),
            Event::VoteReceived(bls_vote(3, block_v3_hash, nid(2))),
            Event::VoteReceived(bls_vote(3, block_v3_hash, nid(3))),
            Event::VoteReceived(bls_vote(3, block_v3_hash, nid(4))),
            Event::NewViewReceived(crate::dispatch::Verified::unchecked(signed_newview(
                dummy_qc(View(99), [0x99; 32]),
                nid(4),
            ))),
            Event::PacemakerAdvance(View(100)),
        ]
    }

    let run1 = make_core(1).replay(build_trace());
    let run2 = make_core(1).replay(build_trace());

    assert_eq!(run1, run2, "replay must be deterministic for a fixed trace",);
    assert_eq!(run1.len(), 9, "one action vector per event");

    // Spot-checks so the test fails informatively if a future
    // dispatch change widens or shrinks a step's output.
    assert!(
        run1[0].is_empty(),
        "step 1 (PacemakerAdvance, no high_qc) emits nothing",
    );
    assert!(
        run1[3].iter().any(|a| matches!(a, Action::Commit(_))),
        "step 4 (third proposal) must emit Commit(genesis)",
    );
    assert!(
        run1[6]
            .iter()
            .any(|a| matches!(a, Action::BuildProposal { .. })),
        "step 7 (quorum fires) must emit BuildProposal (#606)",
    );
    assert!(
        run1[8]
            .iter()
            .any(|a| matches!(a, Action::Broadcast(ConsensusMsg::NewView(_)))),
        "step 9 (PacemakerAdvance) must broadcast NewView",
    );
}

// ── #197: Consensus-layer WAL-replay invariants ────────────────
//
// sim_crash.rs (in src/sim/) covers the storage half of the
// survivor guarantee — that fsync'd KV/WAL bytes survive a
// restart. These tests cover the *consensus* half: regardless of
// whether the bytes hit disk, when a fresh `HotStuffCore` is
// re-initialized from a persisted `(last_voted_view, locked,
// high_qc)` triple, does it actually behave like a survivor —
// refusing to double-vote, lose its lock, or re-adopt a stale
// high_qc?
//
// The tests are deliberately at the safety-core layer, not the
// sim layer: the core is pure (no clock, no I/O), so a
// "snapshot + new core from snapshot" pattern is the cleanest
// way to model a restart without dragging in disk-backing
// machinery the safety property doesn't depend on.
mod wal_replay {
    use super::*;

    /// Model what the integration layer does on boot: build a
    /// fresh [`HotStuffCore`] whose [`HotStuffState`] is seeded
    /// from a persisted `(last_voted_view, locked, high_qc)`
    /// triple and a list of blocks the block-store hands back.
    ///
    /// `pending` mirrors what the integration layer would
    /// re-insert from its block store on boot — `pending_blocks`
    /// is *not* part of the persisted safety-state snapshot
    /// (full blocks live in the block store, not in the WAL'd
    /// safety triple), so the test supplies it explicitly.
    fn restart_with_persisted_state(
        self_byte: u8,
        last_voted_view: impl Into<View>,
        locked: Option<Locked>,
        high_qc: Option<QuorumCertificate>,
        pending: &[Block],
    ) -> HotStuffCore {
        let last_voted_view = last_voted_view.into();
        let mut state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        state.last_voted_view = last_voted_view;
        state.locked = locked;
        // Mirrors `recover_state`: the persisted bytes decode to
        // `QuorumCertificate`, then wrap as `VerifiedQc` at the
        // audited recovery site.
        state.high_qc = high_qc.map(VerifiedQc::unchecked);
        for block in pending {
            state.insert_pending(block.clone());
        }
        HotStuffCore::new(nid(self_byte), state)
    }

    /// Test 1 — vheight monotonicity across restart.
    ///
    /// Drive a node to vote at view 1, snapshot its persisted
    /// state, re-initialize a fresh core from the snapshot, and
    /// re-deliver the same view-1 proposal. The replica must
    /// refuse — `safe_to_vote` returns false on the
    /// `view > last_voted_view` precondition — so no
    /// `Persist(VotedInView)`, no `Broadcast(Vote)`, and no
    /// `Persist(HighQc)` (high_qc adoption is gated on
    /// `safe_to_vote` firing).
    ///
    /// This is the load-bearing safety invariant of HotStuff:
    /// the safety proof's "no equivocation" guarantee depends
    /// on a restarted replica never voting twice at the same
    /// view.
    #[test]
    fn restart_does_not_revote_at_already_voted_view() {
        // Pre-restart: vote at view 1.
        let genesis = Block::genesis([0; 32], [0; 32]);
        let block_v1 = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
        let justify_v0 = dummy_qc(View(0), genesis.hash());
        let signed = signed_proposal(block_v1.clone(), justify_v0, nid(2));

        let mut pre = make_core(1);
        let pre_actions = pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed.clone()),
        ));
        assert!(
            pre_actions.iter().any(|a| matches!(
                a,
                Action::Persist(StateUpdate::VotedInView { view: View(1) })
            )),
            "pre-restart core must vote on the first view-1 proposal: {pre_actions:?}",
        );
        assert_eq!(pre.state().last_voted_view, View(1));

        // Snapshot persisted state. The integration layer flushes
        // these three fields; nothing else needs to survive the
        // crash for the safety invariant to hold.
        let last_voted_view = pre.state().last_voted_view;
        let locked = pre.state().locked;
        let high_qc = pre.state().high_qc.as_ref().map(|q| q.inner().clone());

        // Restart: fresh core, same persisted triple.
        let mut post = restart_with_persisted_state(
            1,
            last_voted_view,
            locked,
            high_qc,
            std::slice::from_ref(&block_v1),
        );

        // Replay the same view-1 proposal.
        let post_actions = post.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed),
        ));

        // No new vote, no broadcast, no high_qc churn — the
        // proposal is silently absorbed (B2 still inserts it
        // into pending_blocks, but that's not an `Action`).
        assert!(
            post_actions.is_empty(),
            "restarted core must emit no actions on a re-delivered same-view proposal: \
                 {post_actions:?}",
        );
        assert_eq!(
            post.state().last_voted_view,
            View(1),
            "last_voted_view stays pinned at the persisted value",
        );
    }

    /// Test 2 — locked_qc preservation.
    ///
    /// Drive a node to lock at height 1 (via three consecutive
    /// proposals at views 1, 2, 3 — the two-chain rule fires on
    /// the third). Snapshot, restart, then present a sibling
    /// proposal at view 4 that does *not* extend the locked
    /// block and whose justify is older than the lock. Both
    /// arms of `safe_to_vote`'s safety disjunction (extension,
    /// liveness) must fail — the replica refuses to vote and
    /// the lock survives untouched.
    ///
    /// A regression that lost or weakened the lock on restart
    /// would let the sibling extract a vote, splitting the
    /// chain. See HotStuff Appendix B Lemma 6.
    #[test]
    fn restart_with_locked_qc_refuses_proposal_breaking_lock() {
        // Pre-restart: drive to a lock at height 1.
        let genesis = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
        let block_v1 = chain[0].clone();
        let block_v2 = chain[1].clone();
        let block_v3 = chain[2].clone();

        let mut pre = make_core(1);
        pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                block_v1.clone(),
                dummy_qc(View(0), genesis.hash()),
                nid(2),
            )),
        ));
        pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                block_v2.clone(),
                dummy_qc(View(1), block_v1.hash()),
                nid(2),
            )),
        ));
        pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                block_v3.clone(),
                dummy_qc(View(2), block_v2.hash()),
                nid(2),
            )),
        ));
        // Two-chain promotion fires on the third proposal:
        // grandparent of view 3 is block_v1 (view 1, height 1).
        let expected_lock = Locked {
            view: View(1),
            height: Height(1),
            block_hash: block_v1.hash(),
        };
        assert_eq!(pre.state().locked, Some(expected_lock));
        assert_eq!(pre.state().last_voted_view, View(3));

        let last_voted_view = pre.state().last_voted_view;
        let locked = pre.state().locked;
        let high_qc = pre.state().high_qc.as_ref().map(|q| q.inner().clone());

        // Restart with the persisted snapshot. block_v1 is the
        // locked block — it MUST be in `pending_blocks` for the
        // extension walk that `safe_to_vote` will run.
        let mut post = restart_with_persisted_state(
            1,
            last_voted_view,
            locked,
            high_qc,
            &[block_v1.clone(), block_v2, block_v3],
        );

        // A Byzantine sibling at view 4: rooted directly on
        // genesis (height 1, NOT extending the locked
        // block_v1), with a stale justify (view 0 ≤ locked
        // view 1, so the liveness rule doesn't fire either).
        let sibling = Block {
            header: BlockHeader {
                parent_hash: genesis.hash(),
                height: Height(1),
                view: View(4),
                proposer: nid(3),
                state_commitment: [0xCC; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
                timestamp: 0,
            },
            commands: Vec::new(),
        };
        let stale_justify = dummy_qc(View(0), genesis.hash());
        let signed_sibling = signed_proposal(sibling, stale_justify, nid(3));

        let actions = post.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_sibling),
        ));

        assert!(
            actions
                .iter()
                .all(|a| !matches!(a, Action::Broadcast(ConsensusMsg::Vote(_)))),
            "lock-breaking sibling must not extract a vote: {actions:?}",
        );
        assert!(
            actions
                .iter()
                .all(|a| !matches!(a, Action::Persist(StateUpdate::VotedInView { .. }))),
            "no Persist(VotedInView) for a refused proposal: {actions:?}",
        );
        assert_eq!(
            post.state().locked,
            Some(expected_lock),
            "lock survives the restart and the refused proposal",
        );
        assert_eq!(post.state().last_voted_view, View(3));
    }

    /// Test 3 — high_qc preservation across restart.
    ///
    /// Drive a node to adopt a `high_qc` at view 1 (process
    /// proposals at views 1 then 2 — the second's justify
    /// QC(view=1) is adopted as high_qc). Snapshot, restart,
    /// then deliver a `NewView` carrying a stale `high_qc`
    /// (view 0). The strict `>` in [`should_update_high_qc`]
    /// must reject the stale QC — no `Persist(HighQc)` and no
    /// regression of `state.high_qc.view`.
    #[test]
    fn restart_does_not_adopt_stale_high_qc_via_newview() {
        let genesis = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
        let block_v1 = chain[0].clone();
        let block_v2 = chain[1].clone();

        let mut pre = make_core(1);
        pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                block_v1.clone(),
                dummy_qc(View(0), genesis.hash()),
                nid(2),
            )),
        ));
        let fresh_qc_v1 = dummy_qc(View(1), block_v1.hash());
        pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                block_v2.clone(),
                fresh_qc_v1.clone(),
                nid(2),
            )),
        ));
        assert_eq!(
            pre.state().high_qc.as_ref().map(|q| q.view()),
            Some(View(1))
        );

        let last_voted_view = pre.state().last_voted_view;
        let locked = pre.state().locked;
        let high_qc = pre.state().high_qc.as_ref().map(|q| q.inner().clone());

        let mut post = restart_with_persisted_state(
            1,
            last_voted_view,
            locked,
            high_qc,
            &[block_v1, block_v2],
        );

        // A NewView carrying a stale high_qc (view 0). The
        // sender is a peer; on the wire this is the shape an
        // ill-informed validator would emit before catching up.
        let stale_newview = signed_newview(dummy_qc(View(0), genesis.hash()), nid(3));
        let actions = post.step(Event::NewViewReceived(
            crate::dispatch::Verified::unchecked(stale_newview),
        ));

        assert!(
            actions.is_empty(),
            "stale NewView must produce no actions: {actions:?}",
        );
        assert_eq!(
            post.state().high_qc.as_ref().map(|q| q.view()),
            Some(View(1)),
            "high_qc preserved at view 1 across restart and stale NewView",
        );
        assert_eq!(
            post.state().high_qc.as_ref().map(|q| q.inner().clone()),
            Some(fresh_qc_v1)
        );
    }

    /// Test 4 — partial persistence.
    ///
    /// `on_proposal_received` emits `Persist(VotedInView)`
    /// before `Persist(HighQc)`. The integration layer flushes
    /// each Persist before the dependent broadcast leaves the
    /// machine, so the worst case at a crash boundary is
    /// "VotedInView hit disk, HighQc did not, Vote never went
    /// out". Model that snapshot and assert two things:
    ///
    /// 1. The persisted vote is binding — re-delivering the
    ///    same proposal post-restart does NOT produce a vote.
    /// 2. The lost high_qc is harmless — it is not retroactively
    ///    adopted from the (now refused) proposal, but it is
    ///    naturally re-acquired from the next proposal's
    ///    justify, so the cluster's freshness story still
    ///    converges.
    ///
    /// This is the consensus-side mirror of
    /// `sim_crash.rs::crash_recovery_preserves_flushed_storage_and_wal_state`'s
    /// "unflushed entry may disappear" clause.
    #[test]
    fn restart_with_persisted_vote_but_missing_high_qc_is_safe() {
        let genesis = Block::genesis([0; 32], [0; 32]);
        let block_v1 = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
        let justify_v0 = dummy_qc(View(0), genesis.hash());
        let signed_v1 = signed_proposal(block_v1.clone(), justify_v0, nid(2));

        // Pre-restart: capture the action sequence and pin the
        // emission order the partial-persistence scenario depends
        // on. If a future refactor re-orders these, the
        // "VotedInView landed but HighQc didn't" scenario stops
        // being the worst-case crash boundary and this test
        // needs to be re-derived.
        let mut pre = make_core(1);
        let pre_actions = pre.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_v1.clone()),
        ));
        let voted_idx = pre_actions
            .iter()
            .position(|a| matches!(a, Action::Persist(StateUpdate::VotedInView { .. })));
        let high_qc_idx = pre_actions
            .iter()
            .position(|a| matches!(a, Action::Persist(StateUpdate::HighQc(_))));
        assert!(
            matches!((voted_idx, high_qc_idx), (Some(v), Some(h)) if v < h),
            "Persist(VotedInView) must precede Persist(HighQc) for the partial-\
                 persistence scenario to be the worst case: {pre_actions:?}",
        );

        // The "crash between Persist actions" snapshot: the
        // VotedInView write reached fsync'd disk, the HighQc
        // write did not.
        let mut post = restart_with_persisted_state(
            1,
            /* last_voted_view */ 1,
            /* locked */ None,
            /* high_qc */ None,
            std::slice::from_ref(&block_v1),
        );

        // (1) Persisted vote is binding — re-delivery of the
        // same proposal must not extract a second vote.
        let replay = post.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_v1),
        ));
        assert!(
            replay
                .iter()
                .all(|a| !matches!(a, Action::Persist(StateUpdate::VotedInView { .. }))),
            "binding vote: no Persist(VotedInView) on replay: {replay:?}",
        );
        assert!(
            replay
                .iter()
                .all(|a| !matches!(a, Action::Broadcast(ConsensusMsg::Vote(_)))),
            "binding vote: no Vote broadcast on replay: {replay:?}",
        );
        // High_qc adoption is gated on `safe_to_vote` firing,
        // so the missed write is also not retroactively
        // recovered from the refused proposal — this is
        // *intentional*: the safety property never required us
        // to remember it, only to not double-vote.
        assert!(
            post.state().high_qc.is_none(),
            "missed HighQc not retroactively adopted from a refused proposal",
        );

        // (2) Harmless: the next proposal carries an even
        // fresher justify and adoption resumes via the normal
        // path. The lost high_qc was a freshness optimization,
        // not a safety witness.
        let block_v2 = chain_from_genesis(&genesis, &[1, 2], nid(2))[1].clone();
        let qc_v1 = dummy_qc(View(1), block_v1.hash());
        let signed_v2 = signed_proposal(block_v2, qc_v1.clone(), nid(2));
        let actions_v2 = post.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_v2),
        ));

        assert!(
            actions_v2.iter().any(|a| matches!(
                a,
                Action::Persist(StateUpdate::HighQc(qc)) if qc.view == View(1)
            )),
            "next proposal recovers high_qc adoption via the normal path: \
                 {actions_v2:?}",
        );
        assert_eq!(
            post.state().high_qc.as_ref().map(|q| q.view()),
            Some(View(1)),
            "high_qc adopted at view 1 from the recovery proposal's justify",
        );
        assert_eq!(
            post.state().last_voted_view,
            View(2),
            "the recovery proposal at view 2 is voted on normally",
        );
    }

    /// Issue #407 / audit finding 4-6: a leader that crashes
    /// between `Signed::sign` (inside the integration layer's
    /// egress path for the `Broadcast(Proposal)` action) and the
    /// network bytes leaving the host must not be able to mint a
    /// *different* signed `Proposal(view)` envelope on restart.
    ///
    /// Pre-restart, `build_proposal_at_view` emits
    /// `Persist(ProposedInView { view })` immediately before its
    /// `Broadcast(Proposal)`, so the dispatcher's
    /// `apply_safety_actions` flushes the persist before any
    /// outbound bytes leave. After restart, the recovery path
    /// threads the persisted value back into the safety core via
    /// [`HotStuffCore::with_proposed_in_view`], so the in-memory
    /// guard re-fires on the next `try_propose_as_leader(view)`
    /// and the build path returns an empty action vec. Two
    /// distinct signed `Proposal(view)` envelopes from the same
    /// honest leader would otherwise be slashable equivocation
    /// evidence in any future slashing implementation.
    #[test]
    fn restart_does_not_re_propose_at_already_proposed_view() {
        // Pre-restart: nid(1) is the round-robin leader of view 4
        // (validators are nid(1..=4); 4 % 4 = 0 → nid(1)). Seed a
        // fresh high_qc over genesis (view 0) and invoke
        // `become_leader(4)` so the build path fires.
        let mut pre = make_core(1);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let qc_genesis = dummy_qc(View(0), genesis.hash());
        pre.state.high_qc = Some(VerifiedQc::unchecked(qc_genesis.clone()));

        let pre_actions = pre.become_leader(4);
        // #606: become_leader emits BuildProposal; simulate the integration
        // layer building + finalizing. `proposal_built` emits the
        // Persist(ProposedInView) + Broadcast(Proposal) pair (persist
        // first, #407) and sets the per-view guard.
        let (bp_view, bp_high_qc, bp_parent) = pre_actions
            .iter()
            .find_map(|a| match a {
                Action::BuildProposal {
                    view,
                    high_qc,
                    parent,
                } => Some((*view, high_qc.clone(), parent.clone())),
                _ => None,
            })
            .expect("pre-restart leader emits BuildProposal");
        assert_eq!(bp_view, View(4));
        let built = pre
            .build_proposal(bp_view, &bp_high_qc, &bp_parent)
            .expect("builder succeeds");
        let finalize = pre.proposal_built(bp_view, built, bp_high_qc);
        let proposed_idx = finalize.iter().position(|a| {
            matches!(
                a,
                Action::Persist(StateUpdate::ProposedInView { view: View(4) })
            )
        });
        let broadcast_idx = finalize
            .iter()
            .position(|a| matches!(a, Action::Broadcast(ConsensusMsg::Proposal(_))));
        assert!(
            matches!((proposed_idx, broadcast_idx), (Some(p), Some(b)) if p < b),
            "Persist(ProposedInView) must precede Broadcast(Proposal) so the \
                 dispatcher flushes the durable mirror before any bytes leave: \
                 {finalize:?}",
        );
        assert_eq!(pre.proposed_in_view(), View(4));
        // Capture the proposal envelope; a second build at view 4
        // must not produce *any* envelope, distinct or otherwise.
        let pre_proposal = finalize
            .iter()
            .find_map(|a| match a {
                Action::Broadcast(ConsensusMsg::Proposal(p)) => Some(p.clone()),
                _ => None,
            })
            .expect("pre-restart leader must have broadcast a proposal");

        // "Crash and restart": fresh state plus the persisted
        // `proposed_in_view` threaded back through
        // `with_proposed_in_view`, mirroring what the integration
        // layer's `recover()` does.
        let mut post_state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        post_state.high_qc = Some(VerifiedQc::unchecked(qc_genesis.clone()));
        let mut post = HotStuffCore::new(nid(1), post_state).with_proposed_in_view(View(4));

        let post_actions = post.become_leader(4);
        assert!(
            post_actions.is_empty(),
            "restart with persisted proposed_in_view must not re-mint at the \
                 same view (would be slashable equivocation if envelopes differed): \
                 {post_actions:?}",
        );
        assert!(
            post_actions
                .iter()
                .all(|a| !matches!(a, Action::Broadcast(ConsensusMsg::Proposal(_)))),
            "no second Broadcast(Proposal) at view 4 after restart: {post_actions:?}",
        );
        // Sanity: with the guard absent (`with_proposed_in_view`
        // not called), the same setup *would* re-mint — confirming
        // the persistence is what's holding the line, not some
        // other branch of `build_proposal_at_view`.
        let mut post_unguarded_state =
            HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        post_unguarded_state.high_qc = Some(VerifiedQc::unchecked(qc_genesis));
        let mut post_unguarded = HotStuffCore::new(nid(1), post_unguarded_state);
        let unguarded_actions = post_unguarded.become_leader(4);
        assert!(
            unguarded_actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { view: View(4), .. })),
            "without the persisted guard, restart *would* re-attempt the proposal at view 4: \
                 {unguarded_actions:?}",
        );
        // The second envelope here happens to be byte-identical
        // because `TestBlockBuilder` is deterministic — production
        // builders are not (different mempool ordering, different
        // `high_qc` snapshot if a peer NewView landed between the
        // two attempts), so the audit finding's "different
        // envelope" hazard is real even when the builder input
        // looks identical. The guard fires regardless of envelope
        // equality.
        let _ = pre_proposal;
    }
}

// ── E1 / E4: Multi-replica property-test harness ────────────────
//
// The harness lives as a nested `mod property` so clippy's
// `items_after_test_module` stays happy (only one top-level
// `#[cfg(test)] mod tests` in the file). Later commits add the
// invariant function and the proptest driver; this module ships
// the deterministic fixture plus a hand-built end-to-end test
// that proves the bus wiring before any randomization.

mod property {
    //! Deterministic simulator for `n = 3f + 1` honest HotStuff
    //! replicas.
    //!
    //! `ReplicaSet` owns one [`HotStuffCore`] per validator, plus
    //! a per-replica inbox of pending [`Event`]s. `apply_actions`
    //! converts each replica's emitted [`Action`]s into the
    //! appropriate inbox pushes on the other replicas — the
    //! "fake bus" from #93's property-test spec. No clock, no
    //! network; just deterministic delivery.
    //!
    //! `Persist` and `RequestBlock` actions are ignored in the
    //! sim: the harness doesn't model durability (the cores'
    //! in-memory state is the source of truth) and every block
    //! the cores need is delivered inline via `ProposalReceived`
    //! events, so no fetch path is necessary.

    use std::collections::{BTreeMap, VecDeque};

    use super::*;

    /// The four-nids-with-increasing-bytes layout from the unit
    /// tests generalized to arbitrary `n`: validator `i` has
    /// NodeId `[i as u8 + 1; 32]` so `validators[i].cmp(validators[j])`
    /// matches `i.cmp(&j)` — the `RoundRobinSelector` inside each
    /// core maps view `v` to validator index `v % n`.
    pub(crate) fn validator_set(n: usize) -> ValidatorSet {
        let members: Vec<crate::validator_set::ValidatorId> = (1..=n as u8)
            .map(|b| crate::validator_set::ValidatorId::from_genesis_pubkey([b; 32]))
            .collect();
        ValidatorSet::new(members)
    }

    pub(crate) struct ReplicaSet {
        /// Honest cores, indexed 0..n_honest. Byzantine validators
        /// have no core — their NodeIds appear in `validators`
        /// (so leader election still maps views to them), but
        /// they produce events only via the adversary strategies
        /// in the property tests below.
        pub cores: Vec<HotStuffCore>,
        /// Per-honest-replica event inbox.
        pub inboxes: Vec<VecDeque<Event>>,
        /// Per-honest-replica committed-blocks ledger.
        pub commits: Vec<BTreeMap<Height, Block>>,
        pub validators: ValidatorSet,
        pub genesis: Block,
        /// How many of the trailing `validators` entries are
        /// Byzantine. Honest validator indices are `0..n_honest`
        /// where `n_honest = validators.len() - byzantine_count`.
        pub byzantine_count: usize,
        /// Chain-level signature scheme this set runs under
        /// (#354 step 3). Drives whether `event_from_msg`
        /// produces a BLS partial alongside each Vote and which
        /// genesis-QC shape `kickoff_proposal` uses.
        pub signature_scheme: SignatureSchemeChoice,
        /// Per-validator BLS keypair. Length matches
        /// `validators.len()`. Indexed parallel to validator order
        /// (sorted ascending), so `bls_keys[i]` belongs to
        /// `validators.get(i)` — Byzantine slots included so
        /// adversarial helpers can sign forged Vote partials
        /// under the Byzantine validator's own BLS key.
        pub bls_keys: Vec<(
            boule_core::crypto::sig_scheme::BlsSecretKey,
            boule_core::crypto::sig_scheme::BlsPublicKey,
        )>,
    }

    impl ReplicaSet {
        /// Build `n` all-honest replicas under `BlsAggregated`.
        /// Shorthand for `new_with_byzantine(n, 0)`.
        pub fn new(n: usize) -> Self {
            Self::new_with_byzantine(n, 0)
        }

        /// Build `n_total` validators with the last `byzantine_count`
        /// treated as Byzantine, under `BlsAggregated`.
        ///
        /// Every validator (including Byzantine slots) gets a
        /// deterministic BLS keypair seeded from its sorted index, so
        /// the same `n_total` always produces byte-identical keys
        /// across runs of the proptest harness.
        pub fn new_with_byzantine(n_total: usize, byzantine_count: usize) -> Self {
            assert!(
                byzantine_count < n_total,
                "byzantine_count must be strictly less than n_total",
            );
            let scheme = SignatureSchemeChoice::BlsAggregated;
            let n_honest = n_total - byzantine_count;
            let validators = validator_set(n_total);
            let genesis = Block::genesis([0; 32], [0; 32]);
            let cores: Vec<HotStuffCore> = (0..n_honest)
                .map(|i| {
                    let nid = validators.get(i).unwrap().into_node_id();
                    let state = HotStuffState::new(validators.clone(), genesis.clone());
                    HotStuffCore::new(nid, state).with_signature_scheme(scheme)
                })
                .collect();
            let inboxes = (0..n_honest).map(|_| VecDeque::new()).collect();
            let commits = (0..n_honest).map(|_| BTreeMap::new()).collect();
            let bls_keys: Vec<_> = (0..n_total)
                .map(|i| {
                    let mut ikm = [0u8; 32];
                    // Spread i across the IKM so different
                    // validator indices produce distinct
                    // pubkeys; XOR with a salt so a
                    // collision against any other test's
                    // seed scheme is unlikely.
                    ikm[0] = (i as u8) ^ 0xA0;
                    ikm[1] = ((i >> 8) as u8) ^ 0x5A;
                    boule_core::crypto::sig_scheme::BlsAggregated::keygen(&ikm)
                        .expect("proptest BLS keygen must not fail")
                })
                .collect();
            Self {
                cores,
                inboxes,
                commits,
                validators,
                genesis,
                byzantine_count,
                signature_scheme: scheme,
                bls_keys,
            }
        }

        /// Sign a BLS partial over the canonical Vote pre-image
        /// using validator `signer_idx`'s BLS key. Returns `None`
        /// on Ed25519 chains (where the optional partial field
        /// rides as `None`). Panics on BLS chains if `signer_idx`
        /// is out of range — the caller should index validators
        /// directly.
        pub fn bls_partial_for_vote(
            &self,
            signer_idx: usize,
            vote: &Vote,
        ) -> Option<boule_core::crypto::sig_scheme::BlsPartialSig> {
            if self.signature_scheme != SignatureSchemeChoice::BlsAggregated {
                return None;
            }
            let preimg = boule_core::crypto::signed::preimage::<Vote>(
                vote,
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("preimage of a fixed-shape Vote must succeed");
            let sk = &self.bls_keys[signer_idx].0;
            Some(
                boule_core::crypto::sig_scheme::BlsAggregated::sign_partial(sk, &preimg)
                    .expect("BLS partial signing must not fail under valid inputs"),
            )
        }

        /// Number of honest replicas the harness is running.
        pub fn len(&self) -> usize {
            self.cores.len()
        }

        /// Byzantine NodeIds — the trailing validator slots that
        /// have no core. Property tests use this list to pick
        /// signers for adversarial events.
        pub fn byzantine_nids(&self) -> Vec<NodeId> {
            let n_honest = self.cores.len();
            (n_honest..n_honest + self.byzantine_count)
                .map(|i| self.validators.get(i).unwrap().into_node_id())
                .collect()
        }

        /// Map a NodeId to an honest-replica index, if that
        /// NodeId belongs to an honest validator. Returns `None`
        /// for Byzantine (or unknown) ids. `apply_actions`
        /// uses this to drop `SendTo` destined for Byzantine —
        /// the adversary sees the message but doesn't process
        /// it through any harness-owned core.
        pub fn honest_index_of(&self, nid: &NodeId) -> Option<usize> {
            let vid = crate::validator_set::ValidatorId::from_genesis_pubkey(*nid);
            let idx = self.validators.index_of(&vid)?;
            if idx < self.cores.len() {
                Some(idx)
            } else {
                None
            }
        }

        /// Queue `event` for honest `replica`'s next `deliver_one`.
        pub fn inject(&mut self, replica: usize, event: Event) {
            self.inboxes[replica].push_back(event);
        }

        /// Queue `event` for every honest replica's inbox.
        pub fn inject_all(&mut self, event: Event) {
            for i in 0..self.cores.len() {
                self.inject(i, event.clone());
            }
        }

        /// Pop the next pending event for `replica` and feed it
        /// through `step`. Returns `true` if an event was
        /// delivered, `false` if the inbox was empty.
        pub fn deliver_one(&mut self, replica: usize) -> bool {
            let Some(event) = self.inboxes[replica].pop_front() else {
                return false;
            };
            let actions = self.cores[replica].step(event);
            self.apply_actions(replica, actions);
            true
        }

        fn apply_actions(&mut self, source: usize, actions: Vec<Action>) {
            let source_nid = self.validators.get(source).unwrap().into_node_id();
            for action in actions {
                match action {
                    Action::Broadcast(msg) => {
                        // Only honest replicas have inboxes;
                        // Byzantine "receipt" is a no-op. The
                        // event is built once per target so the
                        // immutable `self` borrow inside
                        // `event_from_msg` doesn't race the
                        // mutable `self.inboxes` borrow.
                        for target in 0..self.cores.len() {
                            let event = self.event_from_msg(source_nid, msg.clone());
                            self.inboxes[target].push_back(event);
                        }
                    }
                    Action::Commit(block) => {
                        self.commits[source].insert(block.header.height, block);
                    }
                    // Safety-core effects the harness doesn't
                    // model. `Persist` is durability, `RequestBlock`
                    // is sync; both are integration-layer jobs.
                    // `EquivocationEvidence` and
                    // `ProposalEquivocationEvidence` are
                    // informational (logged + counter-incremented)
                    // — the harness counts the action presence
                    // rather than acting on it.
                    Action::Persist(_)
                    | Action::RequestBlock { .. }
                    | Action::EquivocationEvidence { .. }
                    | Action::ProposalEquivocationEvidence { .. } => {}
                    // #606: build moved out of the core. Stand in for the
                    // integration layer — run the builder and re-apply the
                    // resulting Persist + Broadcast(Proposal) (which then
                    // fans out to inboxes like any broadcast). A build
                    // failure is the retriable skip.
                    Action::BuildProposal {
                        view,
                        high_qc,
                        parent,
                    } => {
                        if let Ok(block) =
                            self.cores[source].build_proposal(view, &high_qc, &parent)
                        {
                            let built = self.cores[source].proposal_built(view, block, high_qc);
                            self.apply_actions(source, built);
                        }
                    }
                }
            }
        }

        /// Round-robin deliver for up to `max_rounds` passes, or
        /// until every inbox is empty. Does NOT panic on
        /// non-quiescence: honest HotStuff is self-sustaining
        /// (each successful view triggers the next), so tests
        /// bound the run explicitly and inspect the recorded
        /// commits afterwards.
        pub fn run_bounded(&mut self, max_rounds: usize) {
            for _ in 0..max_rounds {
                let mut progress = false;
                for i in 0..self.cores.len() {
                    if self.deliver_one(i) {
                        progress = true;
                    }
                }
                if !progress {
                    return;
                }
            }
        }

        /// Seed a fully-signed BLS QC over `(view, block_hash)` —
        /// exactly what an honest integration layer would produce
        /// from `n` real validators voting. Used for crafting the
        /// kickoff proposal and Byzantine forged QCs; not something
        /// the safety core would ever build internally.
        ///
        /// The bitmap is filled and the aggregate folded from real
        /// per-validator BLS partials over the `(view, block_hash)`
        /// pre-image, so the resulting QC is structurally
        /// well-formed and `verify_aggregate_bls`-checkable. The
        /// safety core only reads `view`, `block_hash`, and
        /// `has_quorum`, but keeping the QC well-formed mirrors what
        /// an honest integration layer would produce.
        pub fn synth_qc(&self, view: View, block_hash: BlockHash) -> QuorumCertificate {
            let mut qc = QuorumCertificate::new_bls(view, block_hash, self.validators.len());
            let vote = Vote { view, block_hash };
            let preimg = boule_core::crypto::signed::preimage::<Vote>(
                &vote,
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("Vote preimage must succeed");
            for i in 0..self.validators.len() {
                let sk = &self.bls_keys[i].0;
                let partial =
                    boule_core::crypto::sig_scheme::BlsAggregated::sign_partial(sk, &preimg)
                        .expect("BLS partial signing must not fail");
                qc.add_bls_partial(i, partial);
            }
            qc
        }
    }

    impl ReplicaSet {
        /// Wrap a `ConsensusMsg` from `source` in the corresponding
        /// `Signed<_>` envelope and promote it to the matching
        /// `Event` kind. Signatures aren't verified by the safety
        /// core, so we stamp a zero sig — but on BLS chains we
        /// *do* attach a real BLS partial under `source`'s BLS
        /// key, because `add_bls_partial` panics on bad bytes
        /// (see `BlsAggregated::add_partial` in
        /// `boule_core::crypto::sig_scheme`).
        fn event_from_msg(&self, source: NodeId, msg: ConsensusMsg) -> Event {
            let sig = [0u8; 64];
            match msg {
                ConsensusMsg::Proposal(payload) => {
                    Event::ProposalReceived(crate::dispatch::Verified::unchecked(Signed {
                        payload,
                        signer: source,
                        sig,
                    }))
                }
                ConsensusMsg::Vote(payload) => {
                    let source_vid = crate::validator_set::ValidatorId::from_genesis_pubkey(source);
                    let signer_idx = self
                        .validators
                        .index_of(&source_vid)
                        .expect("event_from_msg called with unknown source NodeId");
                    let bls_partial = self.bls_partial_for_vote(signer_idx, &payload);
                    Event::VoteReceived(VoteVariant::from_optional_partial(
                        crate::dispatch::Verified::unchecked(Signed {
                            payload,
                            signer: source,
                            sig,
                        }),
                        bls_partial,
                    ))
                }
                ConsensusMsg::NewView(payload) => {
                    Event::NewViewReceived(crate::dispatch::Verified::unchecked(Signed {
                        payload,
                        signer: source,
                        sig,
                    }))
                }
            }
        }
    }

    // ── Hand-built deterministic driver ────────────────────────

    /// Build a view-1 kickoff proposal rooted on `genesis` with a
    /// synthesized genesis QC as its justify. The leader of view
    /// 1 (`validators[1]`) would normally produce this after
    /// collecting view-0 NewView messages; we bypass bootstrap
    /// by injecting it as an incoming event.
    fn kickoff_proposal(replicas: &ReplicaSet) -> Signed<Proposal> {
        let genesis_qc = replicas.synth_qc(View(0), replicas.genesis.hash());
        let leader_idx = 1 % replicas.len();
        let leader_nid = replicas.validators.get(leader_idx).unwrap().into_node_id();
        let builder = TestBlockBuilder {
            proposer: leader_nid,
        };
        let block_v1 = builder
            .build(&replicas.genesis, View(1), &genesis_qc, &HashMap::new(), 0)
            .expect("test builder must not fail");
        Signed {
            payload: Proposal {
                block: block_v1,
                justify: genesis_qc,
            },
            signer: leader_nid,
            sig: [0u8; 64],
        }
    }

    /// The safety invariant this whole milestone is built around:
    /// for every pair of replicas `(i, j)` and every height `h`,
    /// if both committed a block at height `h`, the blocks agree
    /// byte-for-byte. Panics with a precise `(i, j, h)` message
    /// on the first violation so a failed proptest shrinks to a
    /// single offending height rather than a diff of two maps.
    ///
    /// "Commit at the same height" is the cross-replica analog of
    /// HotStuff's `Theorem 2` ("conflicting nodes cannot both be
    /// committed"): at any fixed height, there must be exactly
    /// one committed block across the honest set.
    pub(crate) fn assert_no_conflicting_commits(replicas: &ReplicaSet) {
        let n = replicas.len();
        for i in 0..n {
            for j in (i + 1)..n {
                for (height, block_i) in &replicas.commits[i] {
                    let Some(block_j) = replicas.commits[j].get(height) else {
                        continue;
                    };
                    assert_eq!(
                        block_i.hash(),
                        block_j.hash(),
                        "replicas {i} and {j} committed conflicting blocks at \
                             height {height}: hash {:?} vs {:?}",
                        block_i.hash(),
                        block_j.hash(),
                    );
                }
            }
        }
    }

    #[test]
    fn four_honest_replicas_agree_on_a_commit() {
        // Smoke test: n = 3f + 1 for f = 1. Kick off view 1 by
        // broadcasting a hand-crafted proposal to every replica,
        // run the bus for a bounded number of rounds, and assert
        // (a) at least one commit per replica, (b) no pair of
        // replicas has conflicting commits.
        //
        // This is the minimum proof that the bus correctly
        // relays `Broadcast(Vote)` and `Broadcast(Proposal)`
        // between cores, and that the invariant we'll actually
        // check against Byzantine inputs in PR β holds trivially
        // for honest inputs.
        let mut replicas = ReplicaSet::new(4);
        let kickoff = kickoff_proposal(&replicas);
        replicas.inject_all(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(kickoff),
        ));

        // Honest HotStuff keeps going indefinitely; bound the
        // run and inspect commits afterwards. 64 rounds is
        // comfortably past the ~8 rounds to the first commit on
        // this schedule.
        replicas.run_bounded(64);

        // Every replica committed at least one block.
        for i in 0..replicas.len() {
            assert!(
                !replicas.commits[i].is_empty(),
                "replica {i} recorded no commits: did the bus hang?",
            );
        }

        assert_no_conflicting_commits(&replicas);

        // The first committed block (lowest height) must match
        // across replicas.
        let (&h0, b0) = replicas.commits[0].iter().next().unwrap();
        for i in 1..replicas.len() {
            let other = replicas.commits[i]
                .get(&h0)
                .unwrap_or_else(|| panic!("replica {i} missing commit at height {h0}"));
            assert_eq!(
                other.hash(),
                b0.hash(),
                "replica {i}'s block at height {h0} diverges from replica 0's",
            );
        }
    }

    // ── E3 (honest-only slice) ──────────────────────────────────
    //
    // Randomize the delivery schedule: at each step, pick which
    // replica gets to drain one event from its inbox. Unlike the
    // strict round-robin above, this exercises arbitrary
    // interleavings of inter-replica messages — including
    // pathological skews like "replica 0 drains ten events
    // before anyone else delivers once".
    //
    // With no Byzantine replicas the invariant holds trivially
    // (safety rests on the cores themselves, which we've already
    // unit-tested to death). The point of this proptest is to
    // stress the harness: if `apply_actions` has an ordering
    // bug, or if the cores carry implicit schedule-dependent
    // state, the invariant will fail under some seed. PR β
    // extends this with Byzantine event generators; this PR
    // ships the plumbing first so that β's failures are
    // unambiguously Byzantine-driven rather than harness-driven.

    use proptest::prelude::*;

    /// Shared body for `bls_honest_replicas_never_conflict_under_random_delivery`
    /// (#354 step 3). Builds a fresh BLS `ReplicaSet`, kicks off view 1,
    /// then drains the random delivery schedule and asserts the
    /// no-conflicting-commits invariant.
    fn run_honest_replicas_never_conflict(schedule: Vec<usize>) {
        let mut replicas = ReplicaSet::new_with_byzantine(4, 0);
        let kickoff = kickoff_proposal(&replicas);
        replicas.inject_all(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(kickoff),
        ));

        for replica in schedule {
            replicas.deliver_one(replica);
        }

        assert_no_conflicting_commits(&replicas);
    }

    proptest! {
        #[test]
        fn bls_honest_replicas_never_conflict_under_random_delivery(
            schedule in proptest::collection::vec(0usize..4, 1..=200),
        ) {
            run_honest_replicas_never_conflict(schedule);
        }
    }

    // ── β2: Byzantine vote strategy ─────────────────────────────
    //
    // A single enum carries both honest-delivery schedule steps
    // and Byzantine vote injections. Keeping them in one
    // `Vec<ByzantineVoteStep>` (rather than two parallel
    // sequences) lets proptest's shrinker trim the trace
    // uniformly — a failure shrinks to the minimal prefix that
    // triggers the invariant violation.
    //
    // "Byzantine vote" covers double-voting (same Byzantine
    // signer, different (view, block_hash)), voting for forked
    // / phantom blocks (block_hash chosen arbitrarily, likely
    // not in any honest `pending_blocks`), and stale/out-of-
    // order delivery (view bounded low, injected at arbitrary
    // schedule positions). Those three Byzantine attack vectors
    // collapse to "arbitrary signed vote from a Byzantine id".

    #[derive(Debug, Clone)]
    enum ByzantineVoteStep {
        Deliver(usize),
        InjectVote {
            view: View,
            block_hash: BlockHash,
            target_honest: usize,
        },
    }

    fn byzantine_vote_step_strategy(n_honest: usize) -> impl Strategy<Value = ByzantineVoteStep> {
        prop_oneof![
            // Honest deliveries: heavier weight so the run
            // actually makes progress between injections. 3:1
            // is a coarse dial; if Byzantine rates ever need
            // tuning the only effect is test latency vs.
            // strategy coverage.
            3 => (0..n_honest).prop_map(ByzantineVoteStep::Deliver),
            1 => (0u64..8, prop::array::uniform32(any::<u8>()), 0..n_honest).prop_map(
                |(view, block_hash, target_honest)| ByzantineVoteStep::InjectVote {
                    view: View(view),
                    block_hash,
                    target_honest,
                },
            ),
        ]
    }

    /// Shared body for the Byzantine-vote proptest across schemes.
    /// On BLS chains the Byzantine vote carries a real BLS partial
    /// signed under the Byzantine validator's BLS key — without it
    /// the safety core's `on_vote_received` would silently drop the
    /// vote (defense-in-depth from #354 step 2), erasing the test's
    /// adversarial signal.
    fn run_byzantine_votes_never_break_safety(schedule: Vec<ByzantineVoteStep>) {
        let mut replicas = ReplicaSet::new_with_byzantine(4, 1);
        let byz_nid = replicas.byzantine_nids()[0];
        let byz_vid = crate::validator_set::ValidatorId::from_genesis_pubkey(byz_nid);
        let byz_idx = replicas
            .validators
            .index_of(&byz_vid)
            .expect("byzantine NodeId must appear in validator set");
        let kickoff = kickoff_proposal(&replicas);
        replicas.inject_all(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(kickoff),
        ));

        for step in schedule {
            match step {
                ByzantineVoteStep::Deliver(i) => {
                    replicas.deliver_one(i);
                }
                ByzantineVoteStep::InjectVote {
                    view,
                    block_hash,
                    target_honest,
                } => {
                    let vote_payload = Vote { view, block_hash };
                    let bls_partial = replicas.bls_partial_for_vote(byz_idx, &vote_payload);
                    let vote = Signed {
                        payload: vote_payload,
                        signer: byz_nid,
                        sig: [0u8; 64],
                    };
                    replicas.inject(
                        target_honest,
                        Event::VoteReceived(VoteVariant::from_optional_partial(
                            crate::dispatch::Verified::unchecked(vote),
                            bls_partial,
                        )),
                    );
                }
            }
        }

        assert_no_conflicting_commits(&replicas);
    }

    proptest! {
        #[test]
        fn bls_byzantine_votes_never_break_safety(
            schedule in proptest::collection::vec(
                byzantine_vote_step_strategy(3),
                1..=200,
            ),
        ) {
            run_byzantine_votes_never_break_safety(schedule);
        }
    }

    // ── β3: Byzantine proposal strategy ─────────────────────────
    //
    // A Byzantine proposer can craft a `Signed<Proposal>` with
    // any block contents and any justify QC. Because the safety
    // core explicitly doesn't verify QC signatures (that's the
    // integration layer's job per #24), this covers the
    // "proposal with bogus justify" attack from #93's
    // verification list: the core trusts the `justify` view
    // field but can only vote on a proposal that passes
    // `safe_to_vote`, so a fake justify.view attempting to hit
    // the liveness rule needs the block to either not extend
    // the lock or to be fresh-view relative to it. Either way,
    // safety of committed blocks must hold.

    #[derive(Debug, Clone)]
    enum ByzantineProposalStep {
        Deliver(usize),
        InjectProposal {
            parent_hash: BlockHash,
            view: View,
            justify_view: View,
            justify_block_hash: BlockHash,
            target_honest: usize,
        },
    }

    fn byzantine_proposal_step_strategy(
        n_honest: usize,
    ) -> impl Strategy<Value = ByzantineProposalStep> {
        prop_oneof![
            3 => (0..n_honest).prop_map(ByzantineProposalStep::Deliver),
            1 => (
                prop::array::uniform32(any::<u8>()),
                0u64..10,
                0u64..10,
                prop::array::uniform32(any::<u8>()),
                0..n_honest,
            )
                .prop_map(
                    |(parent_hash, view, justify_view, justify_block_hash, target_honest)| {
                        ByzantineProposalStep::InjectProposal {
                            parent_hash,
                            view: View(view),
                            justify_view: View(justify_view),
                            justify_block_hash,
                            target_honest,
                        }
                    },
                ),
        ]
    }

    /// Assemble a `Signed<Proposal>` from a Byzantine adversary:
    /// arbitrary block over `parent_hash` at `view`, arbitrary
    /// justify-QC with the claimed signatures the safety core
    /// won't actually verify. Scheme-aware so the embedded QC
    /// matches the chain's flavor — `synth_qc` builds a real BLS
    /// aggregate on BLS chains, mirroring what the integration
    /// layer would feed to the safety core.
    fn byzantine_proposal(
        replicas: &ReplicaSet,
        byz_nid: NodeId,
        parent_hash: BlockHash,
        view: View,
        justify_view: View,
        justify_block_hash: BlockHash,
    ) -> Signed<Proposal> {
        let header = BlockHeader {
            parent_hash,
            height: Height(view.0),
            view,
            proposer: byz_nid,
            state_commitment: [view.0 as u8; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: 0,
        };
        let block = Block {
            header,
            commands: Vec::new(),
        };
        let justify = replicas.synth_qc(justify_view, justify_block_hash);
        Signed {
            payload: Proposal { block, justify },
            signer: byz_nid,
            sig: [0u8; 64],
        }
    }

    /// Shared body for the Byzantine-proposal proptest.
    fn run_byzantine_proposals_never_break_safety(schedule: Vec<ByzantineProposalStep>) {
        let mut replicas = ReplicaSet::new_with_byzantine(4, 1);
        let byz_nid = replicas.byzantine_nids()[0];
        let kickoff = kickoff_proposal(&replicas);
        replicas.inject_all(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(kickoff),
        ));

        for step in schedule {
            match step {
                ByzantineProposalStep::Deliver(i) => {
                    replicas.deliver_one(i);
                }
                ByzantineProposalStep::InjectProposal {
                    parent_hash,
                    view,
                    justify_view,
                    justify_block_hash,
                    target_honest,
                } => {
                    let proposal = byzantine_proposal(
                        &replicas,
                        byz_nid,
                        parent_hash,
                        view,
                        justify_view,
                        justify_block_hash,
                    );
                    replicas.inject(
                        target_honest,
                        Event::ProposalReceived(crate::dispatch::Verified::unchecked(proposal)),
                    );
                }
            }
        }

        assert_no_conflicting_commits(&replicas);
    }

    // BLS pairing-check + per-validator partial signing pushes the
    // per-case cost up, so the schedule bound and case count are
    // trimmed to keep a single test under the 15-s wall-clock budget
    // on the default GitHub-hosted runner.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 96,
            .. ProptestConfig::default()
        })]

        #[test]
        fn bls_byzantine_proposals_never_break_safety(
            schedule in proptest::collection::vec(
                byzantine_proposal_step_strategy(3),
                1..=120,
            ),
        ) {
            run_byzantine_proposals_never_break_safety(schedule);
        }
    }

    // ── β4: Combined Byzantine strategies ───────────────────────
    //
    // Umbrella proptest mixing honest delivery with all three
    // Byzantine event kinds — vote, proposal, NewView —
    // interleaved arbitrarily. The individual strategies above
    // stay: each one shrinks to a smaller failing seed if a
    // single attack vector is the culprit. This mixed test
    // catches interactions between them that the standalone
    // strategies can't reach (e.g., a bogus NewView that bumps
    // `high_qc` to a high view, followed by a Byzantine
    // proposal whose justify lines up with that high view to
    // trigger the liveness rule).

    #[derive(Debug, Clone)]
    enum MixedStep {
        Deliver(usize),
        InjectVote {
            view: View,
            block_hash: BlockHash,
            target_honest: usize,
        },
        InjectProposal {
            parent_hash: BlockHash,
            view: View,
            justify_view: View,
            justify_block_hash: BlockHash,
            target_honest: usize,
        },
        InjectNewView {
            qc_view: View,
            qc_block_hash: BlockHash,
            target_honest: usize,
        },
    }

    fn mixed_step_strategy(n_honest: usize) -> impl Strategy<Value = MixedStep> {
        prop_oneof![
            // 6:1:1:1 honest:byz_vote:byz_proposal:byz_newview.
            // Heavy honest weight keeps the trace making
            // progress; light Byzantine weight leaves room for
            // rare-but-nasty interaction patterns to surface.
            6 => (0..n_honest).prop_map(MixedStep::Deliver),
            1 => (0u64..10, prop::array::uniform32(any::<u8>()), 0..n_honest).prop_map(
                |(view, block_hash, target_honest)| MixedStep::InjectVote {
                    view: View(view),
                    block_hash,
                    target_honest,
                },
            ),
            1 => (
                prop::array::uniform32(any::<u8>()),
                0u64..10,
                0u64..10,
                prop::array::uniform32(any::<u8>()),
                0..n_honest,
            )
                .prop_map(
                    |(parent_hash, view, justify_view, justify_block_hash, target_honest)| {
                        MixedStep::InjectProposal {
                            parent_hash,
                            view: View(view),
                            justify_view: View(justify_view),
                            justify_block_hash,
                            target_honest,
                        }
                    },
                ),
            1 => (0u64..10, prop::array::uniform32(any::<u8>()), 0..n_honest).prop_map(
                |(qc_view, qc_block_hash, target_honest)| MixedStep::InjectNewView {
                    qc_view: View(qc_view),
                    qc_block_hash,
                    target_honest,
                },
            ),
        ]
    }

    /// Shared body for the mixed-Byzantine-events proptest across
    /// schemes. Builds Byzantine vote / proposal / NewView events
    /// using the scheme-aware helpers (`bls_partial_for_vote`,
    /// `synth_qc`) so the BLS branch sees real partials and real
    /// BLS QCs, mirroring what an integration-layer-fed safety
    /// core would receive.
    fn run_mixed_byzantine_events_never_break_safety(schedule: Vec<MixedStep>) {
        let mut replicas = ReplicaSet::new_with_byzantine(4, 1);
        let byz_nid = replicas.byzantine_nids()[0];
        let byz_vid = crate::validator_set::ValidatorId::from_genesis_pubkey(byz_nid);
        let byz_idx = replicas
            .validators
            .index_of(&byz_vid)
            .expect("byzantine NodeId must appear in validator set");
        let kickoff = kickoff_proposal(&replicas);
        replicas.inject_all(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(kickoff),
        ));

        for step in schedule {
            match step {
                MixedStep::Deliver(i) => {
                    replicas.deliver_one(i);
                }
                MixedStep::InjectVote {
                    view,
                    block_hash,
                    target_honest,
                } => {
                    let vote_payload = Vote { view, block_hash };
                    let bls_partial = replicas.bls_partial_for_vote(byz_idx, &vote_payload);
                    let vote = Signed {
                        payload: vote_payload,
                        signer: byz_nid,
                        sig: [0u8; 64],
                    };
                    replicas.inject(
                        target_honest,
                        Event::VoteReceived(VoteVariant::from_optional_partial(
                            crate::dispatch::Verified::unchecked(vote),
                            bls_partial,
                        )),
                    );
                }
                MixedStep::InjectProposal {
                    parent_hash,
                    view,
                    justify_view,
                    justify_block_hash,
                    target_honest,
                } => {
                    let proposal = byzantine_proposal(
                        &replicas,
                        byz_nid,
                        parent_hash,
                        view,
                        justify_view,
                        justify_block_hash,
                    );
                    replicas.inject(
                        target_honest,
                        Event::ProposalReceived(crate::dispatch::Verified::unchecked(proposal)),
                    );
                }
                MixedStep::InjectNewView {
                    qc_view,
                    qc_block_hash,
                    target_honest,
                } => {
                    let qc = replicas.synth_qc(qc_view, qc_block_hash);
                    let nv = Signed {
                        payload: NewView { high_qc: qc },
                        signer: byz_nid,
                        sig: [0u8; 64],
                    };
                    replicas.inject(
                        target_honest,
                        Event::NewViewReceived(crate::dispatch::Verified::unchecked(nv)),
                    );
                }
            }
        }

        assert_no_conflicting_commits(&replicas);
    }

    // BLS pairing-check verification plus per-vote BLS partial
    // signing makes each case meaningfully heavier, so the schedule
    // bound and case count are trimmed to keep a single test under
    // the 15-s wall-clock budget on the default GitHub-hosted runner.
    // The honest+Byzantine attack-vector coverage is unchanged: every
    // strategy in `mixed_step_strategy` is still sampled, just with
    // a smaller envelope.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            .. ProptestConfig::default()
        })]

        #[test]
        fn bls_mixed_byzantine_events_never_break_safety(
            schedule in proptest::collection::vec(mixed_step_strategy(3), 1..=150),
        ) {
            run_mixed_byzantine_events_never_break_safety(schedule);
        }
    }
}

// ── Bounded-cache eviction (#135) ──────────────────────────────────
//
// The four caches the safety core owns directly are
// `vote_bucket` and `parked_proposals` (the integration layer's
// `timeout_buckets` lives in `consensus::node` and is tested
// there). `pending_blocks` lives on `HotStuffState` but its cap
// and counter are seeded by `HotStuffCore::with_limits`, so its
// eviction tests live here too. Each cache is exercised at two
// scales: insert exactly 2× its cap, and a policy-specific
// assertion (lowest-view victim, gc_below sweep, high_qc chain
// protection) that pins down which entries survive.

mod eviction {
    use super::*;
    use crate::limits::{CacheEvictionCounters, CacheLimits};

    /// Build a tight-cap core. Validators are still the canonical
    /// four; cap fields are passed as a literal so each test can
    /// scale them independently.
    fn make_core_with_limits(self_byte: u8, limits: CacheLimits) -> HotStuffCore {
        let state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        HotStuffCore::with_limits(
            nid(self_byte),
            state,
            limits,
            CacheEvictionCounters::default(),
        )
    }

    fn cap_only_vote_bucket(cap: usize) -> CacheLimits {
        let mut l = CacheLimits::unbounded_for_tests();
        l.vote_bucket_capacity = cap;
        l
    }

    fn cap_only_parked(cap: usize) -> CacheLimits {
        let mut l = CacheLimits::unbounded_for_tests();
        l.parked_proposals_capacity = cap;
        l
    }

    fn cap_only_pending_blocks(cap: usize) -> CacheLimits {
        let mut l = CacheLimits::unbounded_for_tests();
        l.pending_blocks_capacity = cap;
        l
    }

    // ── vote_bucket ────────────────────────────────────────────────

    /// Insert 2× the cap of distinct `(view, block_hash)` votes —
    /// the cap holds and the counter records every drop.
    #[test]
    fn vote_bucket_inserting_twice_the_cap_evicts_to_cap() {
        let cap = 4usize;
        let mut core = make_core_with_limits(1, cap_only_vote_bucket(cap));
        // Distinct (view, block_hash) tuples so each vote lands
        // in its own bucket. We use the first three validators
        // as signers; the fourth is `self_id` so its votes would
        // be ignored as our own. Each tuple's signer is rotated
        // so no two votes collide on the same (view, block_hash,
        // signer) idempotency key.
        let signers = [nid(2), nid(3), nid(4)];
        for i in 0..(2 * cap) {
            let view = View(i as u64);
            let block_hash: BlockHash = [i as u8 + 1; 32];
            let signer = signers[i % signers.len()];
            let signed = signed_vote(view, block_hash, signer);
            core.step(Event::VoteReceived(bls_vote_from_signed(signed)));
            assert!(
                core.vote_bucket.len() <= cap,
                "vote_bucket grew past cap after insert {i}: len={}",
                core.vote_bucket.len(),
            );
        }
        // Final state: exactly cap entries, and the counter
        // recorded `cap` evictions (one per insert past the cap).
        assert_eq!(core.vote_bucket.len(), cap);
        assert_eq!(core.eviction_counters().vote_bucket(), cap as u64);
        // Lowest-view-first eviction: the surviving views are
        // the cap most recent ones (cap..2*cap-1).
        let mut surviving_views: Vec<View> = core.vote_bucket.keys().map(|(v, _)| *v).collect();
        surviving_views.sort();
        let expected: Vec<View> = (cap as u64..(2 * cap) as u64).map(View).collect();
        assert_eq!(surviving_views, expected);
    }

    /// `gc_below` — driving `PacemakerAdvance(N)` drops every
    /// `vote_bucket` entry with `view < N` immediately.
    #[test]
    fn vote_bucket_pacemaker_advance_evicts_below_gc_floor() {
        // Loose cap — exercise only the gc_below path.
        let mut core = make_core_with_limits(1, cap_only_vote_bucket(1024));
        let signer = nid(2);
        for view in 0..10 {
            let block_hash: BlockHash = [view as u8 + 1; 32];
            core.step(Event::VoteReceived(bls_vote(view, block_hash, signer)));
        }
        assert_eq!(core.vote_bucket.len(), 10);
        assert_eq!(core.eviction_counters().vote_bucket(), 0);

        // Advance the pacemaker to view 7 — buckets for views
        // 0..7 must be dropped; 7..10 survive.
        let _ = core.step(Event::PacemakerAdvance(View(7)));
        assert_eq!(core.vote_bucket.len(), 3);
        assert_eq!(core.eviction_counters().vote_bucket(), 7);
        let mut surviving: Vec<View> = core.vote_bucket.keys().map(|(v, _)| *v).collect();
        surviving.sort();
        assert_eq!(surviving, vec![View(7), View(8), View(9)]);
    }

    /// Repeat votes for the same `(view, block_hash)` from
    /// distinct signers must NOT trigger eviction — the cap only
    /// trims genuinely-new buckets.
    #[test]
    fn vote_bucket_repeat_inserts_for_same_key_do_not_evict() {
        let cap = 2usize;
        let mut core = make_core_with_limits(1, cap_only_vote_bucket(cap));
        // Fill to cap with two distinct tuples first.
        let _ = core.step(Event::VoteReceived(bls_vote(0, [1; 32], nid(2))));
        let _ = core.step(Event::VoteReceived(bls_vote(1, [2; 32], nid(2))));
        assert_eq!(core.vote_bucket.len(), cap);
        assert_eq!(core.eviction_counters().vote_bucket(), 0);

        // Three more votes on the SAME (view, block_hash) tuples
        // from different signers — bucket-update path, no growth.
        let _ = core.step(Event::VoteReceived(bls_vote(0, [1; 32], nid(3))));
        let _ = core.step(Event::VoteReceived(bls_vote(0, [1; 32], nid(4))));
        let _ = core.step(Event::VoteReceived(bls_vote(1, [2; 32], nid(3))));
        assert_eq!(core.vote_bucket.len(), cap);
        assert_eq!(core.eviction_counters().vote_bucket(), 0);
    }

    // ── parked_proposals ──────────────────────────────────────────

    /// Insert 2× the cap of distinct orphan proposals — cap
    /// holds, counter records every drop, and the lowest-view
    /// proposals are the ones evicted.
    #[test]
    fn parked_proposals_inserting_twice_the_cap_evicts_to_cap() {
        let cap = 3usize;
        let mut core = make_core_with_limits(1, cap_only_parked(cap));
        let sender = nid(2);
        let orphan_parent: BlockHash = [0xFF; 32];
        for i in 0..(2 * cap) {
            let view = View(i as u64);
            // Distinct view per child guarantees a distinct
            // child block hash AND lets us assert which views
            // survive eviction.
            let mut child = orphan_child(orphan_parent, view, nid(3));
            // Vary state_commitment so even at the same view two
            // children would hash differently — defensive.
            child.header.state_commitment = [i as u8 + 1; 32];
            let dummy = dummy_qc(View(0), core.state().genesis_hash);
            let _ = core.step(Event::ProposalReceived(
                crate::dispatch::Verified::unchecked(signed_proposal(child, dummy, sender)),
            ));
            assert!(
                core.parked_proposals.len() <= cap,
                "parked_proposals grew past cap after insert {i}",
            );
        }
        assert_eq!(core.parked_proposals.len(), cap);
        assert_eq!(core.eviction_counters().parked_proposals(), cap as u64);
        // Lowest-view-first eviction: the surviving views are
        // the cap most recent ones (cap..2*cap-1).
        let mut surviving_views: Vec<View> = core
            .parked_proposals
            .values()
            .map(|s| s.payload.block.header.view)
            .collect();
        surviving_views.sort();
        let expected: Vec<View> = (cap as u64..(2 * cap) as u64).map(View).collect();
        assert_eq!(surviving_views, expected);
    }

    /// Re-parking the same `child_hash` (e.g. a duplicate
    /// retransmission) must not grow the map and so must not
    /// trigger eviction.
    #[test]
    fn parked_proposals_idempotent_repark_does_not_evict() {
        let cap = 1usize;
        let mut core = make_core_with_limits(1, cap_only_parked(cap));
        let sender = nid(2);
        let orphan_parent: BlockHash = [0xAA; 32];
        let child = orphan_child(orphan_parent, 1, nid(3));
        let dummy = dummy_qc(View(0), core.state().genesis_hash);

        // Two identical inserts — second is a no-op overwrite.
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(
                child.clone(),
                dummy.clone(),
                sender,
            )),
        ));
        let _ = core.step(Event::ProposalReceived(
            crate::dispatch::Verified::unchecked(signed_proposal(child, dummy, sender)),
        ));
        assert_eq!(core.parked_proposals.len(), 1);
        assert_eq!(core.eviction_counters().parked_proposals(), 0);
    }

    // ── pending_blocks ────────────────────────────────────────────

    /// Insert 2× the cap of pending blocks (above genesis) and
    /// observe the lowest-height entries getting trimmed. Genesis
    /// must always survive — the safety walks rest on it.
    #[test]
    fn pending_blocks_inserting_twice_the_cap_evicts_to_cap_protecting_genesis() {
        // cap = 4 means the map can hold genesis + 3 others.
        let cap = 4usize;
        let mut core = make_core_with_limits(1, cap_only_pending_blocks(cap));
        let genesis_hash = core.state().genesis_hash;

        // No high_qc set so only genesis is "protected"; every
        // other insert is fair game for eviction.
        let chain = chain_from_genesis(
            core.state().pending_blocks.get(&genesis_hash).unwrap(),
            &(1..=(2 * cap as u64)).collect::<Vec<_>>(),
            nid(2),
        );
        for block in &chain {
            core.state.insert_pending(block.clone());
            assert!(
                core.state.pending_blocks.len() <= cap,
                "pending_blocks grew past cap; len={}",
                core.state.pending_blocks.len(),
            );
        }
        assert_eq!(core.state.pending_blocks.len(), cap);
        // Genesis must survive every eviction round.
        assert!(core.state.pending_blocks.contains_key(&genesis_hash));
        // Lowest-height-first eviction: surviving non-genesis
        // entries are the most-recent cap-1 heights of the chain.
        let mut surviving_heights: Vec<u64> = core
            .state
            .pending_blocks
            .values()
            .filter(|b| b.hash() != genesis_hash)
            .map(|b| b.header.height.0)
            .collect();
        surviving_heights.sort();
        let expected_low = (2 * cap as u64) - (cap as u64 - 1) + 1;
        let expected: Vec<u64> = (expected_low..=(2 * cap as u64)).collect();
        assert_eq!(surviving_heights, expected);
        // Counter recorded one drop per evicted block.
        let inserted = chain.len() as u64;
        let surviving_non_genesis = (cap as u64) - 1;
        assert_eq!(
            core.eviction_counters().pending_blocks(),
            inserted - surviving_non_genesis,
        );
    }

    /// The high_qc chain is protected: when the map is at cap,
    /// the safety core picks a non-protected victim rather than
    /// evicting any block reachable from `high_qc.block_hash`
    /// within `PROTECTED_HIGH_QC_DEPTH` parent links. Without
    /// this protection, the two-chain and three-chain walks
    /// would lose their footing under a fork flood.
    #[test]
    fn pending_blocks_high_qc_ancestors_are_protected_from_eviction() {
        // Pick a cap that comfortably holds genesis + the
        // 3-block high_qc chain *and* leaves room for a couple
        // of forks: genesis + 3 chain = 4 protected, plus 2
        // fork slots → cap = 6. Inserting 5 forks then forces
        // eviction, and every eviction must pick a fork (never
        // a protected block).
        let cap = 6usize;
        let mut core = make_core_with_limits(1, cap_only_pending_blocks(cap));
        let genesis_hash = core.state().genesis_hash;
        let genesis = core
            .state()
            .pending_blocks
            .get(&genesis_hash)
            .unwrap()
            .clone();

        // Build a chain genesis -> b1 -> b2 -> b3 at heights 1,2,3
        // and pin high_qc on the tip so the whole chain (plus
        // genesis) sits in the protected set.
        let chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
        for block in &chain {
            core.state.insert_pending(block.clone());
        }
        let tip_hash = chain.last().unwrap().hash();
        core.state.high_qc = Some(VerifiedQc::unchecked(dummy_qc(View(3), tip_hash)));
        assert_eq!(core.state.pending_blocks.len(), 4);
        assert_eq!(core.eviction_counters().pending_blocks(), 0);

        // Insert 5 forks off genesis at height 1. With cap=6, only
        // (cap - 4 protected) = 2 fork slots are free, so forks 3,
        // 4, 5 each evict the previously-inserted lowest-height
        // non-protected entry — i.e. another fork.
        let n_forks = 5usize;
        for i in 0..n_forks {
            let header = crate::replication::block::BlockHeader {
                parent_hash: genesis_hash,
                height: Height(1),
                view: View(100) + View(i as u64),
                proposer: nid(3),
                state_commitment: [0xC0 + i as u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
                timestamp: 0,
            };
            let fork = Block {
                header,
                commands: Vec::new(),
            };
            core.state.insert_pending(fork);
        }

        // Every protected block must still be present.
        assert!(core.state.pending_blocks.contains_key(&genesis_hash));
        for b in &chain {
            assert!(
                core.state.pending_blocks.contains_key(&b.hash()),
                "high_qc chain block at height {} must survive eviction",
                b.header.height,
            );
        }
        // Cap is hard now that protected ≤ cap: total stays ≤ cap.
        assert_eq!(core.state.pending_blocks.len(), cap);
        // Counter incremented once per evicted fork (5 inserted,
        // 2 surviving fork slots → 3 evictions).
        assert_eq!(core.eviction_counters().pending_blocks(), 3);
    }
}
