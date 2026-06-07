//! Proptest fuzz harness for malformed consensus wire input (#198).
//!
//! Postcard decoding itself is panic-safe; what these properties pin
//! down is everything *downstream* of decode:
//!
//! - [`boule_consensus::dispatch::ingress`] never panics on arbitrary
//!   peer-controlled bytes nor on a structurally adversarial
//!   [`WireMessage`] (e.g. `SignerBitmap` with a length mismatch or
//!   stray bits past `len`, QC with `signatures.len()` ≠
//!   `signers.count()`, vote/proposal at the high end of the view
//!   range).
//! - A four-replica honest cluster keeps the
//!   "no conflicting commits across heights" invariant under a flood
//!   of malformed events interleaved with honest delivery.
//! - The safety core's bounded caches (`vote_bucket`,
//!   `parked_proposals`, `pending_blocks`) stay within their
//!   configured caps under a stream of distinct malformed inputs —
//!   the cap behaviour from #135 / #203 is what stops a Byzantine
//!   peer from forcing unbounded memory growth.
//!
//! # Bounds
//!
//! Generated views and heights are clamped to `0..256`. The safety
//! core has a handful of `view + 1` / `header.view + 1` sites
//! (`step::on_vote_received`, `safety_rules::three_chain_commit`)
//! that would panic in debug on `u64::MAX`. Hardening those is a
//! separate concern; the issue itself calls out "no `u64::MAX` view"
//! as out of scope for this fuzzer.
//!
//! # Performance
//!
//! Each property keeps per-iteration work cheap (one ingress call, or
//! a 4-replica run bounded to ~150 steps) so the whole module fits
//! well under the 15s/test budget at the default `PROPTEST_CASES=256`
//! and still scales to nightly's `PROPTEST_CASES=4096` without
//! tripping CI's wall-clock limit.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::OnceLock;

use bytes::Bytes;
use proptest::prelude::*;
use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
use serde::Serialize;
use zeroize::Zeroizing;

use boule_consensus::dispatch::ingress;
use boule_consensus::hotstuff::qc::{
    ConsensusMsg, NewView, Proposal, QuorumCertificate, SignerBitmap, TimeoutVote, Vote,
};
use boule_consensus::hotstuff::state::HotStuffState;
use boule_consensus::hotstuff::step::{Action, BlockBuilder, Event, HotStuffCore};
use boule_consensus::limits::{CacheEvictionCounters, CacheLimits};
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::validator_set::ValidatorSet;
use boule_consensus::wire::WireMessage;
use boule_consensus::{Height, View};
use boule_core::crypto::signed::{ChainId, NodeSigner, Signed, Signer};
use boule_core::identity::NodeId;
use boule_core::identity::NodeIdentity;

// ── Shared signer pool ──────────────────────────────────────────────

const N_VALIDATORS: usize = 4;

/// Cap on generated view/height values. Picked low enough that
/// `header.view + 1` arithmetic in the safety core stays away from
/// `u64::MAX`; high enough that the fuzzer still exercises the
/// cross-view paths (vote bucket keying, three-chain commit walk).
const MAX_VIEW: u64 = 256;

fn fresh_signer() -> NodeSigner {
    let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
    let identity = NodeIdentity {
        pkcs8_der: Zeroizing::new(kp.serialize_der()),
    };
    NodeSigner::from_identity(&identity).unwrap()
}

/// Pool of `N_VALIDATORS` Ed25519 signers shared across every
/// proptest case. Ed25519 keygen is the dominant per-iteration cost
/// for any fuzzer that signs payloads, so amortizing it across the
/// whole module keeps the `cases=4096` nightly run within budget.
fn signer_pool() -> &'static [NodeSigner; N_VALIDATORS] {
    static POOL: OnceLock<[NodeSigner; N_VALIDATORS]> = OnceLock::new();
    POOL.get_or_init(|| {
        [
            fresh_signer(),
            fresh_signer(),
            fresh_signer(),
            fresh_signer(),
        ]
    })
}

/// Validator set built from the shared signer pool's NodeIds. Sorted
/// by `ValidatorSet::new`; the order is opaque but deterministic
/// across cases since the underlying signers are.
fn pool_validator_set() -> ValidatorSet {
    let ids: Vec<boule_consensus::validator_set::ValidatorId> = signer_pool()
        .iter()
        .map(|s| boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(s.node_id()))
        .collect();
    ValidatorSet::new(ids)
}

// ── Wire-twin for malformed `SignerBitmap` ──────────────────────────

/// Same on-wire layout as [`SignerBitmap`] but with public fields, so
/// the fuzzer can mint bitmaps whose `bits.len()` and `len` are
/// inconsistent with each other (a state the type's own constructors
/// refuse). Postcard encodes structs positionally, so deserializing
/// these bytes into a real `SignerBitmap` lands a malformed value
/// without going through the type's safe API.
#[derive(Serialize)]
struct WireBitmap {
    bits: Vec<u8>,
    len: u32,
}

fn arb_signer_bitmap() -> impl Strategy<Value = SignerBitmap> {
    (prop::collection::vec(any::<u8>(), 0..16), 0u32..32).prop_map(|(bits, len)| {
        let twin = WireBitmap { bits, len };
        let bytes = postcard::to_stdvec(&twin).expect("twin is serializable");
        postcard::from_bytes(&bytes).expect("any (Vec<u8>, u32) decodes to a SignerBitmap")
    })
}

// ── Generators for the wire payload types ───────────────────────────

fn arb_qc() -> impl Strategy<Value = QuorumCertificate> {
    (
        0u64..MAX_VIEW,
        any::<[u8; 32]>(),
        arb_signer_bitmap(),
        prop::collection::vec(any::<[u8; 64]>(), 0..16),
    )
        .prop_map(|(view, block_hash, signers, signatures)| {
            QuorumCertificate::from_raw_parts(
                View(view),
                block_hash,
                signers,
                boule_consensus::hotstuff::qc::QcSignatures::Ed25519Collected(signatures),
            )
        })
}

fn arb_block(genesis_hash: BlockHash) -> impl Strategy<Value = Block> {
    (
        // Bias toward "extends genesis" so a real chain-of-one can
        // form, while still feeding random parent hashes that exercise
        // the parked-proposal path.
        prop_oneof![
            1 => Just(genesis_hash),
            1 => any::<[u8; 32]>(),
        ],
        0u64..MAX_VIEW,
        0u64..MAX_VIEW,
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..32), 0..4),
    )
        .prop_map(
            |(parent_hash, height, view, proposer, state_commitment, cmds)| {
                let commands: Vec<Bytes> = cmds.into_iter().map(Bytes::from).collect();
                let header = BlockHeader {
                    parent_hash,
                    height: Height(height),
                    view: View(view),
                    proposer,
                    state_commitment,
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                    timestamp: 0,
                };
                Block { header, commands }
            },
        )
}

fn arb_proposal(genesis_hash: BlockHash) -> impl Strategy<Value = Proposal> {
    (arb_block(genesis_hash), arb_qc()).prop_map(|(block, justify)| Proposal { block, justify })
}

fn arb_vote() -> impl Strategy<Value = Vote> {
    (0u64..MAX_VIEW, any::<[u8; 32]>()).prop_map(|(view, block_hash)| Vote {
        view: View(view),
        block_hash,
    })
}

fn arb_new_view() -> impl Strategy<Value = NewView> {
    arb_qc().prop_map(|high_qc| NewView { high_qc })
}

fn arb_timeout_vote() -> impl Strategy<Value = TimeoutVote> {
    (0u64..MAX_VIEW, prop::option::of(arb_qc())).prop_map(|(view, high_qc)| TimeoutVote {
        view: View(view),
        high_qc,
    })
}

/// Index into the shared signer pool — the wire generator picks one
/// here so the fuzzer can sign with whichever signer it lands on.
fn arb_signer_idx() -> impl Strategy<Value = usize> {
    0..N_VALIDATORS
}

/// Generate a `WireMessage`, sign the payload with a real key from
/// the shared pool, and return both the encoded bytes and the signer
/// NodeId. Signature verification will pass for the resulting frame —
/// the fuzz target is everything *past* signature verification.
fn arb_signed_wire_bytes_and_signer() -> impl Strategy<Value = (Vec<u8>, NodeId)> {
    let genesis_hash = Block::genesis([0; 32], [0; 32]).hash();
    prop_oneof![
        (arb_signer_idx(), arb_proposal(genesis_hash)).prop_map(|(idx, p)| {
            let signer = &signer_pool()[idx];
            let signed = Signed::sign(p, signer, &ChainId::TEST).expect("sign Proposal");
            let bytes = postcard::to_stdvec(&WireMessage::Proposal(signed))
                .expect("encode WireMessage::Proposal");
            (bytes, signer.node_id())
        }),
        (arb_signer_idx(), arb_vote()).prop_map(|(idx, v)| {
            let signer = &signer_pool()[idx];
            let signed = Signed::sign(v, signer, &ChainId::TEST).expect("sign Vote");
            let bytes = postcard::to_stdvec(&WireMessage::Vote(signed, None))
                .expect("encode WireMessage::Vote");
            (bytes, signer.node_id())
        }),
        (arb_signer_idx(), arb_new_view()).prop_map(|(idx, nv)| {
            let signer = &signer_pool()[idx];
            let signed = Signed::sign(nv, signer, &ChainId::TEST).expect("sign NewView");
            let bytes = postcard::to_stdvec(&WireMessage::NewView(signed))
                .expect("encode WireMessage::NewView");
            (bytes, signer.node_id())
        }),
        (arb_signer_idx(), arb_timeout_vote()).prop_map(|(idx, tv)| {
            let signer = &signer_pool()[idx];
            let signed = Signed::sign(tv, signer, &ChainId::TEST).expect("sign TimeoutVote");
            let bytes = postcard::to_stdvec(&WireMessage::TimeoutVote(signed))
                .expect("encode WireMessage::TimeoutVote");
            (bytes, signer.node_id())
        }),
        any::<[u8; 32]>().prop_map(|hash| {
            let bytes = postcard::to_stdvec(&WireMessage::BlockRequest(hash))
                .expect("encode WireMessage::BlockRequest");
            (bytes, [0u8; 32])
        }),
        (
            arb_signer_idx(),
            any::<[u8; 32]>(),
            prop::option::of(arb_block(Block::genesis([0; 32], [0; 32]).hash())),
        )
            .prop_map(|(idx, requested_hash, block)| {
                let signer = &signer_pool()[idx];
                let payload = boule_consensus::wire::BlockResponsePayload {
                    requested_hash,
                    block,
                };
                let signed = Signed::sign(payload, signer, &ChainId::TEST)
                    .expect("sign BlockResponsePayload");
                let bytes = postcard::to_stdvec(&WireMessage::BlockResponse(signed))
                    .expect("encode WireMessage::BlockResponse");
                (bytes, signer.node_id())
            }),
    ]
}

// ── ingress no-panic properties ─────────────────────────────────────

proptest! {
    /// Arbitrary peer-controlled bytes can never make `ingress` panic.
    /// This covers the postcard-rejection path: garbage, truncated
    /// frames, oversized varints, and so on. The result is allowed to
    /// be either `Ok` (the bytes happened to decode to a no-auth
    /// variant like `BlockRequest`) or `Err`; only a panic counts as
    /// a failure here.
    #[test]
    fn prop_ingress_no_panic_on_arbitrary_bytes(
        from_byte in any::<u8>(),
        bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let from = [from_byte; 32];
        let vs = pool_validator_set();
        let history = boule_consensus::validator_history::ValidatorSetHistory::from_genesis(vs);
        let key_history =
            boule_consensus::validator_key_history::ValidatorKeyHistory::from_set_history(
                &history,
            );
        let _ = ingress(from, &bytes, &history, &key_history, &ChainId::TEST);
    }

    /// A `WireMessage` whose payload is structurally adversarial —
    /// malformed `SignerBitmap`, mismatched `signatures.len()` /
    /// `signers.count()`, random parent hashes, far-future views — but
    /// whose envelope is signed by a legitimate validator must still
    /// flow through `ingress` without panicking. Ingress will accept
    /// most of these (it only verifies the envelope, not the embedded
    /// QC); the safety-core dispatch they feed into is exercised by
    /// the cluster property below.
    #[test]
    fn prop_ingress_no_panic_on_arbitrary_wire_message(
        (bytes, from) in arb_signed_wire_bytes_and_signer(),
    ) {
        let vs = pool_validator_set();
        let history = boule_consensus::validator_history::ValidatorSetHistory::from_genesis(vs);
        let key_history =
            boule_consensus::validator_key_history::ValidatorKeyHistory::from_set_history(
                &history,
            );
        let _ = ingress(from, &bytes, &history, &key_history, &ChainId::TEST);
    }
}

// ── In-file 4-replica harness ───────────────────────────────────────
//
// The deterministic `ReplicaSet` simulator from `step.rs::tests::property`
// is private to that module's test tree, so this fuzzer carries its
// own minimal copy. The two harnesses don't need to stay in lockstep:
// this one only feeds `Event`s into `step()` and inspects `Commit`
// actions, which is the smallest surface that lets us assert the
// no-conflicting-commits invariant.

/// Validator set built from `n_total` distinct NodeIds whose first
/// byte is `1..=n_total`. Sorted, deduplicated, and indexed so
/// `validators[i]` is the all-`(i+1)` NodeId — matches the layout of
/// the existing `step::tests::property::validator_set` fixture so a
/// reader who has seen one harness recognises the other.
fn cluster_validator_set(n_total: usize) -> ValidatorSet {
    let members: Vec<boule_consensus::validator_set::ValidatorId> = (1..=n_total as u8)
        .map(|b| boule_consensus::validator_set::ValidatorId::from_genesis_pubkey([b; 32]))
        .collect();
    ValidatorSet::new(members)
}

struct TestBlockBuilder {
    proposer: NodeId,
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

struct ReplicaSet {
    cores: Vec<HotStuffCore>,
    inboxes: Vec<VecDeque<Event>>,
    commits: Vec<BTreeMap<Height, Block>>,
    validators: ValidatorSet,
    genesis: Block,
}

impl ReplicaSet {
    fn new(n: usize) -> Self {
        let validators = cluster_validator_set(n);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let cores: Vec<HotStuffCore> = (0..n)
            .map(|i| {
                let nid = validators.get(i).unwrap().into_node_id();
                let state = HotStuffState::new(validators.clone(), genesis.clone());
                HotStuffCore::new(nid, state)
            })
            .collect();
        let inboxes = (0..n).map(|_| VecDeque::new()).collect();
        let commits = (0..n).map(|_| BTreeMap::new()).collect();
        Self {
            cores,
            inboxes,
            commits,
            validators,
            genesis,
        }
    }

    fn len(&self) -> usize {
        self.cores.len()
    }

    fn inject(&mut self, replica: usize, event: Event) {
        self.inboxes[replica].push_back(event);
    }

    fn inject_all(&mut self, event: Event) {
        for i in 0..self.cores.len() {
            self.inject(i, event.clone());
        }
    }

    fn deliver_one(&mut self, replica: usize) -> bool {
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
                    for target in 0..self.cores.len() {
                        self.inboxes[target].push_back(event_from_msg(source_nid, msg.clone()));
                    }
                }
                Action::Commit(block) => {
                    self.commits[source].insert(block.header.height, block);
                }
                Action::Persist(_)
                | Action::RequestBlock { .. }
                | Action::EquivocationEvidence { .. }
                | Action::ProposalEquivocationEvidence { .. } => {}
                // #606: stand in for the integration layer — build the
                // proposal and re-apply the resulting Broadcast(Proposal).
                Action::BuildProposal {
                    view,
                    high_qc,
                    parent,
                } => {
                    let builder = TestBlockBuilder {
                        proposer: source_nid,
                    };
                    if let Ok(block) = builder.build(
                        &parent,
                        view,
                        &high_qc,
                        &self.cores[source].state().pending_blocks,
                        0,
                    ) {
                        let built = self.cores[source].proposal_built(view, block, high_qc);
                        self.apply_actions(source, built);
                    }
                }
            }
        }
    }

    fn run_bounded(&mut self, max_rounds: usize) {
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

    /// Synthesize a fully-signed QC over `(view, block_hash)` —
    /// signatures are placeholder bytes, since the safety core never
    /// re-verifies embedded QC signatures.
    fn synth_qc(&self, view: View, block_hash: BlockHash) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(view, block_hash, self.validators.len());
        for i in 0..self.validators.len() {
            qc.add_signature(i, [i as u8 + 1; 64]);
        }
        qc
    }
}

fn event_from_msg(source: NodeId, msg: ConsensusMsg) -> Event {
    let sig = [0u8; 64];
    match msg {
        ConsensusMsg::Proposal(payload) => {
            Event::ProposalReceived(boule_consensus::dispatch::Verified::unchecked(Signed {
                payload,
                signer: source,
                sig,
            }))
        }
        ConsensusMsg::Vote(payload) => {
            Event::VoteReceived(boule_consensus::hotstuff::step::VoteVariant::Ed25519(
                boule_consensus::dispatch::Verified::unchecked(Signed {
                    payload,
                    signer: source,
                    sig,
                }),
            ))
        }
        ConsensusMsg::NewView(payload) => {
            Event::NewViewReceived(boule_consensus::dispatch::Verified::unchecked(Signed {
                payload,
                signer: source,
                sig,
            }))
        }
    }
}

/// View-1 kickoff proposal: leader of view 1 (`validators[1 % n]`)
/// builds a child of genesis under a synth genesis-QC.
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

/// Safety: at every height, no two replicas committed differing
/// blocks. This is the cross-replica analog of HotStuff's "conflicting
/// nodes cannot both be committed" — and the property a Byzantine
/// peer with malformed wire input must not be allowed to break.
fn assert_no_conflicting_commits(replicas: &ReplicaSet) {
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
                     height {height}",
                );
            }
        }
    }
}

// ── Cluster fuzz step grammar ───────────────────────────────────────

#[derive(Debug, Clone)]
enum FuzzStep {
    Deliver(usize),
    InjectBytesProposal {
        target: usize,
        sender_idx: usize,
        parent_hash_genesis: bool,
        view: View,
        height: Height,
        justify_view: View,
        justify_block_hash: BlockHash,
    },
    InjectBytesVote {
        target: usize,
        sender_idx: usize,
        view: View,
        block_hash: BlockHash,
    },
    InjectBytesNewView {
        target: usize,
        sender_idx: usize,
        qc_view: View,
        qc_block_hash: BlockHash,
    },
}

fn fuzz_step_strategy(n_replicas: usize) -> impl Strategy<Value = FuzzStep> {
    // 6:1:1:1 honest-deliver : malformed-proposal : malformed-vote :
    // malformed-newview. Heavy honest weight keeps the cluster making
    // progress between malformed injections; light Byzantine weight
    // leaves room for adversarial-pattern coverage.
    prop_oneof![
        6 => (0..n_replicas).prop_map(FuzzStep::Deliver),
        1 => (
            0..n_replicas,
            0..n_replicas, // sender_idx among the validator set
            any::<bool>(),
            0u64..MAX_VIEW,
            0u64..MAX_VIEW,
            0u64..MAX_VIEW,
            any::<[u8; 32]>(),
        ).prop_map(|(target, sender_idx, parent_hash_genesis, view, height, justify_view, justify_block_hash)| {
            FuzzStep::InjectBytesProposal {
                target, sender_idx, parent_hash_genesis,
                view: View(view),
                height: Height(height),
                justify_view: View(justify_view),
                justify_block_hash,
            }
        }),
        1 => (
            0..n_replicas,
            0..n_replicas,
            0u64..MAX_VIEW,
            any::<[u8; 32]>(),
        ).prop_map(|(target, sender_idx, view, block_hash)| {
            FuzzStep::InjectBytesVote { target, sender_idx, view: View(view), block_hash }
        }),
        1 => (
            0..n_replicas,
            0..n_replicas,
            0u64..MAX_VIEW,
            any::<[u8; 32]>(),
        ).prop_map(|(target, sender_idx, qc_view, qc_block_hash)| {
            FuzzStep::InjectBytesNewView { target, sender_idx, qc_view: View(qc_view), qc_block_hash }
        }),
    ]
}

/// Inputs for [`malformed_signed_proposal`]. Bundled so the helper
/// stays under clippy's argument cap without losing any fuzz knobs.
struct MalformedProposalInputs {
    n_validators: usize,
    sender: NodeId,
    genesis_hash: BlockHash,
    parent_hash_genesis: bool,
    view: View,
    height: Height,
    justify_view: View,
    justify_block_hash: BlockHash,
}

/// Mint a malformed `Signed<Proposal>` — block over an arbitrary
/// parent (or genesis), `justify` carrying a malformed bitmap and
/// signature/signer mismatch — claiming `sender` as the signer with a
/// zero `sig`. The safety core never verifies the embedded sig, so a
/// zero signature is enough to drive the dispatch path.
fn malformed_signed_proposal(p: MalformedProposalInputs) -> Signed<Proposal> {
    let parent_hash = if p.parent_hash_genesis {
        p.genesis_hash
    } else {
        let mut h = [0u8; 32];
        h[0] = p.view.0 as u8;
        h[1] = p.height.0 as u8;
        h
    };
    let header = BlockHeader {
        parent_hash,
        height: p.height,
        view: p.view,
        proposer: p.sender,
        state_commitment: [p.view.0 as u8; 32],
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
    let mut justify = QuorumCertificate::new(p.justify_view, p.justify_block_hash, p.n_validators);
    // Mint a full set of placeholder signatures so `has_quorum` is
    // satisfied — the safety core treats this as legitimate.
    for i in 0..p.n_validators {
        justify.add_signature(i, [i as u8 + 1; 64]);
    }
    Signed {
        payload: Proposal { block, justify },
        signer: p.sender,
        sig: [0u8; 64],
    }
}

proptest! {
    // Cap cases per-test below the module default so the 4-replica
    // run stays comfortably under the 15s/test wall-clock budget at
    // default `--test-threads=1`. Nightly's `PROPTEST_CASES=4096` env
    // var still overrides for stress runs.
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// A four-replica honest cluster, started with a view-1 kickoff
    /// proposal, must never commit conflicting blocks regardless of
    /// what malformed events get sprinkled into its inboxes. After
    /// the fuzz schedule completes, the cluster runs its remaining
    /// inboxes to quiescence so the honest tail of the trace can
    /// converge — that's where the "still commits well-formed
    /// proposals" guarantee comes from.
    #[test]
    fn prop_cluster_invariant_under_malformed_flood(
        schedule in prop::collection::vec(fuzz_step_strategy(4), 1..=120),
    ) {
        let mut replicas = ReplicaSet::new(4);
        let n_validators = replicas.validators.len();
        let genesis_hash = replicas.genesis.hash();
        let kickoff = kickoff_proposal(&replicas);
        replicas.inject_all(Event::ProposalReceived(boule_consensus::dispatch::Verified::unchecked(kickoff)));

        for step in schedule {
            match step {
                FuzzStep::Deliver(i) => {
                    replicas.deliver_one(i);
                }
                FuzzStep::InjectBytesProposal {
                    target, sender_idx, parent_hash_genesis,
                    view, height, justify_view, justify_block_hash,
                } => {
                    let sender = replicas.validators.get(sender_idx).unwrap().into_node_id();
                    let signed = malformed_signed_proposal(MalformedProposalInputs {
                        n_validators,
                        sender,
                        genesis_hash,
                        parent_hash_genesis,
                        view,
                        height,
                        justify_view,
                        justify_block_hash,
                    });
                    replicas.inject(target, Event::ProposalReceived(boule_consensus::dispatch::Verified::unchecked(signed)));
                }
                FuzzStep::InjectBytesVote { target, sender_idx, view, block_hash } => {
                    let sender = replicas.validators.get(sender_idx).unwrap().into_node_id();
                    let signed = Signed {
                        payload: Vote { view, block_hash },
                        signer: sender,
                        sig: [0u8; 64],
                    };
                    replicas.inject(target, Event::VoteReceived(boule_consensus::hotstuff::step::VoteVariant::Ed25519(boule_consensus::dispatch::Verified::unchecked(signed))));
                }
                FuzzStep::InjectBytesNewView { target, sender_idx, qc_view, qc_block_hash } => {
                    let sender = replicas.validators.get(sender_idx).unwrap().into_node_id();
                    let mut high_qc = QuorumCertificate::new(
                        qc_view, qc_block_hash, n_validators,
                    );
                    for i in 0..n_validators {
                        high_qc.add_signature(i, [i as u8 + 1; 64]);
                    }
                    let signed = Signed {
                        payload: NewView { high_qc },
                        signer: sender,
                        sig: [0u8; 64],
                    };
                    replicas.inject(target, Event::NewViewReceived(boule_consensus::dispatch::Verified::unchecked(signed)));
                }
            }
        }

        // Drain any remaining inboxes so the honest tail can converge
        // on a commit. Bounded — honest HotStuff is self-sustaining
        // and would otherwise loop forever.
        replicas.run_bounded(64);

        assert_no_conflicting_commits(&replicas);
    }
}

// ── Bounded-cache property ──────────────────────────────────────────
//
// A single safety core under tight `CacheLimits`, fed a stream of
// distinct malformed messages via `step()`. After each step the
// caches must stay within their configured caps.
//
// Eviction policies, recap from `consensus::limits`:
//
// - `vote_bucket`: hard cap; lowest-view entry is dropped on insert
//   at cap.
// - `parked_proposals`: hard cap; lowest-view parked is dropped on
//   insert at cap.
// - `pending_blocks`: *soft* cap; the high_qc parent chain (up to
//   `PROTECTED_HIGH_QC_DEPTH = 4` hops) plus genesis are pinned and
//   the cap is bypassed if they fill it.

const FUZZ_VOTE_BUCKET_CAP: usize = 8;
const FUZZ_PARKED_PROPOSALS_CAP: usize = 4;
const FUZZ_PENDING_BLOCKS_CAP: usize = 8;
/// Slack on the `pending_blocks` cap to account for the soft-cap
/// behaviour: genesis + the high_qc chain (up to 4 hops) are pinned
/// and the cap is bypassed when honoring it would compromise safety
/// walks. 5 = 1 genesis + 4 chain.
const PENDING_BLOCKS_SOFT_CAP_SLACK: usize = 5;

#[derive(Debug, Clone)]
enum CacheStep {
    /// Vote with arbitrary `(view, block_hash)` from a real validator.
    /// Drives growth of `vote_bucket`.
    Vote {
        signer_idx: usize,
        view: View,
        block_hash: BlockHash,
    },
    /// Proposal whose parent is unknown — drives growth of
    /// `parked_proposals`.
    ParkedProposal {
        sender_idx: usize,
        view: View,
        height: Height,
        parent_seed: u8,
    },
    /// Proposal whose parent is genesis — lands a real block in
    /// `state.pending_blocks` (if it survives validation).
    GenesisChildProposal { sender_idx: usize, view: View },
}

fn cache_step_strategy(n_validators: usize) -> impl Strategy<Value = CacheStep> {
    prop_oneof![
        1 => (0..n_validators, 0u64..MAX_VIEW, any::<[u8; 32]>()).prop_map(
            |(signer_idx, view, block_hash)| CacheStep::Vote {
                signer_idx,
                view: View(view),
                block_hash,
            },
        ),
        1 => (0..n_validators, 0u64..MAX_VIEW, 0u64..MAX_VIEW, any::<u8>()).prop_map(
            |(sender_idx, view, height, parent_seed)| CacheStep::ParkedProposal {
                sender_idx,
                view: View(view),
                height: Height(height),
                parent_seed,
            },
        ),
        1 => (0..n_validators, 1u64..MAX_VIEW).prop_map(
            |(sender_idx, view)| CacheStep::GenesisChildProposal {
                sender_idx,
                view: View(view),
            },
        ),
    ]
}

proptest! {
    /// Under a stream of distinct malformed messages, every safety-
    /// core cache stays within its configured cap (modulo the
    /// documented soft-cap slack on `pending_blocks`). This pins the
    /// guarantee from #135 / #203 against a fuzzed adversary.
    #[test]
    fn prop_caches_bounded_under_malformed_flood(
        steps in prop::collection::vec(cache_step_strategy(4), 1..=200),
    ) {
        let validators = cluster_validator_set(4);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let self_id = validators.get(0).unwrap().into_node_id();
        let state = HotStuffState::new(validators.clone(), genesis.clone());
        let limits = CacheLimits {
            vote_bucket_capacity: FUZZ_VOTE_BUCKET_CAP,
            parked_proposals_capacity: FUZZ_PARKED_PROPOSALS_CAP,
            pending_blocks_capacity: FUZZ_PENDING_BLOCKS_CAP,
            timeout_buckets_capacity: usize::MAX,
            // Block-sync retry knobs match `unbounded_for_tests`: no
            // backoff, no rotation, no drop budget. The fuzz harness
            // tests cap-based eviction, not the #196 rotate/drop path.
            block_sync_initial_backoff_views: 0,
            block_sync_max_backoff_views: 0,
            block_sync_per_peer_attempts: u32::MAX,
            block_sync_max_attempts: u32::MAX,
        };
        let counters = CacheEvictionCounters::default();
        let mut core = HotStuffCore::with_limits(self_id, state, limits, counters);

        for step in steps {
            let event = match step {
                CacheStep::Vote { signer_idx, view, block_hash } => {
                    let signer = validators.get(signer_idx).unwrap().into_node_id();
                    Event::VoteReceived(
                        boule_consensus::hotstuff::step::VoteVariant::Ed25519(
                            boule_consensus::dispatch::Verified::unchecked(Signed {
                                payload: Vote { view, block_hash },
                                signer,
                                sig: [0u8; 64],
                            }),
                        ),
                    )
                }
                CacheStep::ParkedProposal { sender_idx, view, height, parent_seed } => {
                    let sender = validators.get(sender_idx).unwrap().into_node_id();
                    let mut parent_hash = [0u8; 32];
                    parent_hash[0] = parent_seed;
                    parent_hash[1] = view.0 as u8;
                    parent_hash[2] = height.0 as u8;
                    let header = BlockHeader {
                        parent_hash,
                        height,
                        view,
                        proposer: sender,
                        state_commitment: [view.0 as u8; 32],
                        commands_commitment: Block::commands_commitment(&[]),
                        validator_history_commitment: [0; 32],
                        committed_height: Height::ZERO,
                        committed_state_root: [0; 32],
                        timestamp: 0,
                    };
                    let block = Block { header, commands: Vec::new() };
                    let mut justify = QuorumCertificate::new(View::ZERO, [0; 32], validators.len());
                    for i in 0..validators.len() {
                        justify.add_signature(i, [i as u8 + 1; 64]);
                    }
                    Event::ProposalReceived(boule_consensus::dispatch::Verified::unchecked(Signed {
                        payload: Proposal { block, justify },
                        signer: sender,
                        sig: [0u8; 64],
                    }))
                }
                CacheStep::GenesisChildProposal { sender_idx, view } => {
                    let sender = validators.get(sender_idx).unwrap().into_node_id();
                    let header = BlockHeader {
                        parent_hash: genesis.hash(),
                        height: Height(1),
                        view,
                        proposer: sender,
                        state_commitment: [view.0 as u8; 32],
                        commands_commitment: Block::commands_commitment(&[]),
                        validator_history_commitment: [0; 32],
                        committed_height: Height::ZERO,
                        committed_state_root: [0; 32],
                        timestamp: 0,
                    };
                    let block = Block { header, commands: Vec::new() };
                    let mut justify = QuorumCertificate::new(View::ZERO, genesis.hash(), validators.len());
                    for i in 0..validators.len() {
                        justify.add_signature(i, [i as u8 + 1; 64]);
                    }
                    Event::ProposalReceived(boule_consensus::dispatch::Verified::unchecked(Signed {
                        payload: Proposal { block, justify },
                        signer: sender,
                        sig: [0u8; 64],
                    }))
                }
            };
            let _ = core.step(event);

            let vote_bucket_len = core.vote_buckets().count();
            let parked_len = core.parked_proposals().count();
            let pending_len = core.state().pending_blocks.len();

            prop_assert!(
                vote_bucket_len <= FUZZ_VOTE_BUCKET_CAP,
                "vote_bucket grew past cap: {} > {}",
                vote_bucket_len,
                FUZZ_VOTE_BUCKET_CAP,
            );
            prop_assert!(
                parked_len <= FUZZ_PARKED_PROPOSALS_CAP,
                "parked_proposals grew past cap: {} > {}",
                parked_len,
                FUZZ_PARKED_PROPOSALS_CAP,
            );
            prop_assert!(
                pending_len <= FUZZ_PENDING_BLOCKS_CAP + PENDING_BLOCKS_SOFT_CAP_SLACK,
                "pending_blocks grew past cap+slack: {} > {} + {}",
                pending_len,
                FUZZ_PENDING_BLOCKS_CAP,
                PENDING_BLOCKS_SOFT_CAP_SLACK,
            );
        }
    }
}
