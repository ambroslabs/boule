//! Integration layer for HotStuff consensus: wires together
//! [`HotStuffCore`], [`Pacemaker`], storage, mempool, and the network.
//!
//! # Scope (milestone 8 / #24)
//!
//! This module houses the parts of the integration layer that exist
//! independently of the async event loop:
//!
//! - Wire protocol constants and the [`WireMessage`] envelope that is
//!   postcard-encoded on the network.
//! - [`NodeConfigForConsensus`]: the plain-data configuration struct.
//! - [`MempoolBlockBuilder`]: the [`BlockBuilder`] impl that pulls
//!   commands from the mempool and stamps `state_commitment` by
//!   temporarily applying the commands to a fork of the committed SM.
//! - [`ConsensusNode`]: the struct holding all components; construction
//!   only — the async event loop lands in a later PR.
//!
//! # Durability note
//!
//! The event loop (Phase D/E) is responsible for ensuring every
//! `Action::Persist` is flushed to WAL before the corresponding
//! outbound message is sent. This module sets up the components;
//! the ordering discipline is enforced when actions are applied.
//!
//! # `state_commitment` simplification
//!
//! [`MempoolBlockBuilder`] computes the child block's `state_commitment`
//! by forking the current committed SM state (snapshot → restore →
//! apply → read commitment → restore back). This is exact when the
//! proposed parent is the last-committed block, which is the common
//! case in a healthy network. A future PR will walk the not-yet-
//! committed ancestor chain for the rare multi-block-in-flight case.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::consensus::hotstuff::step::{BlockBuilder, HotStuffCore};
use crate::consensus::hotstuff::{HotStuffState, QuorumCertificate};
use crate::consensus::pacemaker::Pacemaker;
use crate::consensus::pacemaker::leader::RoundRobinSelector;
use crate::consensus::pacemaker::timeout::ExponentialBackoff;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::Signed;
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash, BlockHeader};
use crate::replication::mempool::Mempool;
use crate::replication::state_machine::StateMachine;
use crate::storage::{Storage, Wal};

// ── Protocol constants ───────────────────────────────────────────────────────

/// Protocol ID registered with the p2p multiplexer for consensus traffic.
/// Gossip uses `0x01`, ping-RPC uses `0x02`.
pub const PROTOCOL_ID: u8 = 0x03;

/// Maximum encoded frame size accepted from the wire for this protocol.
/// Sized to accommodate a full block with up to ~1000 moderate-sized
/// commands; production tuning can raise this without protocol changes.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

// ── Wire message envelope ────────────────────────────────────────────────────

/// Every message sent over the `PROTOCOL_ID` channel is one of these
/// variants, postcard-encoded.
///
/// The three consensus variants carry a [`Signed`] envelope whose
/// signature the integration layer verifies against the claimed signer
/// **before** feeding the payload into [`HotStuffCore::step`].
///
/// `BlockRequest` / `BlockResponse` are the block-sync sub-protocol:
/// when the safety core emits `Action::RequestBlock(hash, peer)`, the
/// integration layer sends `BlockRequest`; the peer replies with
/// `BlockResponse` (carrying the block if it has it, `None` otherwise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Proposal(Signed<crate::consensus::hotstuff::Proposal>),
    Vote(Signed<crate::consensus::hotstuff::qc::Vote>),
    NewView(Signed<crate::consensus::hotstuff::NewView>),
    /// Ask a peer for the block with this content-hash.
    BlockRequest(BlockHash),
    /// Reply to a `BlockRequest`. `None` means "I don't have it".
    BlockResponse(Option<Block>),
}

// ── Node configuration ───────────────────────────────────────────────────────

/// Plain-data configuration for a [`ConsensusNode`].
///
/// Constructed once at startup from the TOML config or test scaffolding
/// and passed into [`ConsensusNode::new`].
#[derive(Debug, Clone)]
pub struct NodeConfigForConsensus {
    /// The committee this node participates in. Must include `self_id`.
    pub validator_set: ValidatorSet,
    /// Pre-agreed genesis block. Every honest replica starts with an
    /// identical copy so `state.genesis_hash` is consistent cluster-wide.
    pub genesis: Block,
    /// Maximum number of commands a leader pulls from the mempool per
    /// proposal. Higher values increase throughput at the cost of
    /// larger blocks.
    pub propose_limit: usize,
    /// View-timer base duration (no consecutive failures). Feeds into
    /// [`ExponentialBackoff`].
    pub timeout_base: Duration,
    /// View-timer ceiling: backoff saturates here.
    pub timeout_max: Duration,
}

impl NodeConfigForConsensus {
    /// Reasonable defaults for a local 4-node test cluster.
    pub fn for_testing(validator_set: ValidatorSet, genesis: Block) -> Self {
        Self {
            validator_set,
            genesis,
            propose_limit: 64,
            timeout_base: Duration::from_millis(200),
            timeout_max: Duration::from_secs(10),
        }
    }
}

// ── Block builder ────────────────────────────────────────────────────────────

/// [`BlockBuilder`] that assembles a child block from the local mempool
/// and the current committed state machine.
///
/// `state_commitment` is computed by forking the committed SM state:
/// snapshot → apply new commands → read commitment → restore.  This is
/// exact when the proposed parent equals the last-committed block
/// (the common case). A future enhancement will walk the uncommitted
/// ancestor chain for the multi-block-in-flight scenario.
pub struct MempoolBlockBuilder {
    self_id: NodeId,
    mempool: Arc<dyn Mempool>,
    /// Shared with the event loop's `Commit` handler, which advances
    /// this SM forward when blocks commit.
    state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
    propose_limit: usize,
}

impl MempoolBlockBuilder {
    pub fn new(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        propose_limit: usize,
    ) -> Self {
        Self {
            self_id,
            mempool,
            state_machine,
            propose_limit,
        }
    }
}

impl BlockBuilder for MempoolBlockBuilder {
    fn build(&self, parent: &Block, view: View, _high_qc: &QuorumCertificate) -> Block {
        let commands = self.mempool.propose(self.propose_limit);

        // Fork the committed SM state: snapshot, apply candidate commands,
        // read commitment, then restore so the SM is left unchanged.
        let state_commitment = {
            let mut sm = self.state_machine.lock();
            let snap = sm.snapshot();

            let mut commitment = sm.state_commitment();
            // Apply each command on the fork; ignore individual errors
            // (a command that fails changes nothing per the StateMachine
            // contract, so commitment is consistent with "skip bad cmds").
            for cmd in &commands {
                if sm.apply(cmd).is_ok() {
                    commitment = sm.state_commitment();
                }
            }

            // Restore SM to committed state regardless of outcome.
            sm.restore(&snap)
                .expect("restore from own snapshot must not fail");
            commitment
        };

        let commands_commitment = Block::commands_commitment(&commands);
        Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height: parent.header.height + 1,
                view,
                proposer: self.self_id,
                state_commitment,
                commands_commitment,
            },
            commands,
        }
    }
}

// ── ConsensusNode ────────────────────────────────────────────────────────────

/// Composes all consensus components into a single struct.
///
/// Construction only in this PR — the async event loop that drives the
/// select! over network events, timers, and pacemaker actions lands in
/// Phase D/E.
pub struct ConsensusNode {
    /// This replica's identity, used to sign outbound messages.
    pub self_id: NodeId,
    /// HotStuff safety core (pure state machine).
    pub core: HotStuffCore,
    /// View-management state machine (pure, no I/O).
    pub pacemaker: Pacemaker,
    /// Shared state machine; mutated on `Action::Commit`.
    pub state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
    /// Source of pending commands for the block builder / leader path.
    pub mempool: Arc<dyn Mempool>,
    /// Durable KV store for control-plane state
    /// (`last_voted_view`, `locked`, `high_qc`).
    pub storage: Arc<dyn Storage>,
    /// Append-only log for durability. Flushed before outbound messages
    /// that depend on the persisted state.
    pub wal: Arc<dyn Wal>,
    /// The ordered committee this node participates in.
    pub validator_set: ValidatorSet,
    /// Configured view-timer behaviour; consulted by the timer helper
    /// in Phase D when arming/re-arming the view timer.
    pub timeout_policy: Arc<ExponentialBackoff>,
}

impl ConsensusNode {
    /// Construct a `ConsensusNode` from configuration and backing
    /// resources. Does **not** start the event loop.
    pub fn new(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> Self {
        let validator_set = Arc::new(config.validator_set.clone());

        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));

        let selector = Arc::new(RoundRobinSelector::new(Arc::clone(&validator_set)));

        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            config.propose_limit,
        ));

        let hs_state = HotStuffState::new(config.validator_set.clone(), config.genesis);
        let core = HotStuffCore::new(self_id, hs_state, builder as Arc<dyn BlockBuilder>);

        Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: config.validator_set,
            timeout_policy,
        }
    }

    /// Current view from the pacemaker's perspective.
    pub fn current_view(&self) -> View {
        self.pacemaker.current_view()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use super::*;
    use crate::consensus::validator_set::ValidatorSet;
    use crate::p2p::NodeId;
    use crate::replication::block::Block;
    use crate::replication::impls::{CounterStateMachine, InMemoryMempool};
    use crate::storage::{MemoryStorage, MemoryWal};

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn four_validators() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
    }

    fn genesis() -> Block {
        Block::genesis([0u8; 32])
    }

    fn test_config(vs: ValidatorSet) -> NodeConfigForConsensus {
        NodeConfigForConsensus::for_testing(vs, genesis())
    }

    fn make_sm() -> Arc<Mutex<Box<dyn StateMachine>>> {
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())))
    }

    fn make_node(self_id: NodeId) -> ConsensusNode {
        let vs = four_validators();
        let cfg = test_config(vs);
        ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(256)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        )
    }

    // ── A4: smoke test ───────────────────────────────────────────────────────

    #[test]
    fn new_initializes_at_view_zero() {
        let node = make_node(nid(1));
        assert_eq!(node.current_view(), 0);
        assert_eq!(node.core.state().current_view, 0);
        assert_eq!(node.pacemaker.current_view(), 0);
    }

    #[test]
    fn self_id_is_stored_correctly() {
        let node = make_node(nid(3));
        assert_eq!(node.self_id, nid(3));
        assert_eq!(node.core.self_id(), nid(3));
        assert_eq!(node.pacemaker.self_id(), nid(3));
    }

    #[test]
    fn genesis_is_in_pending_blocks() {
        let node = make_node(nid(1));
        let g_hash = genesis().hash();
        assert!(
            node.core.state().pending_blocks.contains_key(&g_hash),
            "genesis block must be pre-seeded into pending_blocks",
        );
    }

    // ── A2: WireMessage roundtrip ────────────────────────────────────────────

    fn sample_block() -> Block {
        use crate::replication::block::BlockHeader;
        let g = genesis();
        Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 1,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: vec![],
        }
    }

    fn sample_qc() -> crate::consensus::hotstuff::QuorumCertificate {
        crate::consensus::hotstuff::QuorumCertificate::new(0, genesis().hash(), 4)
    }

    fn dummy_sig() -> [u8; 64] {
        [0u8; 64]
    }

    #[test]
    fn wire_message_proposal_roundtrip() {
        use crate::consensus::hotstuff::Proposal;
        let msg = WireMessage::Proposal(Signed {
            payload: Proposal {
                block: sample_block(),
                justify: sample_qc(),
            },
            signer: nid(1),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_vote_roundtrip() {
        use crate::consensus::hotstuff::qc::Vote;
        let msg = WireMessage::Vote(Signed {
            payload: Vote {
                view: 7,
                block_hash: [0xAB; 32],
            },
            signer: nid(2),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_new_view_roundtrip() {
        use crate::consensus::hotstuff::NewView;
        let msg = WireMessage::NewView(Signed {
            payload: NewView {
                high_qc: sample_qc(),
            },
            signer: nid(3),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_request_roundtrip() {
        let hash = [0xCDu8; 32];
        let msg = WireMessage::BlockRequest(hash);
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_some_roundtrip() {
        let msg = WireMessage::BlockResponse(Some(sample_block()));
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_none_roundtrip() {
        let msg = WireMessage::BlockResponse(None);
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── B3: MempoolBlockBuilder tests ────────────────────────────────────────

    fn make_builder(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(self_id, mempool, sm, 10)
    }

    #[test]
    fn builder_sets_header_fields_from_parent_and_view() {
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let block = builder.build(&parent, 3, &qc);

        assert_eq!(block.header.parent_hash, parent.hash());
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.view, 3);
        assert_eq!(block.header.proposer, nid(1));
    }

    #[test]
    fn builder_pulls_commands_from_mempool() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Decrement.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder.build(&genesis(), 1, &sample_qc());

        assert_eq!(block.commands.len(), 2);
    }

    #[test]
    fn builder_is_deterministic_for_same_inputs() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let b1 = builder.build(&parent, 1, &qc);
        let b2 = builder.build(&parent, 1, &qc);

        assert_eq!(b1.hash(), b2.hash(), "build must be deterministic");
    }

    #[test]
    fn builder_does_not_mutate_state_machine() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let before = sm.lock().state_commitment();

        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        builder.build(&genesis(), 1, &sample_qc());

        let after = sm.lock().state_commitment();
        assert_eq!(
            before, after,
            "build must not leave the state machine mutated",
        );
    }

    #[test]
    fn builder_state_commitment_matches_applying_commands() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let cmd = CounterCommand::Increment.encode();
        mp.insert(cmd.clone()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder.build(&genesis(), 1, &sample_qc());

        // Manually apply the same command and check commitment matches.
        let mut reference_sm = CounterStateMachine::new();
        reference_sm.apply(&cmd).unwrap();
        assert_eq!(
            block.header.state_commitment,
            reference_sm.state_commitment(),
        );
    }

    #[test]
    fn builder_commands_commitment_matches_commands() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Decrement.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder.build(&genesis(), 1, &sample_qc());

        let recomputed = Block::commands_commitment(&block.commands);
        assert_eq!(block.header.commands_commitment, recomputed);
    }
}
