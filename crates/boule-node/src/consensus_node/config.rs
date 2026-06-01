//! Plain-data configuration for [`super::ConsensusNode`].

use std::time::Duration;

use boule_consensus::View;
use boule_consensus::limits::CacheLimits;
use boule_consensus::replication::block::Block;
use boule_consensus::validator_set::ValidatorSet;

/// Plain-data configuration for a [`super::ConsensusNode`].
///
/// Constructed once at startup from the TOML config or test scaffolding
/// and passed into [`super::ConsensusNode::new`].
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
    /// [`boule_consensus::pacemaker::timeout::ExponentialBackoff`].
    pub timeout_base: Duration,
    /// View-timer ceiling: backoff saturates here.
    pub timeout_max: Duration,
    /// Per-cache caps for the safety-core's `vote_bucket`,
    /// `parked_proposals`, `pending_blocks` and the integration
    /// layer's `timeout_buckets`. See
    /// [`boule_consensus::limits::CacheLimits`] for the policy
    /// documentation.
    pub limits: CacheLimits,
    /// Snapshot creation policy. Defaults to disabled (no snapshots
    /// produced) so tests that don't opt in see zero behavioural
    /// change; production wiring in `src/node.rs` substitutes the
    /// operator-configured policy from
    /// [`boule_core::config::ConsensusConfig`].
    pub snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy,

    /// Operator-supplied floor on the gap between a reconfig's commit
    /// view and its `v_eff` (#272). Clamped up to
    /// [`boule_consensus::reconfig::MIN_V_EFF_DELAY`] at validation
    /// time so the consensus-side floor is never undercut. Defaults to
    /// the constant.
    pub min_v_eff_delay: View,

    /// Chain-level signature scheme selected at genesis (#288). Fixed
    /// for the lifetime of the chain — switching requires a
    /// coordinated chain restart from new genesis. Today only
    /// `Ed25519Collected` is implemented; the BLS variant lands in #289
    /// and the "node built for the wrong scheme" mismatch check lands
    /// in #292.
    pub signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice,

    /// Number of committed blocks to retain in the durable block store
    /// (`consensus/block/<hash>`) below `last_committed`. Older
    /// committed blocks are deleted in the same atomic batch as each
    /// commit, alongside their secondary-index entry. `0` disables
    /// pruning (archive mode); see #194 for the policy rationale.
    pub block_retention_window: u64,

    /// Minimum wall-clock spacing between proposals this node produces as
    /// leader (#614). The local leader holds a QC-triggered proposal behind
    /// a timer until this interval has elapsed since its previous proposal,
    /// so block production has a floor on its rate. `0` (the default)
    /// disables pacing — at n >= 4 the network is already slower than any
    /// sane block time, so this only ever bites a local leader that would
    /// otherwise outrun it (most sharply a single-validator set, where it
    /// turns an unbounded propose/self-vote loop into a steady block time).
    pub min_block_interval: Duration,
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
            // Tests should not see eviction unless they explicitly
            // construct a tight-cap config; honest-only proptests in
            // particular fail loudly under spurious eviction. The
            // production wiring in `src/node.rs` substitutes
            // `CacheLimits::production_defaults` (or the operator's
            // override).
            limits: CacheLimits::unbounded_for_tests(),
            // Tests opt into snapshots by replacing this with a real
            // policy. The default keeps the snapshot store untouched.
            snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy::disabled(),
            min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
            signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::default(),
            // Tests build short chains — keep everything by default so
            // an integration test that walks the committed chain by
            // hand never trips over a pruned block. Tests that exercise
            // pruning override this explicitly.
            block_retention_window: 0,
            // Pacing off by default: tests assert on per-event scheduling
            // and must not gain an artificial block-time floor.
            min_block_interval: Duration::ZERO,
        }
    }
}
