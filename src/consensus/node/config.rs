//! Plain-data configuration for [`super::ConsensusNode`].

use std::time::Duration;

use crate::consensus::View;
use crate::consensus::limits::CacheLimits;
use crate::consensus::validator_set::ValidatorSet;
use crate::replication::block::Block;

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
    /// [`crate::consensus::pacemaker::timeout::ExponentialBackoff`].
    pub timeout_base: Duration,
    /// View-timer ceiling: backoff saturates here.
    pub timeout_max: Duration,
    /// Per-cache caps for the safety-core's `vote_bucket`,
    /// `parked_proposals`, `pending_blocks` and the integration
    /// layer's `timeout_buckets`. See
    /// [`crate::consensus::limits::CacheLimits`] for the policy
    /// documentation.
    pub limits: CacheLimits,
    /// Snapshot creation policy. Defaults to disabled (no snapshots
    /// produced) so tests that don't opt in see zero behavioural
    /// change; production wiring in `src/node.rs` substitutes the
    /// operator-configured policy from
    /// [`crate::config::ConsensusConfig`].
    pub snapshot_policy: crate::replication::snapshot::SnapshotPolicy,

    /// Operator-supplied floor on the gap between a reconfig's commit
    /// view and its `v_eff` (#272). Clamped up to
    /// [`crate::consensus::reconfig::MIN_V_EFF_DELAY`] at validation
    /// time so the consensus-side floor is never undercut. Defaults to
    /// the constant.
    pub min_v_eff_delay: View,

    /// Chain-level signature scheme selected at genesis (#288). Fixed
    /// for the lifetime of the chain — switching requires a
    /// coordinated chain restart from new genesis. Today only
    /// `Ed25519Collected` is implemented; the BLS variant lands in #289
    /// and the "node built for the wrong scheme" mismatch check lands
    /// in #292.
    pub signature_scheme: crate::crypto::sig_scheme::SignatureSchemeChoice,
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
            snapshot_policy: crate::replication::snapshot::SnapshotPolicy::disabled(),
            min_v_eff_delay: crate::consensus::reconfig::MIN_V_EFF_DELAY,
            signature_scheme: crate::crypto::sig_scheme::SignatureSchemeChoice::default(),
        }
    }
}
