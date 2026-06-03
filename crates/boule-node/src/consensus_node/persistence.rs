//! Storage codec helpers and durable-state persistence for the
//! consensus integration layer.
//!
//! This module owns the on-storage byte format for every control-plane
//! key (`last_voted_view`, `locked`, `high_qc`, `proposed_in_view`,
//! `last_timeout_vote`, committed blocks, `last_committed`,
//! `validator_history`, etc.) and the recovery path that re-hydrates a
//! [`HotStuffState`] from those keys at startup.
//!
//! The persist-before-send discipline that HotStuff safety requires is
//! enforced by [`super::ConsensusNode::persist_updates`]: every
//! [`StateUpdate`] from a `step` is written atomically before the
//! dependent `Broadcast` / `Commit` action is allowed to proceed. See
//! the function's doc-comment for the durability contract.

use std::collections::HashMap;
use std::collections::VecDeque;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use boule_consensus::hotstuff::Locked;
use boule_consensus::hotstuff::qc::{TimeoutVote, VerifiedQc};
use boule_consensus::hotstuff::step::StateUpdate;
use boule_consensus::hotstuff::{HotStuffState, QuorumCertificate, genesis_qc};
use boule_consensus::replication::block::{Block, BlockHash};
use boule_consensus::validator_set::ValidatorSet;
use boule_consensus::{Height, View};
use boule_core::storage::{Storage, StorageExt};

use super::{ConsensusNode, TRACE_TARGET};

/// Storage key under which the replica's `last_voted_view` is persisted.
///
/// HotStuff safety rests on "never vote twice at the same view across
/// restarts" — the event loop writes this key (via [`ConsensusNode::persist_updates`])
/// before any outbound vote is allowed to leave the node, and the
/// recovery path ([`recover_state`]) reads it back at startup.
pub const STORAGE_KEY_LAST_VOTED_VIEW: &[u8] = b"consensus/last_voted_view";

/// Storage key for the replica's locked block (two-chain lock). See
/// [`Locked`] for the fields persisted.
pub const STORAGE_KEY_LOCKED: &[u8] = b"consensus/locked";

/// Storage key for the replica's highest-known QC, used as the
/// justify on proposals and piggybacked on `NewView`.
pub const STORAGE_KEY_HIGH_QC: &[u8] = b"consensus/high_qc";

/// Storage key for the highest view at which this replica has minted
/// a `Proposal` as leader. Persisted before any `Broadcast(Proposal)`
/// leaves so a crash between `Signed::sign` and the network bytes
/// reaching peers cannot let a restarted leader re-mint a *different*
/// proposal at the same view (different parent walk, different
/// `high_qc` snapshot, different mempool ordering) — two distinct
/// signed `Proposal(v)` envelopes from the same leader are slashable
/// equivocation evidence even when the leader was honest. Read at
/// boot by [`ConsensusNode::recover`] and threaded into the safety
/// core via [`boule_consensus::hotstuff::step::HotStuffCore::with_proposed_in_view`].
/// Audit finding 4-6, issue #407.
pub const STORAGE_KEY_PROPOSED_IN_VIEW: &[u8] = b"consensus/proposed_in_view";

/// Storage key for the most recently broadcast [`TimeoutVote`] envelope.
/// Persisted by [`ConsensusNode::send_timeout`] *before* any byte hits
/// the wire, then replayed bit-identically on every subsequent attempt
/// to time out at the same `view` — whether the next attempt is a timer
/// re-fire in the same process or the first send after a restart. The
/// encoded value is the full [`TimeoutVote`] (`view` + the
/// `Option<QuorumCertificate>` piggyback) so the resigned envelope
/// matches the original byte-for-byte.
///
/// Without this, `send_timeout` would re-read `state.high_qc` on each
/// attempt; that value can advance between attempts (a fresher QC
/// arrived via a NewView, a piggybacked justify from a partial
/// proposal, etc.), producing a *second* signed `TimeoutVote(v)` whose
/// `high_qc` differs from the first. Both envelopes are slashable
/// equivocation evidence even when the replica was honest. Audit
/// finding 14-1, issue #415.
pub const STORAGE_KEY_LAST_TIMEOUT_VOTE: &[u8] = b"consensus/last_timeout_vote";

/// Storage-key prefix under which committed blocks are persisted by
/// content-hash. Each block is written on commit so a peer can fetch
/// it via the block-sync sub-protocol even after we have evicted it
/// from the in-memory `pending_blocks` cache or restarted (which
/// resets `pending_blocks` to just the genesis block).
///
/// Keys are formed as `{STORAGE_KEY_BLOCK_PREFIX}{hash}` (a 32-byte
/// content hash appended to the prefix). See [`block_storage_key`].
///
/// Issue #178: a restarted replica with empty `pending_blocks` was
/// unable to serve a `BlockRequest` for a block it had already
/// committed, leaving its peers' block-sync stuck in a retry loop.
/// Persisting on commit gives every committed block a durable home
/// every replica can serve from.
pub const STORAGE_KEY_BLOCK_PREFIX: &[u8] = b"consensus/block/";

/// Storage-key prefix for the secondary index that maps each committed
/// block's `height` to its content-hash. Written atomically with
/// `consensus/block/<hash>` on commit; the prune-on-commit pass walks
/// this index in ascending-height order to find blocks that have aged
/// out of the configured retention window (#194).
///
/// Keys are formed as `{STORAGE_KEY_HEIGHT_PREFIX}{height_be_u64}` so
/// the redb lex-sorted scan yields heights in ascending numeric order.
/// See [`height_storage_key`].
pub const STORAGE_KEY_HEIGHT_PREFIX: &[u8] = b"consensus/height/";

/// Storage key for the (height, view) of the most recently committed
/// block. Restored at startup so [`boule_consensus::status::ConsensusStatus::last_committed_height`]
/// reflects the durable chain even before the run loop sees its first
/// inbound proposal — fixing the post-restart `last_committed_height
/// = 0` gap called out in #178's reopen comment.
pub const STORAGE_KEY_LAST_COMMITTED: &[u8] = b"consensus/last_committed";

/// Storage key for the persisted [`boule_consensus::validator_history::ValidatorSetHistory`] (#254).
/// Written after every successful commit-time reconfig application;
/// read at startup by [`ConsensusNode::recover`] so the active set
/// tracks committed reconfigs across restarts. The blob is the
/// postcard-encoded full history (genesis boundary + every later
/// boundary in chronological order) — small enough that we don't
/// bother with incremental encoding or a GC bound (#140 open question:
/// keep all, revisit if validator-set churn ever becomes pathological).
pub const STORAGE_KEY_VALIDATOR_HISTORY: &[u8] = b"consensus/validator_history";

/// Storage key for the persisted [`boule_consensus::validator_key_history::ValidatorKeyHistory`] (#260).
/// Written after every successful commit-time rotation application;
/// read at startup so post-rotation signing keys persist across
/// restarts. Same encoding shape as
/// [`STORAGE_KEY_VALIDATOR_HISTORY`]: a single full snapshot rather
/// than a journal, traded for simpler recovery.
pub const STORAGE_KEY_VALIDATOR_KEY_HISTORY: &[u8] = b"consensus/validator_key_history";

/// Storage key for the persisted [`boule_consensus::bls_key_history::BlsKeyHistory`]
/// (#339). Written alongside [`STORAGE_KEY_VALIDATOR_KEY_HISTORY`]
/// after every successful commit-time rotation application on BLS
/// chains; read at startup so the per-validator BLS pubkey timeline
/// persists across restarts. Without this, an old QC verified after
/// a restart would index against a stale post-genesis pubkey set
/// because the rotations are reseeded from genesis only.
pub const STORAGE_KEY_BLS_KEY_HISTORY: &[u8] = b"consensus/bls_key_history";

/// Storage key for the committed-equivocation-evidence registry (#657).
/// Written after every commit that records new evidence; read at startup
/// so the "this validator already has committed evidence" dedup survives
/// restarts (and survives block pruning, which a rebuild-from-blocks
/// approach would not). The blob is a postcard-encoded map from the
/// equivocator's stable `ValidatorId` to the view it equivocated at — the
/// input a later slashing pass (#658) consumes.
pub const STORAGE_KEY_COMMITTED_EVIDENCE: &[u8] = b"consensus/committed_evidence";

/// Bound on [`ConsensusNode::recent_qcs`]. The cache only needs to
/// retain the QC for the most recently-committed block (so the
/// snapshot creation hook can find it); a small buffer absorbs
/// re-orderings between proposal arrival and commit. Production
/// memory cost is negligible — each QC is ≤ a few KiB and the cache
/// is tens of entries deep.
pub const RECENT_QC_CACHE_CAPACITY: usize = 32;

/// Bounded LRU-by-insertion cache of QCs keyed by block hash.
///
/// Insertion order is tracked in a `VecDeque`; on overflow, the
/// oldest entry is dropped. Lookups are O(1) via the inner `HashMap`.
#[derive(Default)]
pub(super) struct RecentQcCache {
    map: HashMap<BlockHash, QuorumCertificate>,
    order: VecDeque<BlockHash>,
}

impl RecentQcCache {
    pub(super) fn insert(&mut self, hash: BlockHash, qc: QuorumCertificate, capacity: usize) {
        if self.map.insert(hash, qc).is_none() {
            self.order.push_back(hash);
            // Evict the oldest entries until back under cap.
            while self.order.len() > capacity {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    pub(super) fn get(&self, hash: &BlockHash) -> Option<&QuorumCertificate> {
        self.map.get(hash)
    }
}

// ── Codec helpers ────────────────────────────────────────────────────────────

/// Serialize a `last_voted_view` value to its on-storage encoding.
pub fn encode_voted_view(view: View) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&view).context("encode last_voted_view")
}

/// Inverse of [`encode_voted_view`].
pub fn decode_voted_view(bytes: &[u8]) -> anyhow::Result<View> {
    postcard::from_bytes(bytes).context("decode last_voted_view")
}

/// Serialize a [`Locked`] value to its on-storage encoding.
pub fn encode_locked(locked: &Locked) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(locked).context("encode locked")
}

/// Inverse of [`encode_locked`].
pub fn decode_locked(bytes: &[u8]) -> anyhow::Result<Locked> {
    postcard::from_bytes(bytes).context("decode locked")
}

/// Serialize a [`QuorumCertificate`] (as `high_qc`) to its on-storage
/// encoding.
pub fn encode_high_qc(qc: &QuorumCertificate) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(qc).context("encode high_qc")
}

/// Inverse of [`encode_high_qc`].
pub fn decode_high_qc(bytes: &[u8]) -> anyhow::Result<QuorumCertificate> {
    postcard::from_bytes(bytes).context("decode high_qc")
}

/// Serialize a `proposed_in_view` value to its on-storage encoding.
/// See [`STORAGE_KEY_PROPOSED_IN_VIEW`] for the durability contract
/// (audit finding 4-6, issue #407).
pub fn encode_proposed_in_view(view: View) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&view).context("encode proposed_in_view")
}

/// Inverse of [`encode_proposed_in_view`].
pub fn decode_proposed_in_view(bytes: &[u8]) -> anyhow::Result<View> {
    postcard::from_bytes(bytes).context("decode proposed_in_view")
}

/// Serialize a [`TimeoutVote`] envelope for the durable
/// [`STORAGE_KEY_LAST_TIMEOUT_VOTE`] slot. See that key's docs for the
/// equivocation-prevention contract (audit finding 14-1, issue #415).
pub fn encode_last_timeout_vote(payload: &TimeoutVote) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(payload).context("encode last_timeout_vote")
}

/// Inverse of [`encode_last_timeout_vote`].
pub fn decode_last_timeout_vote(bytes: &[u8]) -> anyhow::Result<TimeoutVote> {
    postcard::from_bytes(bytes).context("decode last_timeout_vote")
}

/// Compose the storage key for a committed block keyed by its
/// content-hash: `STORAGE_KEY_BLOCK_PREFIX || hash`.
pub fn block_storage_key(hash: &BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_BLOCK_PREFIX.len() + hash.len());
    key.extend_from_slice(STORAGE_KEY_BLOCK_PREFIX);
    key.extend_from_slice(hash);
    key
}

/// Compose the storage key for the height-index entry of a committed
/// block: `STORAGE_KEY_HEIGHT_PREFIX || height.to_be_bytes()`. The
/// big-endian encoding is load-bearing — redb sorts keys
/// lexicographically and we rely on that order matching numeric height
/// for the prune-on-commit range scan (#194).
pub fn height_storage_key(height: Height) -> Vec<u8> {
    let raw = height.0.to_be_bytes();
    let mut key = Vec::with_capacity(STORAGE_KEY_HEIGHT_PREFIX.len() + raw.len());
    key.extend_from_slice(STORAGE_KEY_HEIGHT_PREFIX);
    key.extend_from_slice(&raw);
    key
}

/// Decode the big-endian u64 height from a `consensus/height/<be_u64>`
/// key. Returns `None` if the key does not have the expected prefix or
/// the trailing eight-byte payload.
pub fn decode_height_storage_key(key: &[u8]) -> Option<Height> {
    let suffix = key.strip_prefix(STORAGE_KEY_HEIGHT_PREFIX)?;
    let bytes: [u8; 8] = suffix.try_into().ok()?;
    Some(Height(u64::from_be_bytes(bytes)))
}

/// Serialize a committed [`Block`] for the durable block store. See
/// [`STORAGE_KEY_BLOCK_PREFIX`].
pub fn encode_block(block: &Block) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(block).context("encode committed block")
}

/// Inverse of [`encode_block`].
pub fn decode_block(bytes: &[u8]) -> anyhow::Result<Block> {
    postcard::from_bytes(bytes).context("decode committed block")
}

/// Persisted `(height, view, hash)` triple for the most recently
/// committed block. Stored at [`STORAGE_KEY_LAST_COMMITTED`].
///
/// `last_committed_hash` is the content-hash of the most recently
/// committed block — used by the recovery path (#325 PR B) as the tip
/// from which to walk the committed-block chain backward to genesis,
/// rebuilding the validator histories from each block's reconfig and
/// rotation commands. Without the hash, recovery would have no way to
/// locate the chain tip in storage.
///
/// The genesis case (no blocks yet committed) is `height == 0`,
/// `view == 0`, `last_committed_hash == [0; 32]` (the all-zero hash
/// is reserved for "no tip persisted" and is distinguishable from a
/// real block hash because the recovery path treats `height == 0` as
/// "no chain to walk").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCommitted {
    pub height: Height,
    pub view: View,
    pub last_committed_hash: BlockHash,
}

/// Serialize the `(height, view)` checkpoint to its on-storage
/// encoding.
pub fn encode_last_committed(lc: &LastCommitted) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(lc).context("encode last_committed")
}

/// Inverse of [`encode_last_committed`].
pub fn decode_last_committed(bytes: &[u8]) -> anyhow::Result<LastCommitted> {
    postcard::from_bytes(bytes).context("decode last_committed")
}

/// Recover a [`HotStuffState`] by reading the persisted control-plane
/// keys from `storage`.
///
/// A fresh node state (equivalent to `HotStuffState::new(vs, genesis)`)
/// is the baseline; any of `last_voted_view`, `locked`, `high_qc` that
/// were previously persisted by [`ConsensusNode::persist_updates`] are
/// overlaid.
///
/// `pending_blocks` is re-seeded with the blocks referenced by the
/// recovered `locked` and `high_qc` (when those blocks are present in
/// durable storage — `persist_updates` writes them alongside their
/// metadata for exactly this reason). Without this, a 4-node cluster
/// whose replicas resume with divergent on-disk state can permanently
/// stall: every leader's [`boule_consensus::hotstuff::step::HotStuffCore::become_leader`] short-circuits
/// because the high-QC's parent block isn't in `pending_blocks`, so no
/// proposal ever fires and the block-sync request that would otherwise
/// fetch the missing block is never triggered (issue #206). Older
/// committed blocks remain on-demand-only — they live under
/// [`STORAGE_KEY_BLOCK_PREFIX`] and are served by the
/// `Dispatch::ServeBlock` arm via [`load_block_from_storage`] — so boot
/// stays O(1) rather than O(committed-blocks).
///
/// Missing keys are expected on a first startup and are not errors.
pub fn recover_state(
    storage: &dyn Storage,
    validator_set: ValidatorSet,
    genesis: Block,
) -> anyhow::Result<HotStuffState> {
    let boot_qc = genesis_qc(&genesis, &validator_set);
    let mut state = HotStuffState::new(validator_set, genesis);
    // Default every fresh replica to the cluster-agreed genesis QC so
    // view-1 can proceed without waiting for a cross-cluster NewView
    // round. If the replica previously persisted a fresher QC we
    // overlay that below.
    //
    // Genesis QC: dispatch verifier short-circuits at view==0 /
    // signer_count==0 (mirrors `ConsensusNode::new`). Audit
    // finding 5-1 / issue #408.
    state.high_qc = Some(VerifiedQc::unchecked(boot_qc));

    if let Some(raw) = storage
        .get(STORAGE_KEY_LAST_VOTED_VIEW)
        .context("read last_voted_view from storage")?
    {
        state.last_voted_view = decode_voted_view(&raw)?;
    }

    if let Some(raw) = storage
        .get(STORAGE_KEY_LOCKED)
        .context("read locked from storage")?
    {
        state.locked = Some(decode_locked(&raw)?);
    }

    if let Some(raw) = storage
        .get(STORAGE_KEY_HIGH_QC)
        .context("read high_qc from storage")?
    {
        // Recovery from our own durable storage: the QC was a
        // `VerifiedQc` at the time it was written by
        // `persist_updates` (every code path that lands a QC in
        // `state.high_qc` first verified it via the dispatch
        // verifier or trusted-by-construction at one of this
        // module's audited sites). Trust on read mirrors what we
        // extend to `last_voted_view` and `locked` from the same
        // store. Audit finding 5-1 / issue #408.
        state.high_qc = Some(VerifiedQc::unchecked(decode_high_qc(&raw)?));
    }

    // Re-seed `pending_blocks` with the locked / high_qc blocks plus a
    // bounded fringe of their ancestors so the safety-rule walks
    // (extension via locked, become_leader's parent lookup, the 2-chain
    // promotion walk, and the 3-chain commit walk) terminate without
    // first having to round-trip through block-sync. Genesis is already
    // in `pending_blocks`. Any block missing from storage (e.g. an older
    // snapshot adopted via NewView before the persist-with-block pairing
    // landed) is silently skipped — the existing block-sync paths still
    // cover that case.
    //
    // Walking `RECOVER_PARENT_HOPS` parents from each anchor closes
    // audit finding 4-5: the 2-chain promotion walk needs the locked
    // block's grandparent and the 3-chain commit walk needs high_qc's
    // great-grandparent, so without this the first proposal received
    // post-restart can silently fail to promote the lock for one or
    // two views before the chain refills.
    if let Some(qc) = state.high_qc.as_ref().cloned() {
        rehydrate_ancestors(storage, &mut state, qc.block_hash())?;
    }
    if let Some(locked) = state.locked {
        rehydrate_ancestors(storage, &mut state, locked.block_hash)?;
    }

    Ok(state)
}

/// Number of parent hops [`recover_state`] walks back from each of
/// `high_qc.block_hash` and `locked.block_hash` when re-seeding
/// `pending_blocks`. Set to two so the loaded fringe covers both the
/// 2-chain promotion walk (locked + grandparent) and the 3-chain
/// commit walk (high_qc + great-grandparent) on the first proposal
/// received after restart. See audit finding 4-5 / issue #412.
const RECOVER_PARENT_HOPS: usize = 2;

/// Walk up to [`RECOVER_PARENT_HOPS`] parents back from `start`,
/// loading each block from durable storage into `state.pending_blocks`.
/// Stops at genesis (`parent_hash == [0; 32]`), at a block already in
/// `pending_blocks` (its parents will be reached via that block's own
/// `header.parent_hash`), or when a block is absent from storage —
/// whichever comes first.
fn rehydrate_ancestors(
    storage: &dyn Storage,
    state: &mut HotStuffState,
    start: BlockHash,
) -> anyhow::Result<()> {
    let mut cursor = start;
    for _ in 0..=RECOVER_PARENT_HOPS {
        let parent = if let Some(b) = state.pending_blocks.get(&cursor) {
            b.header.parent_hash
        } else if let Some(block) = load_block_from_storage(storage, &cursor)? {
            let parent = block.header.parent_hash;
            state.insert_pending(block);
            parent
        } else {
            break;
        };
        if parent == [0u8; 32] {
            break;
        }
        cursor = parent;
    }
    Ok(())
}

/// Read a previously-committed block from durable storage by its
/// content-hash. Returns `Ok(None)` when the key is absent (the block
/// was never committed by this replica), `Err` only on backend errors
/// or corrupt bytes. See [`STORAGE_KEY_BLOCK_PREFIX`].
pub fn load_block_from_storage(
    storage: &dyn Storage,
    hash: &BlockHash,
) -> anyhow::Result<Option<Block>> {
    let key = block_storage_key(hash);
    match storage.get(&key)? {
        Some(raw) => Ok(Some(decode_block(&raw)?)),
        None => Ok(None),
    }
}

/// Walk the committed-chain from `tip_hash` backwards, collecting
/// blocks whose `header.height` falls inside `[from_height, to_height]`
/// (inclusive on both ends). Caps the returned vector at `cap` blocks
/// regardless of how wide the requested span is — the responder's
/// per-response budget for the bulk-range RPC (#514). Walks stop as
/// soon as the cursor's height drops below `from_height`.
///
/// Returns blocks in ascending-height order. Returns `Ok(Vec::new())`
/// when `tip_hash == [0; 32]` (no committed chain yet) or when the
/// walk finds nothing inside the range.
///
/// Storage today is keyed by content-hash — there is no height-
/// indexed key, so the walk-by-parent path is the canonical way to
/// resolve a height range. Cost is `O(tip_height - to_height + (to -
/// from) + 1)` in storage reads, which dominates `from_height` close
/// to the tip — the common catch-up case.
pub fn load_block_range_from_storage(
    storage: &dyn Storage,
    tip_hash: BlockHash,
    from_height: Height,
    to_height: Height,
    cap: usize,
) -> anyhow::Result<Vec<Block>> {
    if from_height > to_height || cap == 0 {
        return Ok(Vec::new());
    }
    if tip_hash == [0u8; 32] {
        return Ok(Vec::new());
    }
    let mut collected: Vec<Block> = Vec::new();
    let mut cursor = tip_hash;
    loop {
        let block = match load_block_from_storage(storage, &cursor)? {
            Some(b) => b,
            None => break,
        };
        let h = block.header.height;
        if h < from_height {
            break;
        }
        let parent = block.header.parent_hash;
        if h <= to_height {
            collected.push(block);
            if collected.len() >= cap {
                break;
            }
        }
        // Sentinel for genesis: parent_hash on a genesis block is
        // (by convention) something that does not resolve to another
        // block. The next iteration's load_block_from_storage will
        // return None and we exit cleanly.
        if h == Height::ZERO {
            break;
        }
        cursor = parent;
    }
    // Walked tip → from, so `collected` is descending. Reverse for
    // ascending wire order.
    collected.reverse();
    Ok(collected)
}

/// Extract a fresh `BlsKeyHistory` containing only the genesis
/// (`v_eff = 0`) entries of `loaded`. Used by the recovery rebuild
/// path (#325 PR B) as the seed for replaying the chain's BLS
/// rotations: we can't trust the loaded history's later entries
/// (those are exactly what the rebuild is verifying), but the
/// genesis entries are cross-checked at the genesis iteration
/// against the genesis block's stamped `validator_history_commitment`.
/// If those entries are tampered with, the very first iteration of
/// the walk fires the mismatch error.
pub(super) fn genesis_only_bls_seed(
    loaded: &boule_consensus::bls_key_history::BlsKeyHistory,
) -> boule_consensus::bls_key_history::BlsKeyHistory {
    use boule_consensus::bls_key_history::{
        BlsKeyHistory, PersistedBlsKeyEntry, PersistedBlsKeyHistory, PersistedBlsValidator,
    };
    let persisted = loaded.to_persisted();
    let genesis_only = PersistedBlsKeyHistory {
        validators: persisted
            .validators
            .into_iter()
            .filter_map(|v| {
                let mut v0_entries: Vec<PersistedBlsKeyEntry> = v
                    .entries
                    .into_iter()
                    .filter(|e| e.v_eff == View::ZERO)
                    .collect();
                if v0_entries.is_empty() {
                    // Reconfig-added validator (no genesis entry).
                    // Don't seed it — the rebuild will add it back via
                    // the corresponding reconfig command at its
                    // `v_eff` block. If the loaded history has a
                    // genesis-time entry the chain didn't actually
                    // produce (or the chain produced one this
                    // tampering removed), the per-block commitment
                    // check fires at the relevant iteration.
                    None
                } else {
                    // Genesis entry only — strip any later entries.
                    v0_entries.truncate(1);
                    Some(PersistedBlsValidator {
                        stable_id: v.stable_id,
                        entries: v0_entries,
                    })
                }
            })
            .collect(),
    };
    BlsKeyHistory::from_persisted(genesis_only)
        .expect("genesis-only BLS seed has valid invariants by construction")
}

impl ConsensusNode {
    /// Walk the persisted committed-block chain from genesis to the
    /// last-committed tip, rebuilding the validator histories from
    /// each block's reconfig and rotation commands, and assert that
    /// the rebuilt histories match what's currently loaded into this
    /// node from storage.
    ///
    /// **Audit goal (#325 PR B / 7-F2 anti-rollback)**: a corrupted
    /// or rolled-back persisted history blob — for instance, an
    /// attacker who flipped a byte in a boundary's `v_eff` to seat a
    /// validator early, or replaced the genesis member list — must be
    /// rejected at startup before consensus signs anything against
    /// the rolled-back state. This method is the gate.
    ///
    /// Two checks run together:
    ///
    /// 1. **Per-block commitment cross-check** (defense-in-depth):
    ///    each block's
    ///    [`boule_consensus::replication::block::BlockHeader::validator_history_commitment`]
    ///    must match the rebuild's `(set, key, bls?)` snapshot taken
    ///    *before* applying the block's commands. With PR A's
    ///    pre-block stamping semantics, this matches what the leader
    ///    actually signed at proposal time.
    /// 2. **End-of-walk equality**: after applying every block's
    ///    commands, the rebuilt persisted forms must equal the
    ///    histories loaded from storage. This is the literal audit
    ///    criterion: a tampered blob that survived the
    ///    `from_persisted` invariants will diverge here.
    ///
    /// Caller contract: invoke this **after** [`Self::with_bls_key_history`]
    /// has been wired in on BLS chains, since the BLS history is part
    /// of the commitment.
    ///
    /// Returns `Err` on any divergence. The caller propagates: the
    /// operator sees the error and the node refuses to start.
    ///
    /// # Out of scope
    ///
    /// Snapshot sync (#229) will eventually bound the walk; today it
    /// walks the entire committed chain. For chains a few thousand
    /// blocks deep this is fine (each iteration is a storage read +
    /// in-memory hash); deployments with millions of blocks may
    /// notice startup latency. Acceptable until #229 lands.
    pub fn verify_persisted_history_consistency(&self) -> anyhow::Result<()> {
        use boule_consensus::history_commitment::{
            apply_reconfig_commands_to_set_history, apply_rotation_commands_to_histories,
            validator_history_commitment_v1,
        };
        use boule_consensus::validator_history::ValidatorSetHistory;
        use boule_consensus::validator_key_history::ValidatorKeyHistory;

        // Locate the chain tip from storage. Empty-tip = no blocks
        // committed yet (fresh boot or freshly reset storage); the
        // genesis-only triple in memory is trivially consistent with
        // a zero-block chain, so there's nothing to walk.
        let last_committed = match self
            .storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .context("read last_committed from storage")?
        {
            Some(raw) => decode_last_committed(&raw)?,
            None => return Ok(()),
        };
        if last_committed.height == Height::ZERO {
            // No committed blocks past genesis; nothing to walk.
            return Ok(());
        }

        // Walk backward from the tip to genesis, collecting blocks.
        // The walk uses each block's `parent_hash` link, same as
        // block-sync. Genesis is found either:
        //
        //  - in the in-memory `pending_blocks` (where
        //    [`HotStuffState::new`] always pre-seeds it), or
        //  - in storage at the `consensus/block/<genesis_hash>` key, if
        //    the safety core's `persist_updates` ever wrote it (which
        //    happens whenever a Locked / HighQc references genesis).
        //
        // We accept either source — both paths share the same hash so
        // the rebuilt chain anchors on the same content. Failing to
        // find genesis is an error (unreachable on a healthy chain
        // because the chain head's parent walk must terminate at
        // `genesis_hash`).
        let configured_genesis_hash = self.core.state().genesis_hash;
        let mut chain: Vec<Block> = Vec::new();
        let mut cursor = last_committed.last_committed_hash;
        loop {
            let block = if cursor == configured_genesis_hash {
                // Prefer the in-memory genesis (always present at
                // recover time) over a storage lookup. This keeps the
                // walk working even on tests that don't bother
                // persisting genesis under STORAGE_KEY_BLOCK_PREFIX.
                if let Some(g) = self.core.state().pending_blocks.get(&cursor).cloned() {
                    g
                } else if let Some(g) = load_block_from_storage(self.storage.as_ref(), &cursor)? {
                    g
                } else {
                    anyhow::bail!(
                        "validator history rebuild: genesis block at hash {} missing from both \
                         pending_blocks and storage — this should be unreachable on a healthy \
                         restart",
                        hex::encode(cursor),
                    );
                }
            } else {
                match load_block_from_storage(self.storage.as_ref(), &cursor)? {
                    Some(block) => block,
                    None => {
                        // The backward walk reached a committed block that
                        // `block_retention_window` has pruned from storage. On
                        // a chain longer than the retention window this is the
                        // *expected* state, not tampering — we simply can't
                        // rebuild the validator history all the way to genesis
                        // to cross-check it. Skip this best-effort anti-rollback
                        // verification (trusting the persisted history blob for
                        // the pruned prefix) rather than refusing to start: a
                        // node must be able to restart after retention has
                        // pruned old blocks. Full coverage would require never
                        // pruning reconfig-boundary blocks (a follow-up).
                        tracing::warn!(
                            target: TRACE_TARGET,
                            pruned_hash = %hex::encode(cursor),
                            "validator-history consistency check skipped: committed chain pruned \
                             below the retention window; trusting the persisted history for the \
                             pruned prefix",
                        );
                        return Ok(());
                    }
                }
            };
            let is_genesis = block.header.height == Height::ZERO;
            let parent = block.header.parent_hash;
            chain.push(block);
            if is_genesis {
                break;
            }
            cursor = parent;
        }
        chain.reverse();

        // Genesis bookkeeping: the first block of the rebuilt chain
        // must be the same genesis configured into this node. If
        // not, the persisted block store has been replaced wholesale
        // — we'd rather refuse than splice an alien chain onto our
        // identity.
        let walked_genesis_hash = chain
            .first()
            .expect("non-empty chain by virtue of last_committed.height > 0")
            .hash();
        if walked_genesis_hash != configured_genesis_hash {
            anyhow::bail!(
                "validator history rebuild: walked-chain genesis hash {} does not match \
                 configured genesis hash {} — persisted block store may be from a \
                 different chain",
                hex::encode(walked_genesis_hash),
                hex::encode(configured_genesis_hash),
            );
        }

        // Seed the rebuild from the loaded `validator_history`'s
        // genesis (`v_eff = 0`) boundary. We deliberately do *not*
        // re-derive from `self.validator_set` because that's the
        // *current* (latest-boundary) set after recovery — which
        // would differ from the genesis members on any chain that
        // has already committed a reconfig.
        //
        // Trusting the loaded blob's genesis boundary is safe even
        // under tampering: if those members are wrong, the very
        // first iteration of the walk below computes a commitment
        // over the tampered seed and compares against the genesis
        // *block*'s stamped commitment (which was hashed over the
        // *real* members at chain birth). The mismatch fires the
        // rejection.
        let genesis_members: Vec<boule_consensus::validator_set::ValidatorId> = self
            .validator_history
            .iter()
            .next()
            .map(|(_, set)| set.iter().copied().collect())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator history rebuild: loaded validator_history is empty (no genesis \
                     boundary)"
                )
            })?;
        let genesis_seed_set = ValidatorSet::new(genesis_members);
        let _ = chain.first().expect("non-empty chain"); // sanity: bind drops when block-walked is non-empty
        let mut rebuilt_set = ValidatorSetHistory::from_genesis(genesis_seed_set.clone());
        let mut rebuilt_key = ValidatorKeyHistory::new(genesis_seed_set.iter().copied());
        // BLS history seed: on a BLS chain, mirror whatever genesis
        // entries the loaded BLS history starts with. We don't have
        // the original `genesis_bls` config in hand here (it's
        // resolved by `src/node.rs` and folded into `bls_key_history`
        // via `with_bls_key_history`), so we extract the genesis
        // (`v_eff = 0`) entries from the loaded history. If the
        // loaded BLS history was tampered, the end-of-walk equality
        // check still catches it because the tampered entries flow
        // through both sides of the comparison.
        //
        // PR B refinement: instead of trusting the loaded history's
        // genesis entries, we cross-check against the genesis block's
        // stamped commitment below — the very first iteration
        // compares the rebuilt commitment (computed from the seed we
        // just constructed) against the genesis block's claim. If the
        // seed is wrong, the genesis-iteration check fires.
        let mut rebuilt_bls = self.bls_key_history.as_ref().map(genesis_only_bls_seed);

        for block in &chain {
            // #325 PR C semantics: each block's stamped commitment is
            // the **post-block** v1 hash — the histories *after*
            // applying this block's reconfig/rotation commands. So
            // apply first, then hash, then compare. Genesis is a
            // no-op for the apply step (zero commands), and its
            // stamped commitment equals the genesis-seed hash, so
            // the comparison still holds at N=0.
            apply_reconfig_commands_to_set_history(
                block,
                &mut rebuilt_set,
                &mut rebuilt_key,
                self.signature_scheme,
                self.min_v_eff_delay,
                &self.chain_id,
            );
            apply_rotation_commands_to_histories(
                block,
                &rebuilt_set,
                &mut rebuilt_key,
                rebuilt_bls.as_mut(),
                Some(&self.operator_key_history),
                &self.chain_id,
                self.signature_scheme,
            );
            let claimed = block.header.validator_history_commitment;
            let actual =
                validator_history_commitment_v1(&rebuilt_set, &rebuilt_key, rebuilt_bls.as_ref());
            if claimed != actual {
                anyhow::bail!(
                    "validator_history_commitment mismatch at block height={} view={} hash={}: \
                     block claims {} but rebuild from chain produces {} — persisted history \
                     blob may be tampered or rolled back (audit #325/7-F2)",
                    block.header.height,
                    block.header.view,
                    hex::encode(block.hash()),
                    hex::encode(claimed),
                    hex::encode(actual),
                );
            }
        }

        // End-of-walk equality: the loaded blobs must match the
        // rebuild byte-for-byte. This is the literal audit criterion.
        let loaded_set_persisted = self.validator_history.to_persisted();
        let rebuilt_set_persisted = rebuilt_set.to_persisted();
        if loaded_set_persisted != rebuilt_set_persisted {
            anyhow::bail!(
                "validator_history_rebuild_mismatch: loaded validator_history does not match \
                 rebuild from chain — persisted blob may be tampered. \
                 loaded boundary_count={} rebuilt boundary_count={}",
                loaded_set_persisted.boundaries.len(),
                rebuilt_set_persisted.boundaries.len(),
            );
        }
        let loaded_key_persisted = self.validator_key_history.to_persisted();
        let rebuilt_key_persisted = rebuilt_key.to_persisted();
        if loaded_key_persisted != rebuilt_key_persisted {
            anyhow::bail!(
                "validator_key_history_rebuild_mismatch: loaded validator_key_history does not \
                 match rebuild from chain — persisted blob may be tampered. \
                 loaded validators={} rebuilt validators={}",
                loaded_key_persisted.validators.len(),
                rebuilt_key_persisted.validators.len(),
            );
        }
        match (self.bls_key_history.as_ref(), rebuilt_bls.as_ref()) {
            (Some(loaded), Some(rebuilt)) => {
                let lp = loaded.to_persisted();
                let rp = rebuilt.to_persisted();
                if lp != rp {
                    anyhow::bail!(
                        "bls_key_history_rebuild_mismatch: loaded bls_key_history does not \
                         match rebuild from chain — persisted blob may be tampered. \
                         loaded validators={} rebuilt validators={}",
                        lp.validators.len(),
                        rp.validators.len(),
                    );
                }
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!(
                    "bls_key_history_rebuild_mismatch: BLS history present/absent mismatch \
                     between loaded and rebuild — chain scheme inconsistency",
                );
            }
        }

        Ok(())
    }

    /// Durably record a slice of [`StateUpdate`]s to
    /// [`ConsensusNode::storage`].
    ///
    /// Every update is applied inside a single atomic batch: on success
    /// every key is visible, on failure none are. If the same logical
    /// key appears multiple times in `updates`, the last write wins —
    /// this matches the safety-core's emission order, where freshly
    /// emitted updates semantically supersede earlier ones within the
    /// same `step`.
    ///
    /// The integration event loop (Phase D) must call this for every
    /// `Action::Persist` **before** forwarding any `Action::Broadcast` /
    /// `Action::Commit` that depends on the persisted state. That
    /// ordering is the durability discipline HotStuff
    /// safety requires — a crash between "send vote" and "write
    /// `last_voted_view`" would otherwise let a restarted replica vote
    /// twice at the same view.
    ///
    /// In addition to the metadata write, every persisted `Locked` /
    /// `HighQc` carries the *block* it references into durable storage
    /// (under [`STORAGE_KEY_BLOCK_PREFIX`]) when that block is currently
    /// in the safety core's `pending_blocks`. Without this, a divergent
    /// resume could leave the cluster permanently stalled: the leader
    /// would have a `high_qc` but no parent block in `pending_blocks`,
    /// so [`boule_consensus::hotstuff::step::HotStuffCore::become_leader`] would silently return an
    /// empty action set and no proposal would ever fire — preventing
    /// even the block-sync request that would otherwise repopulate the
    /// chain. Persisting the block alongside its referencing QC closes
    /// that gap so [`recover_state`] can re-seed `pending_blocks` with
    /// exactly the blocks the safety walks need to terminate. See
    /// issue #206.
    pub fn persist_updates(&self, updates: &[StateUpdate]) -> anyhow::Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        // Pre-encode the block writes for any `Locked` / `HighQc` whose
        // referenced block is still in `pending_blocks`. Done outside
        // the storage batch so a `?` on encoding doesn't poison the
        // batch closure.
        let mut block_writes: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for u in updates {
            let hash = match u {
                StateUpdate::HighQc(qc) => qc.block_hash,
                StateUpdate::Locked(locked) => locked.block_hash,
                StateUpdate::VotedInView { .. } | StateUpdate::ProposedInView { .. } => continue,
            };
            if let Some(block) = self.core.state().pending_blocks.get(&hash) {
                let bytes = encode_block(block)?;
                block_writes.push((block_storage_key(&hash), bytes));
            }
        }
        self.storage.batch(|b| {
            for u in updates {
                match u {
                    StateUpdate::VotedInView { view } => {
                        let bytes = encode_voted_view(*view)?;
                        b.put(STORAGE_KEY_LAST_VOTED_VIEW, &bytes);
                    }
                    StateUpdate::Locked(locked) => {
                        let bytes = encode_locked(locked)?;
                        b.put(STORAGE_KEY_LOCKED, &bytes);
                    }
                    StateUpdate::HighQc(qc) => {
                        let bytes = encode_high_qc(qc)?;
                        b.put(STORAGE_KEY_HIGH_QC, &bytes);
                    }
                    StateUpdate::ProposedInView { view } => {
                        let bytes = encode_proposed_in_view(*view)?;
                        b.put(STORAGE_KEY_PROPOSED_IN_VIEW, &bytes);
                    }
                }
            }
            for (key, bytes) in &block_writes {
                b.put(key, bytes);
            }
            Ok(())
        })?;
        // After durable writes succeed, populate the in-memory QC cache
        // so the snapshot creation hook (in `apply_commit`) can find a
        // QC over each committed block. Done after the batch commits so
        // a backend error can't leave the cache holding entries that
        // never made it to disk.
        for u in updates {
            if let StateUpdate::HighQc(qc) = u {
                self.recent_qcs
                    .lock()
                    .insert(qc.block_hash, qc.clone(), RECENT_QC_CACHE_CAPACITY);
            }
        }
        let kinds: Vec<&'static str> = updates.iter().map(super::update_kind).collect();
        tracing::debug!(
            target: TRACE_TARGET,
            kinds = ?kinds,
            blocks_persisted = block_writes.len(),
            "persisted",
        );
        Ok(())
    }
}
