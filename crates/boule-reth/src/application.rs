//! `RethApplication` — the consensus [`Application`] backed by reth.
//!
//! One boule block carries exactly one command: the opaque EVM execution
//! payload reth built. The mapping, under the deferred-execution model:
//!
//! - [`Application::build_proposal`] (leader) asks reth to build a payload on
//!   the parent block's EVM head and registers it so later builds can chain
//!   on it before it commits (HotStuff pipelining). The boule header's
//!   `state_commitment` is the payload's post-state root; the lagged
//!   `committed_state_root` is reth's committed-frontier root, which every
//!   honest replica reproduces and the QC therefore attests to.
//! - [`Application::commit`] (every node) executes and finalizes the payload
//!   (`newPayloadV3` + `forkchoiceUpdatedV3`), then advances the committed
//!   frontier.
//! - [`Application::check`] is stateless: the command must decode to a
//!   payload carrying a block hash.
//! - [`Application::state_commitment`] is the committed-frontier EVM root.
//! - [`Application::snapshot`]/[`Application::restore`] carry the committed
//!   `(height, root)` only. reth owns the world state in its own database, so
//!   a joiner needs reth's state-sync to execute — a consensus snapshot
//!   cannot reconstruct it. This is a deliberate stub for the single-node
//!   path; full reth state-sync is out of scope.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::reconfig::ReconfigCommand;
use boule_consensus::replication::application::{
    AppContext, Application, CommitResult, IntegrationCapability, ValidatorEffect, ValidatorUpdate,
};
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::stake_source::StakeSource;
use boule_consensus::validator_rotation::DualSignedRotation;
use boule_consensus::{Height, View};
use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;
use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::Value;

use crate::engine::{ElStatus, RethEngine, root_from_hex};
use crate::transport::EngineTransport;
use crate::{endpoint, governance, param, registry, rotation, slashing, staking};

/// Max boule system txs to pull from the mempool into one proposal. Only a
/// single reconfig is ever pending (the one-reconfig-at-a-time rule), so this
/// just bounds the scan.
const SYSTEM_TX_LIMIT: usize = 16;

/// The committed frontier reth has executed and finalized: the height of the
/// last committed boule block and its EVM post-state root.
struct Committed {
    height: Height,
    state_root: [u8; 32],
}

/// A consensus [`Application`] that orders and executes EVM payloads via reth.
pub struct RethApplication {
    transport: Box<dyn EngineTransport>,
    self_id: NodeId,
    fee_recipient: String,
    /// reth's genesis block hash — the EVM parent of the first built block.
    reth_genesis_hash: String,
    /// Pause between `forkchoiceUpdatedV3(attrs)` and `getPayloadV3` so reth's
    /// async build can pull pool transactions in before the payload is sealed.
    build_wait: Duration,
    committed: Mutex<Committed>,
    /// Validator-set source-of-truth (#654/#655). The CL-native ledger fed by
    /// the staking predeploy's `Deposit`/`Withdraw` events, which `commit`
    /// reads from each executed block. Seeded from the genesis validator set.
    stake_source: Mutex<Box<dyn StakeSource>>,
    /// boule's mempool, shared with the integration layer. `build_proposal`
    /// pulls pending consensus-layer system txs (reconfig/rotation) from it
    /// into the block — the only path for them onto the reth backend.
    mempool: Arc<dyn Mempool>,
    /// Seated-weight deltas committed but **not yet mirrored through the EL**
    /// (#791 Part B). Weight changes come from a block's *execution* logs, so
    /// they are only known after `commit` — too late for that block's own
    /// `extra_data`. They are therefore staged here at `commit` and carried in
    /// the **next** block's `registryPayload` (an intrinsic one-block lag of
    /// deriving the delta from execution). `commit` reconciles the buffer against each
    /// committed block's `extra_data` (decoding the weights it already mirrored)
    /// so nothing is carried twice and nothing leaks across leader rotation.
    /// Keyed by validator so a later delta for the same validator supersedes an
    /// earlier pending one (the absolute weight is what the EL applies).
    pending_weights: Mutex<std::collections::BTreeMap<NodeId, u64>>,
}

impl RethApplication {
    /// `genesis_root` is reth's genesis state root, which must equal the
    /// consensus genesis block's `state_commitment` — the caller verifies that
    /// bridge at startup. `reth_genesis_hash` is reth's genesis block hash, the
    /// EVM parent of the first proposed block.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport: Box<dyn EngineTransport>,
        self_id: NodeId,
        fee_recipient: impl Into<String>,
        reth_genesis_hash: impl Into<String>,
        genesis_root: [u8; 32],
        build_wait: Duration,
        stake_source: Box<dyn StakeSource>,
        mempool: Arc<dyn Mempool>,
    ) -> Self {
        Self {
            transport,
            self_id,
            fee_recipient: fee_recipient.into(),
            reth_genesis_hash: reth_genesis_hash.into(),
            build_wait,
            committed: Mutex::new(Committed {
                height: Height::ZERO,
                state_root: genesis_root,
            }),
            stake_source: Mutex::new(stake_source),
            mempool,
            pending_weights: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn engine(&self) -> RethEngine<'_> {
        RethEngine::new(&*self.transport, self.fee_recipient.clone())
    }

    /// Compute the A1 EL-applied registry write set (#781/#783) the leader
    /// carries to the custom EL on the build attributes for the block at `view`.
    ///
    /// This is the **sole** registry write path: the EL applies the carried set
    /// as `recordKey`/`recordWeight`/`recordSettled` system calls at the block
    /// boundary on every replica. Sourced from boule's authoritative consensus
    /// state:
    ///
    /// - **`settledView`** — [`registry::conservative_settled_view`]`(view)`, the
    ///   conservative frontier (#767) held [`registry::SETTLED_VIEW_MARGIN`]
    ///   views behind the committed view. The primary, near-always-present field;
    ///   on the common no-rotation block it is the *only* one, keeping the carried
    ///   `extra_data` to a handful of bytes. `None` below the margin (genesis
    ///   frontier is already 0). The margin remains as harmless defense: a
    ///   rotation effective at view `V` commits its `recordKey` in the SAME block
    ///   the EL applies it, but `settledView` never reaches `V` until `MARGIN`
    ///   views later, so the slashing predeploy never reads ahead of a recorded
    ///   key by construction.
    /// - **`keys`** — the BLS-key rotations this block materializes: each
    ///   rotation system tx the leader is including (`system_cmds`, the same
    ///   commands it pulls into the block) decoded via
    ///   [`registry::record_key_for_rotation`] into the EL's 128-byte EIP-2537
    ///   form. Non-BLS / undecodable commands are skipped (logged), never failing
    ///   the build.
    /// - **`weights`** — the seated-weight deltas committed but not yet mirrored
    ///   through the EL (#791 Part B). A weight change is a function of a block's
    ///   *execution* logs, so it is only known after that block's `commit` — too
    ///   late for its own `extra_data`. We therefore stage each block's deltas in
    ///   [`Self::pending_weights`] at `commit` and carry the pending set in the
    ///   **next** block's payload here (an intrinsic one-block lag of deriving the
    ///   delta from execution, not the retired tx path). Snapshotting (not
    ///   draining) the buffer keeps the build idempotent if the proposal is
    ///   skipped; `commit` is what clears a delta, once it sees a committed block's
    ///   `extra_data` already mirrored it. In a consensus-canonical order (by
    ///   validator id, via the `BTreeMap`).
    ///
    /// Determinism across replicas does not depend on this sourcing: the EL reads
    /// the write set from the *sealed header* `extra_data` on every node's verify
    /// path, so the leader's job is only to mirror authoritative state. Holding
    /// the set in a consensus-canonical order keeps the encoded bytes stable.
    fn registry_payload_for_build(
        &self,
        view: View,
        system_cmds: &[Bytes],
    ) -> crate::registry_payload::RegistryPayload {
        let settled = registry::conservative_settled_view(view);
        let settled_view = if settled.0 == 0 { None } else { Some(settled) };

        let mut keys = Vec::new();
        for cmd in system_cmds {
            match registry::record_key_for_rotation(cmd) {
                Ok(Some(rk)) => keys.push(rk),
                Ok(None) => {} // not a BLS-key rotation — nothing to mirror
                Err(e) => tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    "EL registry write: undecodable rotation command at build; skipping recordKey",
                ),
            }
        }

        // Snapshot the pending seated-weight deltas (committed, not yet
        // EL-mirrored). The `BTreeMap` gives a stable per-validator order.
        let weights: Vec<ValidatorUpdate> = self
            .pending_weights
            .lock()
            .iter()
            .map(|(&node_id, &weight)| ValidatorUpdate { node_id, weight })
            .collect();

        crate::registry_payload::RegistryPayload::new(keys, &weights, settled_view)
    }

    /// #797 — the vote-time integrity gate for the EL-applied registry write
    /// set. Re-derive the registry `extra_data` the leader **should** have
    /// stamped into this proposed `block`, from boule's own authoritative
    /// consensus state, and compare it to what the proposal actually carries.
    /// `Err` (→ refuse to vote) on any mismatch a validator can independently
    /// detect at vote time. Run on every non-leader before voting; an honest
    /// leader's payload always re-derives identically, so the honest path is
    /// unaffected.
    ///
    /// # What is vote-time-validated vs. only commit-time-detected
    ///
    /// The three write-set components differ in their availability *at vote
    /// time* (a validator voting on block N may not yet have **executed** N−1
    /// under deferred execution), so they are handled separately:
    ///
    /// - **`keys`** — derived purely from the BLS-key **rotation system
    ///   commands carried in the proposed block itself** (the same
    ///   [`registry::record_key_for_rotation`] decode the builder ran on them),
    ///   so they are fully available at vote time and are **validated here**.
    ///   This closes the most dangerous attack (#797): a Byzantine leader can no
    ///   longer forge an honest validator's `keyAt` to frame it for slashing,
    ///   because every honest voter re-derives the keys from the same commands
    ///   and rejects a forged key record.
    /// - **`settledView`** — deterministic from the block's `view`
    ///   ([`registry::conservative_settled_view`]), so it is available at vote
    ///   time and **validated here**.
    /// - **`weights`** — derived from the seated-weight deltas of a *prior*
    ///   block's **execution** (staking/slashing events), carried with a
    ///   one-block lag via [`Self::pending_weights`], which is mutated only at
    ///   [`Self::commit`] once the EL reports the relevant block `VALID`. A
    ///   voter on block N may not yet have executed the block whose deltas N's
    ///   weights mirror (or its EL may still be `SYNCING`), so its
    ///   `pending_weights` is **not guaranteed** to match the leader's at build
    ///   time. We therefore do **not** re-derive-and-reject weights here (that
    ///   would risk honest validators rejecting an honest leader's correct
    ///   weights purely from an execution-lag skew, a liveness hole). Weight
    ///   integrity is instead enforced at **commit** by
    ///   [`Self::detect_weight_extra_data_divergence`], which — once this node
    ///   has itself executed and re-derived the expected weights — compares them
    ///   to the committed block's `extra_data` and logs a hard
    ///   `BFT-SAFETY-VIOLATION` on mismatch. This is **detect-after-final**, not
    ///   vote-time prevention: see that method and #797's residual note.
    ///
    /// So after this fix: forged **keys** and **settledView** are *prevented*
    /// (never voted for, never committed); a forged **weight** is *detected*
    /// (and loudly surfaced) at commit but, given the genuine execution lag, is
    /// not yet vote-time-rejected.
    fn validate_registry_extra_data(&self, block: &Block) -> Result<()> {
        // Pull the proposal's EVM execution payload (always the first command)
        // and decode the registry write set the leader stamped into its
        // `extra_data`. A genesis/empty block carries no command and nothing to
        // validate.
        let Some(cmd) = block.commands.first() else {
            return Ok(());
        };
        let payload: Value = serde_json::from_slice(cmd)
            .context("proposed block command is not a JSON execution payload")?;
        let proposed = extra_data_registry_payload(&payload);

        // Re-derive the keys + settledView we expect, from the proposal's own
        // rotation commands and view — both available at vote time.
        let expected_keys = registry_keys_from_commands(&block.commands);
        let expected_settled = {
            let settled = registry::conservative_settled_view(block.header.view);
            if settled.0 == 0 { None } else { Some(settled) }
        };

        // The proposal's view of those same two fields (defaulting to "no
        // registry payload" for a plain block, which must carry no keys / no
        // settled-view).
        let proposed_keys = proposed
            .as_ref()
            .map(|p| p.keys.clone())
            .unwrap_or_default();
        let proposed_settled = proposed.as_ref().and_then(|p| p.settled_view);

        if proposed_keys != expected_keys {
            anyhow::bail!(
                "registry extra_data key mismatch (#797): proposal carries {} key record(s), \
                 our independent re-derivation expects {}; refusing to vote",
                proposed_keys.len(),
                expected_keys.len(),
            );
        }
        if proposed_settled != expected_settled {
            anyhow::bail!(
                "registry extra_data settledView mismatch (#797): proposal carries {:?}, \
                 we expect {:?}; refusing to vote",
                proposed_settled.map(|v| v.0),
                expected_settled.map(|v| v.0),
            );
        }

        // Weights are deliberately NOT rejected here — see the method doc on the
        // execution-lag residual; commit-time detection covers them.
        Ok(())
    }

    /// #797 (weight residual) — commit-time detection of a forged seated-weight
    /// delta in a committed block's `extra_data`. Called from [`Self::commit`]
    /// **after** this node has executed the block and re-staged its
    /// pending-weight buffer, so the weights we *expect* this block to have
    /// carried are exactly the deltas that were pending when it was built. Any
    /// difference means a Byzantine proposer forged a `recordWeight` the EL has
    /// now already applied (the block is BFT-final), so this can only **detect
    /// and loudly surface** it — it is too late to prevent. Logged at `error`
    /// with a `BFT-SAFETY-VIOLATION` marker an operator/alert can trip on;
    /// returns `true` when a divergence was found.
    ///
    /// This is the honest residual of #797: keys + settledView are vote-time-
    /// *prevented* ([`Self::validate_registry_extra_data`]); weights, which a
    /// voter cannot reliably re-derive at vote time under deferred execution,
    /// are only *detected* here. Making weights vote-time-derivable is a
    /// follow-up design change (see the issue).
    fn detect_weight_extra_data_divergence(&self, payload: &Value, height: Height) -> bool {
        let carried: Vec<(NodeId, u64)> = extra_data_registry_payload(payload)
            .map(|p| p.weights)
            .unwrap_or_default();
        // The deltas this block *should* have carried: the buffer as it stood
        // before this commit re-staged it. We reconstruct that "expected"
        // multiset from the carried set being a subset of what we would have
        // had pending — but the precise check we can afford here is: every
        // weight the block claims must be one we actually have pending (i.e. one
        // a prior commit on THIS node derived from execution). A weight the
        // proposer invented out of thin air is not in our pending buffer.
        let pending = self.pending_weights.lock();
        let mut diverged = false;
        for (validator, weight) in &carried {
            if pending.get(validator) != Some(weight) {
                diverged = true;
                tracing::error!(
                    target: "boule::reth",
                    height = height.0,
                    validator = %hex::encode(validator),
                    carried_weight = weight,
                    our_pending = ?pending.get(validator),
                    "BFT-SAFETY-VIOLATION (#797): committed block's extra_data carried a \
                     seated-weight delta this node did not derive from execution — a Byzantine \
                     proposer may have forged a recordWeight (block is already final; detected, \
                     not prevented)",
                );
            }
        }
        diverged
    }

    /// #791 Part B — keep the [`Self::pending_weights`] buffer correct across a
    /// commit. First **drop** the seated-weight deltas this committed block's
    /// sealed `extra_data` already mirrored through the EL (decoded from the
    /// committed execution payload's `extraData`), then **stage** this block's
    /// freshly-derived deltas so they ride the next block's `extra_data`.
    ///
    /// A pending entry is removed only when the *committed* block carried the
    /// exact `(validator, weight)` it still holds — a stale pending value that has
    /// since been superseded by a newer delta is left in place to be re-carried.
    /// Staging overwrites per validator (the absolute weight is what the EL
    /// applies), so the buffer holds at most one entry per validator. Run on every
    /// replica, off authoritative committed state, so it is deterministic.
    fn reconcile_pending_weights(&self, payload: &Value, new_updates: &[ValidatorUpdate]) {
        let carried = payload["extraData"]
            .as_str()
            .map(|s| s.trim_start_matches("0x"))
            .and_then(|s| hex::decode(s).ok())
            .and_then(|bytes| crate::registry_payload::RegistryPayload::decode(&bytes))
            .map(|p| p.weights)
            .unwrap_or_default();

        let mut pending = self.pending_weights.lock();
        // Drop only deltas the committed block actually mirrored (same value),
        // so a superseded-then-replaced pending value survives to be re-carried.
        for (validator, weight) in carried {
            if pending.get(&validator) == Some(&weight) {
                pending.remove(&validator);
            }
        }
        // Stage this block's new deltas (overwrites supersede per validator).
        for u in new_updates {
            pending.insert(u.node_id, u.weight);
        }
    }

    /// Read the staking predeploy's `Deposit`/`Withdraw` events *and* the
    /// slashing predeploy's `Slashed` events for the just-executed `payload`,
    /// apply them to the CL-native stake ledger, and return the validator-set
    /// deltas (#655 staking + #732/#658b slashing). Only called once the EL
    /// reports the payload `VALID`, so its logs are available. A failed
    /// `eth_getLogs` is logged and yields no updates for that category — a
    /// transient RPC error must not fail the commit (consensus commits
    /// regardless of the EL).
    async fn derive_validator_updates(
        &self,
        payload: &Value,
        height: Height,
    ) -> Vec<ValidatorUpdate> {
        let block_hash = payload["blockHash"].as_str();
        // Read this block's staking events (empty on any failure — the height
        // still advances so unbondings mature, #660).
        let ops = match block_hash {
            Some(block_hash) => match self
                .transport
                .eth_rpc("eth_getLogs", staking::logs_filter(block_hash))
                .await
            {
                Ok(logs) => staking::parse_stake_logs(&logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        error = %e,
                        "eth_getLogs for staking events failed; no staking ops this block",
                    );
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        // Read this block's `Slashed` events — the slashing predeploy verified
        // each equivocation in the EVM (#732) and only signals; boule applies
        // the penalty here, burning the equivocator's bonded stake (#658b).
        let slashed = match block_hash {
            Some(block_hash) => match self
                .transport
                .eth_rpc("eth_getLogs", slashing::logs_filter(block_hash))
                .await
            {
                Ok(logs) => slashing::parse_slashed_logs(&logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        error = %e,
                        "eth_getLogs for slashing events failed; no slashes this block",
                    );
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        let mut src = self.stake_source.lock();
        // Advance the ledger clock first (releases matured unbondings, #660),
        // then apply this block's ops so their unbonding release is scheduled
        // relative to this height.
        src.advance_to_height(height);
        for (node_id, op) in ops {
            src.apply(node_id, op);
        }
        // Slash after advancing the clock so the equivocator's still-locked
        // unbonding stake is burned too (matured stake is no longer slashable,
        // #660). The resulting `weight 0` removals drain alongside the staking
        // deltas — the integration layer materialises them into one reconfig,
        // merging with the membership jail (#658a).
        for node_id in slashed {
            src.slash(node_id);
        }
        src.take_updates()
    }

    /// Read this block's submission-predeploy events for one category and turn
    /// each into a [`ValidatorEffect`]. Shared by the rotation (#730) and
    /// endpoint (#731) read paths: each predeploy carries an already-signed
    /// consensus command as the log's dynamic `bytes`, which rides straight
    /// through to consensus — the opaque command is *not* interpreted here;
    /// consensus validates the tag and signatures when it materialises the
    /// effect.
    ///
    /// Called only once the EL reports the block `VALID`, so its logs exist; a
    /// failed `eth_getLogs` is logged and yields no effects (a transient RPC
    /// error must not fail the commit — consensus commits regardless of the EL).
    ///
    /// Backfilled over EL self-synced gaps (#674) too, by EVM block number,
    /// exactly as staking is — see [`Self::backfill_self_synced_gap`]. This **is**
    /// a correctness requirement, not best-effort recovery (#772): a governance
    /// `Approved` is emitted **once per proposal** (a one-shot guard — there is no
    /// re-submit), so a `Reconfig`/rotation/endpoint/param effect dropped because
    /// `commit` self-synced past its block would never re-emit, and some replicas
    /// would apply the membership change while others did not → **silent
    /// validator-set divergence** (a safety split). A node that self-syncs past a
    /// gap must derive the byte-identical effect sequence as one that executed
    /// every block in order.
    async fn derive_predeploy_effects(
        &self,
        block_hash: &str,
        filter: Value,
        parse: fn(&Value) -> Vec<bytes::Bytes>,
        wrap: fn(bytes::Bytes) -> ValidatorEffect,
        kind: &str,
    ) -> Vec<ValidatorEffect> {
        let _ = block_hash; // the filter already embeds it; kept for symmetry
        let logs = match self.transport.eth_rpc("eth_getLogs", filter).await {
            Ok(logs) => logs,
            Err(e) => {
                tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    kind,
                    "eth_getLogs for predeploy events failed; no effects this block",
                );
                return Vec::new();
            }
        };
        parse(&logs).into_iter().map(wrap).collect()
    }

    /// This block's rotation-predeploy effects (#730).
    async fn derive_rotation_effects(&self, payload: &Value) -> Vec<ValidatorEffect> {
        let Some(block_hash) = payload["blockHash"].as_str() else {
            return Vec::new();
        };
        self.derive_predeploy_effects(
            block_hash,
            rotation::logs_filter(block_hash),
            rotation::parse_rotation_logs,
            ValidatorEffect::KeyRotation,
            "rotation",
        )
        .await
    }

    /// This block's endpoint-predeploy effects (#731).
    async fn derive_endpoint_effects(&self, payload: &Value) -> Vec<ValidatorEffect> {
        let Some(block_hash) = payload["blockHash"].as_str() else {
            return Vec::new();
        };
        self.derive_predeploy_effects(
            block_hash,
            endpoint::logs_filter(block_hash),
            endpoint::parse_endpoint_logs,
            ValidatorEffect::EndpointUpdate,
            "endpoint",
        )
        .await
    }

    /// This block's parameter-update-predeploy effects (#542 producer).
    async fn derive_param_effects(&self, payload: &Value) -> Vec<ValidatorEffect> {
        let Some(block_hash) = payload["blockHash"].as_str() else {
            return Vec::new();
        };
        self.derive_predeploy_effects(
            block_hash,
            param::logs_filter(block_hash),
            param::parse_param_logs,
            ValidatorEffect::ParamUpdate,
            "param",
        )
        .await
    }

    /// This block's governance-predeploy effects (#729): each `Approved` event
    /// carries the encoded reconfig command for an approved membership change,
    /// surfaced as a `ValidatorEffect::Reconfig`. reth never interprets the
    /// command — consensus validates the membership change and schedules it at a
    /// view boundary when it re-materialises the effect.
    async fn derive_governance_effects(&self, payload: &Value) -> Vec<ValidatorEffect> {
        let Some(block_hash) = payload["blockHash"].as_str() else {
            return Vec::new();
        };
        self.derive_predeploy_effects(
            block_hash,
            governance::logs_filter(block_hash),
            governance::parse_approved_logs,
            ValidatorEffect::Reconfig,
            "governance",
        )
        .await
    }

    /// Backfill **every validator-affecting predeploy event** of the blocks the
    /// EL executed via background self-sync (snap/full, #631) that `commit`
    /// skipped while the EL was `SYNCING` (#674): staking + slashing (the stake
    /// ledger) **and** the rotation/endpoint/param/governance submission effects
    /// (#772).
    ///
    /// When the EL reports `VALID` for a block whose height is more than one
    /// past the committed frontier, every block in the gap
    /// `(prev_height, height)` was executed by the EL out-of-band — not through
    /// `commit`, which returned early while `SYNCING` — so its predeploy events
    /// were never read. For the stake ledger that means it would silently drift
    /// from EL state; for the submission effects (rotation/endpoint/param/
    /// governance) it means committed, **one-shot** membership changes would be
    /// dropped on this node but applied on a node that executed the block →
    /// silent validator-set divergence (#772). The root self-heals via
    /// `recover_frontier`, but neither the ledger nor these effects have such a
    /// re-anchor — they must be reconciled here.
    ///
    /// Each skipped block's events are read *by canonical EVM number* — its hash
    /// is unknown on this path — and applied **at the block's own height**,
    /// exactly as the normal per-block path would, so a node that caught up via
    /// self-sync reaches the byte-identical ledger and the same effect sequence
    /// as one that committed every block in order (unbonding maturity is
    /// height-relative, #660). This relies on the
    /// one-EVM-block-per-committed-boule-block invariant: EVM block number
    /// advances 1:1 with boule height, so the block at boule height `h` has EVM
    /// number `current_number - (height - h)`.
    ///
    /// Applies staking/slashing ops to the ledger but does not drain updates —
    /// the caller's [`Self::derive_validator_updates`] for the current block
    /// drains the gap's and the current block's deltas together. Returns the
    /// gap's submission effects in ascending block order; the caller prepends
    /// them to the current block's effects so the materialised effect sequence
    /// is the same one a fully-executing node produced.
    async fn backfill_self_synced_gap(
        &self,
        payload: &Value,
        prev_height: Height,
        height: Height,
    ) -> Vec<ValidatorEffect> {
        // No gap: the frontier advanced by exactly one block (the common path).
        if height.0 <= prev_height.0 + 1 {
            return Vec::new();
        }
        let Some(current_number) = payload["blockNumber"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        else {
            tracing::warn!(
                target: "boule::reth",
                "self-sync backfill: current payload has no parseable blockNumber; \
                 skipping reconcile over the gap",
            );
            return Vec::new();
        };
        tracing::info!(
            target: "boule::reth",
            from = prev_height.0 + 1,
            to = height.0 - 1,
            "self-sync backfill: reconciling staking/slashing + submission effects over \
             EL self-synced gap",
        );
        let mut gap_effects = Vec::new();
        // Skipped boule heights, oldest first, applied/derived at their own
        // height so the effect order matches the per-block path exactly.
        for h in (prev_height.0 + 1)..height.0 {
            let evm_number = current_number - (height.0 - h);
            // Staking + slashing → the CL stake ledger (drained by the current
            // block's derive_validator_updates, alongside this block's deltas).
            let ops = match self
                .transport
                .eth_rpc("eth_getLogs", staking::logs_filter_by_number(evm_number))
                .await
            {
                Ok(logs) => staking::parse_stake_logs(&logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        height = h,
                        evm_number,
                        error = %e,
                        "self-sync backfill: eth_getLogs failed; staking events for \
                         this skipped block are lost",
                    );
                    Vec::new()
                }
            };
            let slashed = match self
                .transport
                .eth_rpc("eth_getLogs", slashing::logs_filter_by_number(evm_number))
                .await
            {
                Ok(logs) => slashing::parse_slashed_logs(&logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        height = h,
                        evm_number,
                        error = %e,
                        "self-sync backfill: eth_getLogs failed; slashing events for \
                         this skipped block are lost",
                    );
                    Vec::new()
                }
            };
            {
                let mut src = self.stake_source.lock();
                // Advance the ledger clock first (matures unbondings), then
                // apply this block's ops and slashes — same order, at the same
                // height, as the per-block derive_validator_updates path (#660).
                src.advance_to_height(Height(h));
                for (node_id, op) in ops {
                    src.apply(node_id, op);
                }
                for node_id in slashed {
                    src.slash(node_id);
                }
            }
            // Submission effects (rotation/endpoint/param/governance) → one-shot
            // ValidatorEffects that have no re-submit, so they MUST be backfilled
            // (#772). Read by EVM number; the filter embeds it (block_hash unused).
            gap_effects.extend(self.derive_gap_predeploy_effects(evm_number).await);
        }
        gap_effects
    }

    /// Derive one self-synced gap block's submission-predeploy effects by EVM
    /// block number (#772 backfill). Mirrors the per-block
    /// `derive_{rotation,endpoint,param,governance}_effects` order so a
    /// self-synced node produces the byte-identical effect sequence as one that
    /// executed the block via the normal commit path. Read by number, not hash —
    /// the gap block's hash is unknown on the self-sync path.
    async fn derive_gap_predeploy_effects(&self, evm_number: u64) -> Vec<ValidatorEffect> {
        // `derive_predeploy_effects` ignores its block_hash arg (the filter
        // already embeds the selection), so the *_logs_filter_by_number variant
        // slots straight in. Order matches the current-block path in `commit`:
        // rotation, endpoint, param, governance.
        let mut effects = self
            .derive_predeploy_effects(
                "",
                rotation::logs_filter_by_number(evm_number),
                rotation::parse_rotation_logs,
                ValidatorEffect::KeyRotation,
                "rotation (gap backfill)",
            )
            .await;
        effects.extend(
            self.derive_predeploy_effects(
                "",
                endpoint::logs_filter_by_number(evm_number),
                endpoint::parse_endpoint_logs,
                ValidatorEffect::EndpointUpdate,
                "endpoint (gap backfill)",
            )
            .await,
        );
        effects.extend(
            self.derive_predeploy_effects(
                "",
                param::logs_filter_by_number(evm_number),
                param::parse_param_logs,
                ValidatorEffect::ParamUpdate,
                "param (gap backfill)",
            )
            .await,
        );
        effects.extend(
            self.derive_predeploy_effects(
                "",
                governance::logs_filter_by_number(evm_number),
                governance::parse_approved_logs,
                ValidatorEffect::Reconfig,
                "governance (gap backfill)",
            )
            .await,
        );
        effects
    }

    /// Reconcile the committed frontier with reality on restart. `new` starts at
    /// `(0, genesis_root)`, but on a restart reth (its own persistent DB) is
    /// already at the finalized head while consensus recovers its committed
    /// height from storage — so without this the first post-restart proposal
    /// would stamp a genesis lagged `committed_state_root` and fail the
    /// deferred-root vote check. The caller passes reth's finalized
    /// `(height, state_root)` (see [`crate::fetch_finalized_head`]).
    pub fn recover_frontier(&self, height: Height, state_root: [u8; 32]) {
        let mut c = self.committed.lock();
        c.height = height;
        c.state_root = state_root;
    }

    /// The EVM `(block hash, timestamp-seconds)` to build the next block on.
    /// For the boule genesis parent (no commands) that's reth's genesis;
    /// otherwise it is read from the parent boule block's payload command.
    fn parent_evm_anchor(&self, parent: &Block) -> Result<(String, u64)> {
        match parent.commands.first() {
            None => Ok((self.reth_genesis_hash.clone(), 0)),
            Some(cmd) => {
                let payload: Value = serde_json::from_slice(cmd)
                    .context("parent block command is not a JSON execution payload")?;
                let hash = payload["blockHash"]
                    .as_str()
                    .context("parent payload blockHash")?
                    .to_string();
                let ts = payload["timestamp"]
                    .as_str()
                    .context("parent payload timestamp")?;
                let ts = u64::from_str_radix(ts.trim_start_matches("0x"), 16)
                    .context("parent payload timestamp not hex")?;
                Ok((hash, ts))
            }
        }
    }
}

/// Extract the 32-byte post-state root from an execution payload.
fn state_root_of(payload: &Value) -> Result<[u8; 32]> {
    root_from_hex(payload["stateRoot"].as_str().context("payload stateRoot")?)
}

/// Decode the boule registry write set an execution `payload` carries in its
/// `extraData`, or `None` for a plain (non-boule, default `extra_data`) block —
/// the same decode [`RethApplication::reconcile_pending_weights`] runs. Used by
/// the #797 vote-time gate and the commit-time weight check to read what a
/// proposal actually stamped, before comparing to an independent re-derivation.
fn extra_data_registry_payload(
    payload: &Value,
) -> Option<crate::registry_payload::RegistryPayload> {
    payload["extraData"]
        .as_str()
        .map(|s| s.trim_start_matches("0x"))
        .and_then(|s| hex::decode(s).ok())
        .and_then(|bytes| crate::registry_payload::RegistryPayload::decode(&bytes))
}

/// Re-derive the [`RecordKey`](crate::registry::RecordKey)s a block's
/// `extra_data` should mirror, from the **BLS-key rotation system commands in
/// the block itself** — the exact set
/// [`RethApplication::registry_payload_for_build`] feeds to the EL, in the same
/// command order. This is the #797 vote-time re-derivation for keys: it needs
/// only the proposed block (no parent, no execution), so every honest validator
/// reproduces it identically and a forged key record is rejected. A non-BLS /
/// undecodable command contributes no key (same as the build path).
fn registry_keys_from_commands(commands: &[Bytes]) -> Vec<crate::registry::RecordKey> {
    commands
        .iter()
        .filter_map(|cmd| registry::record_key_for_rotation(cmd).ok().flatten())
        .collect()
}

/// `parent` plus its uncommitted ancestors (strictly above the committed
/// frontier), walked through `pending_blocks` and returned **oldest-first**.
///
/// This is the chain a leader must make sure reth knows before it can build
/// on `parent`. The committed frontier and everything below it are already in
/// reth (commit runs `newPayloadV4`), but under HotStuff pipelining `parent`
/// and its recent ancestors may still be uncommitted — and a *rotated* leader
/// only ever **voted** on them (deferred execution: it never executed them),
/// so its reth has not seen those payloads. Registering this chain oldest-
/// first, on top of the known committed frontier, lets the build chain on
/// `parent`. The walk stops at the first block at/below `committed_height` or
/// the first parent missing from `pending_blocks` (the committed boundary).
fn uncommitted_chain<'b>(
    parent: &'b Block,
    pending_blocks: &'b HashMap<BlockHash, Block>,
    committed_height: Height,
) -> Vec<&'b Block> {
    let mut chain = Vec::new();
    let mut cursor = parent;
    while cursor.header.height.0 > committed_height.0 {
        chain.push(cursor);
        match pending_blocks.get(&cursor.header.parent_hash) {
            Some(p) => cursor = p,
            None => break,
        }
    }
    chain.reverse();
    chain
}

impl Application for RethApplication {
    fn build_proposal<'a>(
        &'a self,
        _ctx: &'a AppContext,
        parent: &'a Block,
        view: View,
        _high_qc: &'a QuorumCertificate,
        pending_blocks: &'a HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> BoxFuture<'a, Result<Block>> {
        Box::pin(async move {
            // Snapshot the committed frontier; do not hold the lock across the
            // engine round-trips below.
            let (committed_height, committed_state_root) = {
                let c = self.committed.lock();
                (c.height, c.state_root)
            };

            let (parent_evm_hash, parent_evm_ts) = self.parent_evm_anchor(parent)?;
            // EVM block time: strictly greater than the parent (EVM rule),
            // honoring the agreed consensus time (millis -> seconds).
            let evm_ts = (parent_evm_ts + 1).max(timestamp / 1000);

            let engine = self.engine();
            // Make sure reth knows the uncommitted chain we're about to build
            // on. A rotated leader may have only voted on `parent` and its
            // recent ancestors (never executed them), so register each payload
            // (`newPayloadV4`, no finalize) oldest-first before building.
            // Idempotent for blocks reth already knows; the genesis parent has
            // an empty chain. This is what makes the reth backend work across
            // leader rotation under pipelining.
            for ancestor in uncommitted_chain(parent, pending_blocks, committed_height) {
                if let Some(cmd) = ancestor.commands.first() {
                    let payload: Value = serde_json::from_slice(cmd)
                        .context("uncommitted ancestor command is not a JSON execution payload")?;
                    if engine.register_payload(&payload).await? == ElStatus::Syncing {
                        // Our EL is still syncing the uncommitted chain — it
                        // can't build on a head it doesn't have. Skip proposing
                        // this view; the EL catches up via the commit path, and
                        // a later leader (or this node once caught up) builds.
                        // Retriable: the safety core treats a build Err as a
                        // skipped proposal (#326), not a fault.
                        anyhow::bail!(
                            "reth EL still syncing the uncommitted ancestor chain (height {}); \
                             skipping proposal for view {}",
                            ancestor.header.height.0,
                            view.0,
                        );
                    }
                }
            }
            // A1 EL-applied registry writes (#781/#783): the leader computes the
            // authoritative `(keys, weights, settledView)` write set for this
            // block and hands it to the custom EL on the build attributes. The
            // EL transcribes it into the sealed header `extra_data` and applies
            // `recordKey`/`recordWeight`/`recordSettled` as system calls, so every
            // replica mirrors the identical registry state from the propagated
            // block (no proposer trust — see #777). The pulled-in rotation system
            // txs (`reconfig_cmds` below) feed the key writes; the settled view is
            // the conservative frontier. Empty for the common no-rotation block,
            // which keeps `extra_data` (and the header) small. This is the SOLE
            // registry write path — the legacy proposer-signed tx-write path in
            // `commit` was removed in Phase 3 (#783).
            let reconfig_cmds = self.mempool.propose(SYSTEM_TX_LIMIT);
            let registry_payload = self.registry_payload_for_build(view, &reconfig_cmds);
            let built = engine
                .build_block(
                    &parent_evm_hash,
                    evm_ts,
                    self.build_wait,
                    &registry_payload.to_attribute_hex(),
                )
                .await?;
            // Register immediately so a later build can chain on this block
            // before it commits (HotStuff pipelining).
            engine.register_payload(&built.execution_payload).await?;

            // The block's first command is always the EVM execution payload.
            let mut commands = vec![Bytes::from(
                serde_json::to_vec(&built.execution_payload)
                    .context("serializing the EVM execution payload")?,
            )];
            // Carry pending boule *system* txs (reconfig/rotation) from the
            // mempool too. Application transactions live in reth's own pool
            // and ride the EVM payload, but consensus-layer system txs — e.g.
            // the ReconfigCommand the staking read path mints (#655) — have no
            // other way into a block on the reth backend, since this builder
            // does not draw application commands from boule's mempool. Without
            // this, a minted reconfig would never commit. Their validity is
            // checked at commit (apply_committed_reconfigs); app commands in
            // the pool are ignored here.
            for cmd in reconfig_cmds {
                if ReconfigCommand::is_reconfig_payload(&cmd)
                    || DualSignedRotation::is_rotation_payload(&cmd)
                    || boule_consensus::validator_rotation::DualSignedRotationCancel::is_cancel_payload(&cmd)
                    || boule_consensus::validator_rotation::OperatorSignedRotation::is_operator_rotation_payload(&cmd)
                    || boule_consensus::validator_rotation::DualSignedOperatorRotation::is_operator_key_rotation_payload(&cmd)
                    // Equivocation-evidence system txs (#657): same rationale —
                    // no other path onto the reth backend; validated at commit.
                    || boule_consensus::equivocation_evidence::is_evidence_payload(&cmd)
                    // Endpoint-advertisement system txs (#731): the endpoint
                    // read path mints these; validated + applied at commit.
                    || boule_consensus::endpoint_registry::SignedEndpointCommand::is_endpoint_payload(&cmd)
                    // Consensus-parameter-update system txs (#542): the param
                    // read path mints these; validated + scheduled at commit.
                    || boule_consensus::consensus_params::ConsensusParamUpdate::is_param_update_payload(&cmd)
                {
                    commands.push(cmd);
                }
            }
            let commands_commitment = Block::commands_commitment(&commands);

            Ok(Block {
                header: BlockHeader {
                    parent_hash: parent.hash(),
                    height: parent.header.height + 1,
                    view,
                    proposer: self.self_id,
                    state_commitment: built.state_root_bytes()?,
                    commands_commitment,
                    validator_history_commitment: [0; 32],
                    committed_height,
                    committed_state_root,
                    // Clamp to the parent so block time is non-decreasing.
                    timestamp: timestamp.max(parent.header.timestamp),
                },
                commands,
            })
        })
    }

    fn commit<'a>(
        &'a self,
        _ctx: &'a AppContext,
        block: &'a Block,
    ) -> BoxFuture<'a, Result<CommitResult>> {
        Box::pin(async move {
            let Some(cmd) = block.commands.first() else {
                // Genesis / empty block: nothing to execute.
                return Ok(CommitResult::default());
            };
            let payload: Value = serde_json::from_slice(cmd)
                .context("committed block command is not a JSON execution payload")?;
            let new_root = state_root_of(&payload)?;
            let (_, status) = self.engine().commit_block(&payload).await?;
            // Submission effects derived from blocks the EL self-synced past
            // (#772). Empty unless this commit closed a gap; prepended to the
            // current block's effects below so the materialised order is the
            // same one a fully-executing node produced (ascending by height).
            let mut gap_effects: Vec<ValidatorEffect>;
            match status {
                ElStatus::Valid => {
                    // The EL executed it — advance the committed frontier,
                    // capturing the previous frontier height first so we can
                    // tell whether the EL just self-synced past a gap (#674).
                    let prev_height = {
                        let mut c = self.committed.lock();
                        let prev = c.height;
                        c.height = block.header.height;
                        c.state_root = new_root;
                        prev
                    };
                    // #674/#772: if the frontier jumped by more than one block,
                    // the EL executed the in-between blocks via background
                    // self-sync (not through `commit`). Read their staking +
                    // slashing events now so the CL stake ledger doesn't drift
                    // from EL state, and derive their one-shot submission effects
                    // (rotation/endpoint/param/governance) so a self-synced node
                    // applies the byte-identical effect sequence as one that
                    // executed every block — otherwise a committed, non-re-emitted
                    // governance Approved would land on some replicas and not
                    // others, silently splitting the validator set (#772).
                    gap_effects = self
                        .backfill_self_synced_gap(&payload, prev_height, block.header.height)
                        .await;
                }
                ElStatus::Syncing => {
                    // The EL doesn't have this block's parent yet; commit_block
                    // pointed it at the head via forkchoiceUpdated and it is
                    // syncing in the background. Hold the committed frontier at
                    // the last executed block until the EL reports VALID — don't
                    // claim a state the EL hasn't reached. Not an error:
                    // consensus commits regardless of EL execution outcome.
                    //
                    // Staking events are read only once the EL reports VALID
                    // (below) — its logs aren't available while syncing — so
                    // membership changes from this block are deferred until the
                    // EL catches up and the block is re-committed (#635).
                    tracing::info!(
                        target: "boule::reth",
                        height = block.header.height.0,
                        "reth EL syncing toward committed block; frontier + staking held until VALID",
                    );
                    return Ok(CommitResult::default());
                }
            }
            // The EL executed this block, so the staking and slashing
            // predeploys' events for it are now readable. Read them (#655
            // Deposit/Withdraw + #732/#658b Slashed) and feed the CL-native
            // stake ledger; the resulting deltas become validator_updates the
            // integration layer materialises into a reconfig (#652) — slashes
            // arriving as `weight 0` removals merged with the jail (#658a).
            let validator_updates = self
                .derive_validator_updates(&payload, block.header.height)
                .await;
            // #797 weight residual — detect a forged seated-weight delta in the
            // committed block's `extra_data` BEFORE reconcile drops the
            // mirrored entries. At this instant `pending_weights` still holds
            // exactly the deltas that were pending when this block was built
            // (this node and the leader walked the same committed chain), so an
            // honest block's carried weights are all present; a weight the
            // proposer forged is not, and is loudly surfaced. Detection only —
            // the block is already BFT-final (keys + settledView are the
            // vote-time-*prevented* fields; see `validate_registry_extra_data`).
            self.detect_weight_extra_data_divergence(&payload, block.header.height);
            // #791 Part B — EL-mirrored weights: reconcile then re-stage the
            // pending-weight buffer. This block's sealed `extra_data` carried the
            // weight deltas that were pending when it was *built*; now that it has
            // committed (on every replica), the EL has applied them, so drop them
            // from the buffer. Then stage this block's freshly-derived deltas to
            // ride the next block's `extra_data`. Done on **every** node (not just
            // the proposer) and keyed by validator, so the buffer is byte-identical
            // across replicas and a later delta supersedes an earlier pending one.
            self.reconcile_pending_weights(&payload, &validator_updates);
            // Submission-predeploy events: each carries an encoded consensus
            // command submitted as an EVM tx, surfaced as a ValidatorEffect the
            // integration layer re-materialises into a block command (consensus
            // validates it — signatures and/or v_eff — at commit).
            //   - rotation   (#730) -> KeyRotation
            //   - endpoint   (#731) -> EndpointUpdate
            //   - param      (#542) -> ParamUpdate
            //   - governance (#729) -> Reconfig
            let mut effects = self.derive_rotation_effects(&payload).await;
            // A1 (#777/#783): the registry writes (`recordKey`/`recordWeight`/
            // `recordSettled`) are applied by the custom EL as system calls from
            // the block's `registryPayload` attribute (built in `build_proposal`
            // via `registry_payload_for_build`), so every replica mirrors the
            // identical registry state deterministically — there is no
            // proposer-authored transaction write path here anymore (the legacy
            // `record_rotated_keys`/`record_validator_weights`/`record_settled_view`
            // tx hooks were removed in Phase 3). `commit` only derives the
            // validator-set effects below; the EL is the sole registry writer.
            effects.extend(self.derive_endpoint_effects(&payload).await);
            effects.extend(self.derive_param_effects(&payload).await);
            effects.extend(self.derive_governance_effects(&payload).await);
            // #772: prepend the self-synced gap's submission effects (ascending
            // by height) ahead of this block's, so the materialised effect
            // sequence is byte-identical to a node that executed every block in
            // order. The gap rotations' `recordKey` registry writes were already
            // applied by the EL during self-sync, so this node's `effects` only
            // re-materialise the validator-set changes.
            if !gap_effects.is_empty() {
                gap_effects.extend(effects);
                effects = gap_effects;
            }
            Ok(CommitResult {
                validator_updates,
                effects,
                ..Default::default()
            })
        })
    }

    fn validate_proposal<'a>(&'a self, block: &'a Block) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.validate_registry_extra_data(block) })
    }

    fn check(&self, cmd: &[u8]) -> Result<()> {
        // Tier-1 includability: the command must decode to an execution
        // payload carrying a block hash. Stateless — no reth round-trip.
        let payload: Value =
            serde_json::from_slice(cmd).context("command is not a JSON execution payload")?;
        payload
            .get("blockHash")
            .and_then(|v| v.as_str())
            .context("execution payload is missing blockHash")?;
        Ok(())
    }

    /// #658b: zero the equivocator's bonded stake in the CL-native ledger
    /// (the authoritative balance; `Staking.sol` is a pure event emitter).
    /// The `weight 0` delta is drained by the next `commit`'s `take_updates`
    /// and merges with the jail-remove (#658a) through the reconfig path.
    fn slash(&self, node_id: NodeId) {
        self.stake_source.lock().slash(node_id);
    }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        // The reth backend drives the validator set from on-chain staking logs
        // (#655), burns bonded stake on committed evidence (#658b), and accepts
        // key/operator rotations (#730), endpoint advertisements (#731), and
        // live parameter updates (#542) via their predeploys. It does not (yet)
        // drive rewards through the seam (a milestone-#4 follow-up).
        vec![
            IntegrationCapability::Membership,
            IntegrationCapability::Slashing,
            IntegrationCapability::KeyRotation,
            IntegrationCapability::EndpointAdvertisement,
            IntegrationCapability::ParameterUpdates,
        ]
    }

    fn executed_height(&self) -> Option<Height> {
        // reth's executed frontier: the last committed block whose payload the
        // EL reported VALID. Lags the consensus committed height while the EL
        // is SYNCING, which is what the startup EL-catch-up (#635) keys off.
        Some(self.committed.lock().height)
    }

    fn state_commitment(&self) -> [u8; 32] {
        self.committed.lock().state_root
    }

    fn snapshot(&self) -> Bytes {
        let c = self.committed.lock();
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&c.height.0.to_le_bytes());
        out.extend_from_slice(&c.state_root);
        Bytes::from(out)
    }

    fn restore(&self, snap: &[u8]) -> Result<()> {
        if snap.len() != 40 {
            anyhow::bail!(
                "reth snapshot must be 40 bytes (u64 height + 32-byte root), got {}",
                snap.len()
            );
        }
        let height = u64::from_le_bytes(snap[..8].try_into().unwrap());
        let root: [u8; 32] = snap[8..].try_into().unwrap();
        let mut c = self.committed.lock();
        c.height = Height(height);
        c.state_root = root;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FixtureTransport;

    const RETH_GENESIS: &str = "0x48d8efff29130c4b1149a8cb877448dc06421f6617b92dc0f817ef96d8973767";
    const BLOCK1: &str = "0x24df01d105151ebf3d2a6c33530c4d3078d632fb7be477e4ce038ec645a61e91";
    const BLOCK1_STATE_ROOT: &str =
        "351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f";
    const FEE: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn make_app(genesis_root: [u8; 32]) -> RethApplication {
        RethApplication::new(
            Box::new(FixtureTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            genesis_root,
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        )
    }

    fn genesis() -> Block {
        Block::genesis([0; 32], [0; 32])
    }

    fn sample_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(0, block.hash(), 4)
    }

    #[tokio::test]
    async fn build_from_genesis_maps_payload_into_a_boule_block() {
        let app = make_app([0u8; 32]);
        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");

        assert_eq!(block.header.height, Height(1));
        assert_eq!(block.header.view, View(1));
        assert_eq!(block.header.parent_hash, g.hash());
        assert_eq!(block.header.proposer, [1u8; 32]);
        // Immediate post-state root from reth's getPayload.
        assert_eq!(
            hex::encode(block.header.state_commitment),
            BLOCK1_STATE_ROOT
        );
        // Lagged frontier is genesis until the first commit.
        assert_eq!(block.header.committed_height, Height(0));
        assert_eq!(block.header.committed_state_root, [0u8; 32]);

        // One command == the EVM payload for block 1.
        assert_eq!(block.commands.len(), 1);
        let payload: Value = serde_json::from_slice(&block.commands[0]).unwrap();
        assert_eq!(payload["blockHash"], BLOCK1);
    }

    #[test]
    fn declares_the_capabilities_it_drives() {
        // The reth backend drives the validator set (#655), slashing (#658b),
        // key rotation (#730), endpoint advertisement (#731), and parameter
        // updates (#542) — and declares exactly those, nothing it doesn't drive.
        let app = make_app([0u8; 32]);
        let caps = app.capabilities();
        assert!(caps.contains(&IntegrationCapability::Membership));
        assert!(caps.contains(&IntegrationCapability::Slashing));
        assert!(caps.contains(&IntegrationCapability::KeyRotation));
        assert!(caps.contains(&IntegrationCapability::EndpointAdvertisement));
        assert!(caps.contains(&IntegrationCapability::ParameterUpdates));
        assert!(!caps.contains(&IntegrationCapability::Rewards));
        assert_eq!(caps.len(), 5);
    }

    #[tokio::test]
    async fn commit_executes_and_advances_the_committed_frontier() {
        let app = make_app([0u8; 32]);
        assert_eq!(app.state_commitment(), [0u8; 32], "starts at genesis root");

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");
        // The reth EL drives no membership changes — Ethereum keeps the
        // validator set in the consensus layer.
        assert!(result.validator_updates.is_empty());

        assert_eq!(hex::encode(app.state_commitment()), BLOCK1_STATE_ROOT);
    }

    /// Test transport: engine_* via the golden fixtures (so `commit` reaches
    /// VALID), plus a canned `eth_getLogs` result so the staking read path
    /// can be exercised without a live reth.
    struct StakingTransport {
        inner: FixtureTransport,
        logs: Value,
    }
    impl EngineTransport for StakingTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, _params: Value) -> BoxFuture<'_, Result<Value>> {
            let logs = self.logs.clone();
            Box::pin(async move { Ok(logs) })
        }
    }

    #[tokio::test]
    async fn commit_reads_staking_logs_into_validator_updates() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        // A validator seeded with genesis stake 1; a Withdraw of 1 fully
        // unbonds it, which the ledger reports as a removal (weight 0).
        let node = [2u8; 32];
        let logs = serde_json::json!([{
            "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": format!("0x{:064x}", 1u64),
        }]);
        let app = RethApplication::new(
            Box::new(StakingTransport {
                inner: FixtureTransport,
                logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([(node, 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");
        assert_eq!(
            result.validator_updates,
            vec![ValidatorUpdate {
                node_id: node,
                weight: 0,
            }],
            "a Withdraw of the full stake removes the validator (weight 0)",
        );
    }

    /// Test transport serving slashing-predeploy `Slashed` logs only for the
    /// slashing `eth_getLogs` filter (keyed on the filter's `address`), so a
    /// commit's staking read sees nothing and its slashing read sees the canned
    /// log.
    struct SlashingTransport {
        inner: FixtureTransport,
        slashed_logs: Value,
    }
    impl EngineTransport for SlashingTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            let is_slashing = params[0]["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(slashing::SLASHING_ADDRESS));
            let logs = if is_slashing {
                self.slashed_logs.clone()
            } else {
                Value::Array(Vec::new())
            };
            Box::pin(async move { Ok(logs) })
        }
    }

    /// #732 end-to-end (reth side): a `Slashed` event in a committed block burns
    /// the equivocator's bonded stake through the `StakeSource`, surfacing as a
    /// `weight 0` removal in `validator_updates` (the membership jail, #658a,
    /// merges via the reconfig path). The slashing predeploy already verified
    /// the equivocation in the EVM, so boule needs only the validator id.
    #[tokio::test]
    async fn commit_reads_slashed_logs_into_a_validator_removal() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        // An equivocator seeded with genesis stake 1_000; a Slashed event for
        // it zeroes the stake (weight 0 = removal).
        let equivocator = [2u8; 32];
        let slashed_logs = serde_json::json!([{
            "topics": [slashing::SLASHED_TOPIC, format!("0x{}", "02".repeat(32))],
            // viewNum(uint64) + blockA + blockB — unread by the apply path.
            "data": format!("0x{:064x}{}{}", 5u64, "aa".repeat(32), "bb".repeat(32)),
        }]);
        let app = RethApplication::new(
            Box::new(SlashingTransport {
                inner: FixtureTransport,
                slashed_logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([(equivocator, 1_000u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");

        assert_eq!(
            result.validator_updates,
            vec![ValidatorUpdate {
                node_id: equivocator,
                weight: 0,
            }],
            "a Slashed event burns the equivocator's stake (weight 0 = removal)",
        );
        assert!(
            result.effects.is_empty(),
            "Slashed is applied directly to the stake source, not carried as an effect",
        );
    }

    /// Test transport serving rotation-predeploy logs only for the rotation
    /// `eth_getLogs` filter (keyed on the filter's `address`), so a commit's
    /// staking read sees nothing and its rotation read sees the canned logs.
    struct RotationTransport {
        inner: FixtureTransport,
        rotation_logs: Value,
    }
    impl EngineTransport for RotationTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            let is_rotation = params[0]["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(rotation::ROTATION_ADDRESS));
            let logs = if is_rotation {
                self.rotation_logs.clone()
            } else {
                Value::Array(Vec::new())
            };
            Box::pin(async move { Ok(logs) })
        }
    }

    /// ABI-encode a dynamic `bytes` value as the EVM lays it out in log data:
    /// offset word (`0x20`), length word, then the right-padded payload.
    fn abi_log_bytes(payload: &[u8]) -> String {
        let mut data = Vec::new();
        let mut off = [0u8; 32];
        off[31] = 0x20;
        data.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        data.extend_from_slice(&len);
        data.extend_from_slice(payload);
        data.extend(std::iter::repeat_n(0u8, (32 - payload.len() % 32) % 32));
        format!("0x{}", hex::encode(data))
    }

    /// #730 end-to-end (reth side): a rotation-predeploy event in a committed
    /// block surfaces as a `ValidatorEffect::KeyRotation` carrying the opaque
    /// rotation command, which the integration layer then materialises. reth
    /// does not interpret the command — it passes the bytes straight through.
    #[tokio::test]
    async fn commit_reads_rotation_logs_into_key_rotation_effects() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let cmd = b"OKROT-fake-encoded-dual-signed-rotation-command";
        let rotation_logs = serde_json::json!([{
            "topics": [rotation::ROTATION_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": abi_log_bytes(cmd),
        }]);
        let app = RethApplication::new(
            Box::new(RotationTransport {
                inner: FixtureTransport,
                rotation_logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([([2u8; 32], 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");

        assert!(
            result.validator_updates.is_empty(),
            "no staking logs at the rotation address",
        );
        assert_eq!(result.effects.len(), 1, "one rotation event → one effect");
        match &result.effects[0] {
            ValidatorEffect::KeyRotation(bytes) => {
                assert_eq!(
                    bytes.as_ref(),
                    cmd.as_ref(),
                    "the opaque command rides through"
                );
            }
            other => panic!("expected KeyRotation, got {other:?}"),
        }
    }

    /// Test transport serving endpoint-predeploy logs only for the endpoint
    /// `eth_getLogs` filter (keyed on the filter's `address`).
    struct EndpointTransport {
        inner: FixtureTransport,
        endpoint_logs: Value,
    }
    impl EngineTransport for EndpointTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            let is_endpoint = params[0]["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(endpoint::ENDPOINT_ADDRESS));
            let logs = if is_endpoint {
                self.endpoint_logs.clone()
            } else {
                Value::Array(Vec::new())
            };
            Box::pin(async move { Ok(logs) })
        }
    }

    /// #731 end-to-end (reth side): an endpoint-predeploy event in a committed
    /// block surfaces as a `ValidatorEffect::EndpointUpdate` carrying the opaque
    /// endpoint command, which the integration layer then materialises. reth
    /// does not interpret the command — it passes the bytes straight through.
    #[tokio::test]
    async fn commit_reads_endpoint_logs_into_endpoint_effects() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let cmd = b"ENDPT-fake-encoded-signed-endpoint-command";
        let endpoint_logs = serde_json::json!([{
            "topics": [endpoint::ENDPOINT_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": abi_log_bytes(cmd),
        }]);
        let app = RethApplication::new(
            Box::new(EndpointTransport {
                inner: FixtureTransport,
                endpoint_logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([([2u8; 32], 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");

        assert!(
            result.validator_updates.is_empty(),
            "no staking logs at the endpoint address",
        );
        assert_eq!(result.effects.len(), 1, "one endpoint event → one effect");
        match &result.effects[0] {
            ValidatorEffect::EndpointUpdate(bytes) => {
                assert_eq!(
                    bytes.as_ref(),
                    cmd.as_ref(),
                    "the opaque command rides through"
                );
            }
            other => panic!("expected EndpointUpdate, got {other:?}"),
        }
    }

    /// Test transport serving param-predeploy logs only for the param
    /// `eth_getLogs` filter (keyed on the filter's `address`).
    struct ParamTransport {
        inner: FixtureTransport,
        param_logs: Value,
    }
    impl EngineTransport for ParamTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            let is_param = params[0]["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(param::PARAM_ADDRESS));
            let logs = if is_param {
                self.param_logs.clone()
            } else {
                Value::Array(Vec::new())
            };
            Box::pin(async move { Ok(logs) })
        }
    }

    /// #542 end-to-end (reth side): a param-predeploy event in a committed block
    /// surfaces as a `ValidatorEffect::ParamUpdate` carrying the opaque
    /// param-update command. The event has no indexed validator, so its topics
    /// are just `[topic0]`. reth passes the bytes straight through.
    #[tokio::test]
    async fn commit_reads_param_logs_into_param_effects() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let cmd = b"CPARM-fake-encoded-consensus-param-update";
        let param_logs = serde_json::json!([{
            "topics": [param::PARAM_TOPIC],
            "data": abi_log_bytes(cmd),
        }]);
        let app = RethApplication::new(
            Box::new(ParamTransport {
                inner: FixtureTransport,
                param_logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([([2u8; 32], 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");

        assert!(result.validator_updates.is_empty());
        assert_eq!(result.effects.len(), 1, "one param event → one effect");
        match &result.effects[0] {
            ValidatorEffect::ParamUpdate(bytes) => {
                assert_eq!(
                    bytes.as_ref(),
                    cmd.as_ref(),
                    "the opaque command rides through"
                );
            }
            other => panic!("expected ParamUpdate, got {other:?}"),
        }
    }

    /// Test transport serving governance-predeploy logs only for the governance
    /// `eth_getLogs` filter (keyed on the filter's `address`).
    struct GovernanceTransport {
        inner: FixtureTransport,
        governance_logs: Value,
    }
    impl EngineTransport for GovernanceTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            let is_governance = params[0]["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(governance::GOVERNANCE_ADDRESS));
            let logs = if is_governance {
                self.governance_logs.clone()
            } else {
                Value::Array(Vec::new())
            };
            Box::pin(async move { Ok(logs) })
        }
    }

    /// #729 end-to-end (reth side): a governance `Approved` event in a committed
    /// block surfaces as a `ValidatorEffect::Reconfig` carrying the opaque
    /// reconfig command. The event indexes `proposalId` in `topics[1]` and
    /// carries the command in `data`. reth passes the bytes straight through —
    /// consensus validates the membership change when it materialises the effect.
    #[tokio::test]
    async fn commit_reads_governance_logs_into_reconfig_effects() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let cmd = b"RECFG-fake-encoded-validator-set-reconfig-command";
        let governance_logs = serde_json::json!([{
            "topics": [governance::APPROVED_TOPIC, format!("0x{}", "07".repeat(32))],
            "data": abi_log_bytes(cmd),
        }]);
        let app = RethApplication::new(
            Box::new(GovernanceTransport {
                inner: FixtureTransport,
                governance_logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([([2u8; 32], 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");

        assert!(
            result.validator_updates.is_empty(),
            "no staking logs at the governance address",
        );
        assert_eq!(result.effects.len(), 1, "one Approved event → one effect");
        match &result.effects[0] {
            ValidatorEffect::Reconfig(bytes) => {
                assert_eq!(
                    bytes.as_ref(),
                    cmd.as_ref(),
                    "the opaque reconfig command rides through"
                );
            }
            other => panic!("expected Reconfig, got {other:?}"),
        }
    }

    /// The reth builder must carry a pending boule system tx (a minted
    /// reconfig) from the mempool into the block alongside the EVM payload —
    /// otherwise a staking-driven reconfig never commits (the gap the
    /// multi-process reth e2e caught). App-level pool txs are *not* included
    /// (they ride reth's payload).
    #[tokio::test]
    async fn build_proposal_carries_a_pending_reconfig_from_the_mempool() {
        use boule_consensus::replication::impls::InMemoryMempool;
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let reconfig = ReconfigCommand {
            adds: vec![],
            removes: vec![[9u8; 32]],
            changes: vec![],
            v_eff: View(10),
        }
        .encode();
        mempool.insert(reconfig).unwrap();
        // A plain app command must be ignored (it belongs to reth's pool).
        mempool.insert(Bytes::from_static(b"an-app-tx")).unwrap();

        let app = RethApplication::new(
            Box::new(FixtureTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::empty()),
            Arc::clone(&mempool),
        );
        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        assert_eq!(
            block.commands.len(),
            2,
            "the EVM payload plus the one pending reconfig (the app tx is excluded)",
        );
        assert!(
            ReconfigCommand::is_reconfig_payload(&block.commands[1]),
            "the second command is the carried reconfig",
        );
    }

    #[tokio::test]
    async fn commit_of_genesis_is_a_noop() {
        let app = make_app([9u8; 32]);
        app.commit(&AppContext::default(), &genesis())
            .await
            .expect("genesis commit");
        assert_eq!(app.state_commitment(), [9u8; 32]);
    }

    #[test]
    fn check_accepts_a_payload_and_rejects_garbage() {
        let app = make_app([0u8; 32]);
        let payload = serde_json::json!({ "blockHash": BLOCK1 });
        let cmd = serde_json::to_vec(&payload).unwrap();
        assert!(app.check(&cmd).is_ok());
        assert!(app.check(b"not a payload").is_err());
        // Decodes as JSON but missing blockHash.
        assert!(app.check(b"{}").is_err());
    }

    #[test]
    fn snapshot_round_trips_height_and_root() {
        let app = make_app([0u8; 32]);
        {
            let mut c = app.committed.lock();
            c.height = Height(7);
            c.state_root = [0xAB; 32];
        }
        let snap = app.snapshot();

        let restored = make_app([0u8; 32]);
        restored.restore(&snap).unwrap();
        assert_eq!(restored.state_commitment(), [0xAB; 32]);
        assert_eq!(restored.committed.lock().height, Height(7));
    }

    #[test]
    fn restore_rejects_a_wrong_length_blob() {
        let app = make_app([0u8; 32]);
        assert!(app.restore(&[0u8; 16]).is_err());
    }

    #[test]
    fn executed_height_tracks_the_committed_frontier() {
        // The EL's executed height is the committed frontier — what the startup
        // EL-catch-up (#635) compares against the consensus committed height.
        let app = make_app([0u8; 32]);
        assert_eq!(app.executed_height(), Some(Height(0)), "starts at genesis");
        app.recover_frontier(Height(42), [0xAB; 32]);
        assert_eq!(app.executed_height(), Some(Height(42)));
    }

    #[test]
    fn recover_frontier_seeds_height_and_root_on_restart() {
        // Fresh construction starts at the genesis frontier...
        let app = make_app([7u8; 32]);
        assert_eq!(app.committed.lock().height, Height(0));
        assert_eq!(app.state_commitment(), [7u8; 32]);
        // ...and restart recovery reconciles it to reth's finalized head.
        app.recover_frontier(Height(99), [0xCD; 32]);
        assert_eq!(app.committed.lock().height, Height(99));
        assert_eq!(app.state_commitment(), [0xCD; 32]);
    }

    // ── #629: uncommitted-ancestor registration on the build path ──────────

    fn evm_payload(block_hash: &str) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "blockHash": block_hash,
                "stateRoot": format!("0x{}", "11".repeat(32)),
                "timestamp": "0x1",
            }))
            .unwrap(),
        )
    }

    fn block_with_payload(parent_hash: [u8; 32], height: u64, block_hash: &str) -> Block {
        let commands = vec![evm_payload(block_hash)];
        Block {
            header: BlockHeader {
                parent_hash,
                height: Height(height),
                view: View(height),
                proposer: [1u8; 32],
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0u8; 32],
                committed_height: Height(0),
                committed_state_root: [0u8; 32],
                timestamp: 1,
            },
            commands,
        }
    }

    #[test]
    fn uncommitted_chain_returns_parent_and_ancestors_oldest_first() {
        // genesis(0) <- a(1) <- b(2) <- c(3); committed frontier at height 1.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let c = block_with_payload(b.hash(), 3, "0xcc");
        let pending: HashMap<BlockHash, Block> =
            [(a.hash(), a), (b.hash(), b), (c.hash(), c.clone())]
                .into_iter()
                .collect();

        // a is at the committed frontier (excluded); b, c are uncommitted, so
        // the chain is oldest-first [b, c].
        let chain = uncommitted_chain(&c, &pending, Height(1));
        let heights: Vec<u64> = chain.iter().map(|blk| blk.header.height.0).collect();
        assert_eq!(heights, vec![2, 3]);
    }

    #[test]
    fn uncommitted_chain_is_empty_for_the_genesis_parent() {
        let g = genesis();
        assert!(uncommitted_chain(&g, &HashMap::new(), Height(0)).is_empty());
    }

    #[test]
    fn uncommitted_chain_stops_at_a_missing_parent() {
        // Only c is in pending (its ancestors absent); the walk stops at c.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let c = block_with_payload(b.hash(), 3, "0xcc");
        let pending: HashMap<BlockHash, Block> = [(c.hash(), c.clone())].into_iter().collect();
        let chain = uncommitted_chain(&c, &pending, Height(0));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].header.height.0, 3);
    }

    /// Transport that records the engine methods called while replaying the
    /// golden fixtures, so the driver runs and the call sequence is observable.
    struct RecordingTransport {
        methods: std::sync::Arc<Mutex<Vec<String>>>,
    }

    impl EngineTransport for RecordingTransport {
        fn call(
            &self,
            method: &str,
            params: Value,
            _tag: &str,
        ) -> BoxFuture<'_, anyhow::Result<Value>> {
            self.methods.lock().push(method.to_string());
            let raw = match method {
                "engine_forkchoiceUpdatedV3" => {
                    if params.get(1).is_some_and(|v| !v.is_null()) {
                        include_str!("../fixtures/01-fcu-attrs.json")
                    } else {
                        include_str!("../fixtures/04-fcu-final.json")
                    }
                }
                "engine_getPayloadV4" => include_str!("../fixtures/02-getpayload.json"),
                "engine_newPayloadV4" => include_str!("../fixtures/03-newpayload.json"),
                other => panic!("unexpected engine method {other}"),
            };
            let v = serde_json::from_str::<Value>(raw).unwrap()["result"].clone();
            Box::pin(async move { Ok(v) })
        }
    }

    #[tokio::test]
    async fn build_registers_the_uncommitted_ancestor_chain_before_building() {
        let methods = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let app = RethApplication::new(
            Box::new(RecordingTransport {
                methods: methods.clone(),
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        // Two uncommitted blocks above the (genesis) committed frontier; build
        // on the tip `b`.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let pending: HashMap<BlockHash, Block> =
            [(a.hash(), a), (b.hash(), b.clone())].into_iter().collect();

        app.build_proposal(
            &AppContext::default(),
            &b,
            View(3),
            &sample_qc(&b),
            &pending,
            1_000,
        )
        .await
        .expect("build");

        let m = methods.lock();
        let new_payloads = m.iter().filter(|x| *x == "engine_newPayloadV4").count();
        assert_eq!(new_payloads, 3, "two ancestors (a, b) + the built block");
        // Both ancestors are registered before the build's forkchoiceUpdatedV3.
        let first_fcu = m
            .iter()
            .position(|x| x == "engine_forkchoiceUpdatedV3")
            .expect("build issues a forkchoiceUpdatedV3");
        let registered_before_build = m[..first_fcu]
            .iter()
            .filter(|x| *x == "engine_newPayloadV4")
            .count();
        assert_eq!(
            registered_before_build, 2,
            "ancestors registered before building"
        );
    }

    // ── #636: tolerate Engine-API SYNCING (EL catch-up) ────────────────────

    /// Transport whose newPayload/fcU return `SYNCING` (EL is behind).
    struct SyncingTransport;
    impl EngineTransport for SyncingTransport {
        fn call(
            &self,
            method: &str,
            _params: Value,
            _tag: &str,
        ) -> BoxFuture<'_, anyhow::Result<Value>> {
            let v = match method {
                "engine_newPayloadV4" => serde_json::json!({ "status": "SYNCING" }),
                "engine_forkchoiceUpdatedV3" => {
                    serde_json::json!({ "payloadStatus": { "status": "SYNCING" } })
                }
                other => panic!("unexpected method {other}"),
            };
            Box::pin(async move { Ok(v) })
        }
    }

    #[tokio::test]
    async fn commit_holds_the_frontier_when_the_el_is_syncing() {
        let app = RethApplication::new(
            Box::new(SyncingTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );
        {
            let mut c = app.committed.lock();
            c.height = Height(5);
            c.state_root = [0x55; 32];
        }
        // A committed block the EL can't execute yet (SYNCING).
        let block = block_with_payload([0u8; 32], 10, BLOCK1);
        app.commit(&AppContext::default(), &block)
            .await
            .expect("SYNCING commit is not an error");
        // Frontier held at the last executed block, not advanced to 10.
        assert_eq!(app.committed.lock().height, Height(5));
        assert_eq!(app.state_commitment(), [0x55; 32]);
    }

    /// #674: when the EL reports VALID for a block whose height jumps past the
    /// committed frontier by more than one (it self-synced the in-between
    /// blocks via snap/full sync, never replaying them through `commit`), the
    /// staking events of those skipped blocks are backfilled — read by EVM
    /// number and applied at their own height — so the CL stake ledger does not
    /// silently drift from EL state.
    #[tokio::test]
    async fn commit_backfills_staking_over_an_el_self_synced_gap() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        fn payload_with_number(block_hash: &str, number: u64) -> Bytes {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "blockHash": block_hash,
                    "blockNumber": format!("0x{number:x}"),
                    "stateRoot": format!("0x{}", "11".repeat(32)),
                    "timestamp": "0x1",
                }))
                .unwrap(),
            )
        }

        const VALIDATOR_A: [u8; 32] = [0x0a; 32]; // genesis-staked, withdraws in block 3
        const VALIDATOR_C: [u8; 32] = [0x0c; 32]; // deposits in skipped block 1
        const BLOCK3_HASH: &str = "0x3c";

        // Transport: engine_* report VALID so `commit` advances the frontier;
        // `eth_getLogs` serves per-block staking events — by EVM number for the
        // self-synced gap blocks, by hash for the current block.
        struct GapStakingTransport;
        impl EngineTransport for GapStakingTransport {
            fn call(
                &self,
                method: &str,
                _params: Value,
                _tag: &str,
            ) -> BoxFuture<'_, Result<Value>> {
                let v = match method {
                    "engine_newPayloadV4" => serde_json::json!({ "status": "VALID" }),
                    "engine_forkchoiceUpdatedV3" => {
                        serde_json::json!({ "payloadStatus": { "status": "VALID" } })
                    }
                    other => panic!("unexpected engine method {other}"),
                };
                Box::pin(async move { Ok(v) })
            }
            fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
                let filter = &params[0];
                let logs = if filter["fromBlock"] == serde_json::json!("0x1") {
                    // Skipped block 1: validator C deposits 7.
                    serde_json::json!([{
                        "topics": [staking::DEPOSIT_TOPIC, format!("0x{}", "0c".repeat(32))],
                        "data": format!("0x{:064x}", 7u64),
                    }])
                } else if filter["blockHash"] == serde_json::json!(BLOCK3_HASH) {
                    // Current block 3: validator A withdraws its full stake.
                    serde_json::json!([{
                        "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "0a".repeat(32))],
                        "data": format!("0x{:064x}", 1u64),
                    }])
                } else {
                    // Skipped block 2 (fromBlock 0x2) and anything else: no events.
                    serde_json::json!([])
                };
                Box::pin(async move { Ok(logs) })
            }
        }

        let app = RethApplication::new(
            Box::new(GapStakingTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([(VALIDATOR_A, 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        // Frontier starts at genesis (0). The EL self-synced blocks 1 and 2 in
        // the background; now it executes block 3 (height jumps 0 → 3).
        let block3 = {
            let commands = vec![payload_with_number(BLOCK3_HASH, 3)];
            Block {
                header: BlockHeader {
                    parent_hash: [0u8; 32],
                    height: Height(3),
                    view: View(3),
                    proposer: [1u8; 32],
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0u8; 32],
                    committed_height: Height(0),
                    committed_state_root: [0u8; 32],
                    timestamp: 1,
                },
                commands,
            }
        };

        let result = app
            .commit(&AppContext::default(), &block3)
            .await
            .expect("commit");

        // Frontier advanced to 3.
        assert_eq!(app.committed.lock().height, Height(3));
        // The gap block 1's deposit (C, weight 7) is NOT lost, and the current
        // block 3's withdraw (A → weight 0) also rides this commit.
        let mut got = result.validator_updates.clone();
        got.sort_by_key(|u| u.node_id);
        assert_eq!(
            got,
            vec![
                ValidatorUpdate {
                    node_id: VALIDATOR_A,
                    weight: 0,
                },
                ValidatorUpdate {
                    node_id: VALIDATOR_C,
                    weight: 7,
                },
            ],
            "the self-synced gap's staking event (C +7) is backfilled alongside \
             the current block's (A removed)",
        );
    }

    /// #772: a governance `Approved` (and a rotation) is a **one-shot** effect —
    /// emitted once per proposal, never re-submitted. If the block carrying it
    /// falls in an EL self-sync gap, the effect must still be derived/applied, or
    /// some replicas apply the membership change and others do not → silent
    /// validator-set divergence. This asserts a node that self-syncs **past** a
    /// gap block carrying an `Approved` + a rotation produces the byte-identical
    /// effect sequence as a node that executed every block in order.
    #[tokio::test]
    async fn commit_backfills_one_shot_effects_over_an_el_self_synced_gap() {
        use crate::predeploy_log::test_support::{abi_log_bytes, topic_node};
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        fn payload_with_number(block_hash: &str, number: u64) -> Bytes {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "blockHash": block_hash,
                    "blockNumber": format!("0x{number:x}"),
                    "stateRoot": format!("0x{}", "11".repeat(32)),
                    "timestamp": "0x1",
                }))
                .unwrap(),
            )
        }

        // Opaque command payloads the predeploy logs carry (reth never decodes
        // them — they ride through as the effect's bytes).
        const RECONFIG_CMD: &[u8] = b"reconfig-command-for-an-approved-membership-change";
        const ROTATION_CMD: &[u8] = b"dual-signed-rotation-command";

        // Block 2 (in the self-synced gap) carries a governance Approved + a
        // rotation; block 1 and the current block 3 carry nothing. The gap
        // block's logs are served *by EVM number*; the current block by hash.
        const BLOCK3_HASH: &str = "0x3c";
        struct GapEffectsTransport;
        impl EngineTransport for GapEffectsTransport {
            fn call(
                &self,
                method: &str,
                _params: Value,
                _tag: &str,
            ) -> BoxFuture<'_, Result<Value>> {
                let v = match method {
                    "engine_newPayloadV4" => serde_json::json!({ "status": "VALID" }),
                    "engine_forkchoiceUpdatedV3" => {
                        serde_json::json!({ "payloadStatus": { "status": "VALID" } })
                    }
                    other => panic!("unexpected engine method {other}"),
                };
                Box::pin(async move { Ok(v) })
            }
            fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
                let filter = &params[0];
                let addr = filter["address"].as_str().unwrap_or_default().to_string();
                // The gap block carrying the one-shot effects: EVM number 0x2,
                // selected either by-number (gap backfill) or by-hash (per-block
                // path, used by the no-gap reference node below).
                let is_gap_block = filter["fromBlock"] == serde_json::json!("0x2")
                    || filter["blockHash"] == serde_json::json!("0xb2");
                let logs = if is_gap_block
                    && addr.eq_ignore_ascii_case(governance::GOVERNANCE_ADDRESS)
                {
                    serde_json::json!([{
                        "topics": [governance::APPROVED_TOPIC, topic_node(0xab)],
                        "data": abi_log_bytes(RECONFIG_CMD),
                    }])
                } else if is_gap_block && addr.eq_ignore_ascii_case(rotation::ROTATION_ADDRESS) {
                    serde_json::json!([{
                        "topics": [rotation::ROTATION_TOPIC, topic_node(0x42)],
                        "data": abi_log_bytes(ROTATION_CMD),
                    }])
                } else {
                    serde_json::json!([])
                };
                Box::pin(async move { Ok(logs) })
            }
        }

        fn make() -> RethApplication {
            RethApplication::new(
                Box::new(GapEffectsTransport),
                [1u8; 32],
                FEE,
                RETH_GENESIS,
                [0u8; 32],
                Duration::ZERO,
                Box::new(BondedStakeLedger::empty()),
                std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                    64,
                )),
            )
        }

        fn block_at(hash: &str, number: u64, height: u64) -> Block {
            let commands = vec![payload_with_number(hash, number)];
            Block {
                header: BlockHeader {
                    parent_hash: [0u8; 32],
                    height: Height(height),
                    view: View(height),
                    proposer: [9u8; 32], // not self → no proposer-only registry writes
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0u8; 32],
                    committed_height: Height(0),
                    committed_state_root: [0u8; 32],
                    timestamp: 1,
                },
                commands,
            }
        }

        // (a) Self-synced node: the EL executed blocks 1 and 2 in the background;
        // now it executes block 3, so the frontier jumps 0 → 3 and the gap
        // (blocks 1, 2) is backfilled. Block 2's one-shot effects must appear.
        let synced = make();
        let gap_result = synced
            .commit(&AppContext::default(), &block_at(BLOCK3_HASH, 3, 3))
            .await
            .expect("commit");
        assert_eq!(synced.committed.lock().height, Height(3));

        // (b) Reference node: executes every block in order. Block 2 (by hash
        // 0xb2) carries the same one-shot effects via the normal per-block path.
        let stepwise = make();
        stepwise
            .commit(&AppContext::default(), &block_at("0xb1", 1, 1))
            .await
            .expect("commit b1");
        let ref_block2 = stepwise
            .commit(&AppContext::default(), &block_at("0xb2", 2, 2))
            .await
            .expect("commit b2");
        stepwise
            .commit(&AppContext::default(), &block_at(BLOCK3_HASH, 3, 3))
            .await
            .expect("commit b3");

        // The one-shot effects the executing node derived for block 2 must be
        // byte-identical to what the self-synced node backfilled for the gap.
        let expected = vec![
            ValidatorEffect::KeyRotation(Bytes::from(ROTATION_CMD)),
            ValidatorEffect::Reconfig(Bytes::from(RECONFIG_CMD)),
        ];
        assert_eq!(
            ref_block2.effects, expected,
            "sanity: the per-block path derives the rotation + reconfig from block 2",
        );
        assert_eq!(
            gap_result.effects, expected,
            "the self-synced node must backfill block 2's one-shot rotation + \
             governance Approved (else silent validator-set divergence, #772)",
        );
    }

    #[tokio::test]
    async fn build_skips_when_the_el_is_syncing() {
        let app = RethApplication::new(
            Box::new(SyncingTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let pending: HashMap<BlockHash, Block> = [(a.hash(), a.clone())].into_iter().collect();
        // The leader's EL can't register the uncommitted ancestor (SYNCING) →
        // build is skipped (retriable), not a forged proposal.
        let err = app
            .build_proposal(
                &AppContext::default(),
                &a,
                View(2),
                &sample_qc(&a),
                &pending,
                1_000,
            )
            .await
            .expect_err("build must skip while the EL is syncing");
        assert!(err.to_string().contains("still syncing"));
    }

    // ── seated-weight deltas flow through the EL `registryPayload` ──────────

    /// Transport for the EL-payload weight tests: engine fixtures (so `commit`
    /// reaches VALID) and a canned staking log at the staking predeploy address
    /// (empty elsewhere) so `derive_validator_updates` produces a weight change
    /// the build then carries in the next block's `registryPayload`.
    struct WeightWriteTransport {
        inner: FixtureTransport,
        staking_logs: Value,
    }
    impl EngineTransport for WeightWriteTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            if method == "eth_chainId" {
                return Box::pin(async move { Ok(Value::String("0x539".into())) }); // 1337
            }
            let is_staking = params[0]["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(staking::STAKING_ADDRESS));
            let logs = if is_staking {
                self.staking_logs.clone()
            } else {
                Value::Array(Vec::new())
            };
            Box::pin(async move { Ok(logs) })
        }
    }

    fn weight_app(
        self_id: NodeId,
        staking_logs: Value,
        genesis_stake: Vec<(NodeId, u64)>,
    ) -> RethApplication {
        use boule_consensus::replication::stake_source::BondedStakeLedger;
        RethApplication::new(
            Box::new(WeightWriteTransport {
                inner: FixtureTransport,
                staking_logs,
            }),
            self_id,
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from(genesis_stake)),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        )
    }
    // ── #791 Part B: seated weights flow through the EL `extra_data` ─────────

    /// A seated-weight change committed in block N is **staged** and carried in
    /// the **next** build's `registryPayload` (the one-block lag), so the EL
    /// applies `recordWeight` from `extra_data` on every replica. Build N's own
    /// payload cannot carry it (the delta is only known after N executes).
    #[tokio::test]
    async fn committed_weight_delta_rides_the_next_block_payload() {
        let self_id = [1u8; 32];
        let node = [2u8; 32];
        // A Withdraw of the full genesis stake (3) → weight 0 (a removal).
        let staking_logs = serde_json::json!([{
            "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": format!("0x{:064x}", 3u64),
        }]);
        let app = weight_app(self_id, staking_logs, vec![(node, 3u64)]);

        let g = genesis();
        let ctx = AppContext {
            proposer: self_id,
            ..Default::default()
        };
        let view = View(registry::SETTLED_VIEW_MARGIN + 6);

        // Block N's own payload carries no weight yet (nothing staged).
        assert!(
            app.registry_payload_for_build(view, &[]).weights.is_empty(),
            "block N cannot carry its own (not-yet-executed) weight delta",
        );

        // Commit N: the Withdraw is derived → weight 0 staged for the next block.
        let block = app
            .build_proposal(&ctx, &g, view, &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        app.commit(&ctx, &block).await.expect("commit");

        // Block N+1's payload now carries the seated-weight delta the EL applies.
        let next = app.registry_payload_for_build(view + View(1), &[]);
        assert_eq!(
            next.weights,
            vec![(node, 0)],
            "the committed weight delta rides the next block's registryPayload",
        );
    }

    /// Once a committed block's sealed `extra_data` has mirrored a staged weight
    /// delta through the EL, [`reconcile_pending_weights`] drops it so it is not
    /// carried twice — and a delta the block did *not* carry is retained.
    #[test]
    fn reconcile_drops_only_the_weights_a_committed_block_mirrored() {
        let self_id = [1u8; 32];
        let kept = [7u8; 32];
        let app = weight_app(self_id, Value::Array(Vec::new()), vec![]);
        // Stage two pending deltas as if two prior blocks produced them.
        {
            let mut p = app.pending_weights.lock();
            p.insert([2u8; 32], 0);
            p.insert(kept, 5);
        }
        // A committed block whose `extra_data` mirrored only validator [2;32]→0.
        let carried = crate::registry_payload::RegistryPayload::new(
            vec![],
            &[ValidatorUpdate {
                node_id: [2u8; 32],
                weight: 0,
            }],
            None,
        );
        let payload = serde_json::json!({
            "extraData": format!("0x{}", hex::encode(carried.encode())),
        });

        app.reconcile_pending_weights(&payload, &[]);

        let p = app.pending_weights.lock();
        assert_eq!(p.get(&[2u8; 32]), None, "mirrored delta dropped");
        assert_eq!(p.get(&kept), Some(&5), "un-mirrored delta retained");
    }

    // ── #797: vote-time validation of the EL-applied registry extra_data ─────

    use boule_consensus::validator_rotation::ValidatorKeyRotation;
    use boule_core::crypto::sig_scheme::BlsAggregated;

    /// A real `DualSignedRotation` command (signatures zeroed — the registry
    /// decode never verifies them) rotating `validator` to a fresh BLS key at
    /// `v_eff`, the same shape the builder pulls from the mempool.
    fn bls_rotation_cmd(validator: NodeId, v_eff: u64, key_seed: u8) -> Bytes {
        let mut ikm = [0u8; 32];
        ikm[0] = key_seed;
        let (_, pk) = BlsAggregated::keygen(&ikm).expect("test BLS keygen");
        let payload = ValidatorKeyRotation {
            validator,
            new_pubkey: [0xCC; 32],
            v_eff: View::new(v_eff),
            new_bls_pubkey: Some(pk),
            new_bls_pop: None,
        };
        DualSignedRotation {
            payload,
            sig_old: [0u8; 64],
            sig_new: [0u8; 64],
        }
        .encode_command()
    }

    /// Assemble a proposed block whose first command is an EVM execution
    /// payload carrying `extra_data` (the registry write set the proposer
    /// stamped), followed by `system_cmds` (the rotation/system txs in the
    /// block). The header `view` drives the expected `settledView`.
    fn proposed_block(view: View, extra_data: &[u8], system_cmds: Vec<Bytes>) -> Block {
        let evm_payload = serde_json::json!({
            "blockHash": BLOCK1,
            "extraData": format!("0x{}", hex::encode(extra_data)),
        });
        let mut commands = vec![Bytes::from(serde_json::to_vec(&evm_payload).unwrap())];
        commands.extend(system_cmds);
        let commands_commitment = Block::commands_commitment(&commands);
        Block {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                height: Height(1),
                view,
                proposer: [9u8; 32],
                state_commitment: [0u8; 32],
                commands_commitment,
                validator_history_commitment: [0u8; 32],
                committed_height: Height(0),
                committed_state_root: [0u8; 32],
                timestamp: 0,
            },
            commands,
        }
    }

    /// **The exploit test.** A Byzantine leader stamps `extra_data` claiming a
    /// `recordKey` for an honest validator that the block's own rotation
    /// commands do NOT authorize (a forged key — the slash-an-honest-validator
    /// attack of #797). An honest validator re-derives the expected keys from
    /// the block's commands and `validate_proposal` REJECTS it (would not vote).
    #[tokio::test]
    async fn validate_proposal_rejects_forged_key_in_extra_data() {
        let app = make_app([0u8; 32]);
        let honest_validator = [0x42u8; 32];
        let view = View(registry::SETTLED_VIEW_MARGIN + 10);

        // The block carries NO rotation command, so an honest leader's
        // `extra_data` would carry no keys. The Byzantine leader instead forges
        // a `recordKey` for `honest_validator` directly into `extra_data`.
        let forged_key =
            registry::record_key_for_rotation(&bls_rotation_cmd(honest_validator, 5, 0x9a))
                .unwrap()
                .unwrap();
        let settled = registry::conservative_settled_view(view);
        let forged = crate::registry_payload::RegistryPayload {
            keys: vec![forged_key],
            weights: vec![],
            settled_view: Some(settled),
        };
        let block = proposed_block(view, &forged.encode(), vec![]);

        let err = app
            .validate_proposal(&block)
            .await
            .expect_err("a forged recordKey with no authorizing command must be rejected");
        assert!(
            err.to_string().contains("key mismatch"),
            "rejected for the right reason: {err}",
        );
    }

    /// Mirror of the exploit: an HONEST leader stamps `extra_data` that exactly
    /// matches the rotation command actually in the block (plus the deterministic
    /// `settledView`). `validate_proposal` ACCEPTS it — the honest path is
    /// unaffected by the gate.
    #[tokio::test]
    async fn validate_proposal_accepts_honest_matching_extra_data() {
        let app = make_app([0u8; 32]);
        let rotating = [0x42u8; 32];
        let view = View(registry::SETTLED_VIEW_MARGIN + 10);

        let cmd = bls_rotation_cmd(rotating, 5, 0x9a);
        // The honest extra_data: exactly the key the block's command authorizes,
        // and the deterministic settled view for this view.
        let key = registry::record_key_for_rotation(&cmd).unwrap().unwrap();
        let settled = registry::conservative_settled_view(view);
        let honest = crate::registry_payload::RegistryPayload {
            keys: vec![key],
            weights: vec![],
            settled_view: Some(settled),
        };
        let block = proposed_block(view, &honest.encode(), vec![cmd]);

        app.validate_proposal(&block)
            .await
            .expect("an honest leader's matching extra_data validates");
    }

    /// A forged `settledView` (ahead of the conservative frontier the view
    /// determines) is rejected — the second vote-time-prevented field. This is
    /// what stops a Byzantine leader advancing the slashing predeploy's read
    /// frontier past a not-yet-recorded key.
    #[tokio::test]
    async fn validate_proposal_rejects_forged_settled_view() {
        let app = make_app([0u8; 32]);
        let view = View(registry::SETTLED_VIEW_MARGIN + 10);
        let forged = crate::registry_payload::RegistryPayload {
            keys: vec![],
            weights: vec![],
            // Claim the frontier is the current view (ahead of the conservative
            // `view - MARGIN` every honest node derives).
            settled_view: Some(view),
        };
        let block = proposed_block(view, &forged.encode(), vec![]);

        let err = app
            .validate_proposal(&block)
            .await
            .expect_err("a settledView ahead of the conservative frontier must be rejected");
        assert!(
            err.to_string().contains("settledView mismatch"),
            "rejected for the right reason: {err}",
        );
    }

    /// A plain block (no rotation commands, default `extra_data` below the
    /// settled-view margin) carries no registry payload and validates — the
    /// common no-op case the gate must not break.
    #[tokio::test]
    async fn validate_proposal_accepts_plain_block() {
        let app = make_app([0u8; 32]);
        // A view at/under the margin → expected settledView is `None`, so the
        // honest extra_data is empty (a non-boule blob).
        let block = proposed_block(View(1), b"reth/v2.2.0/linux", vec![]);
        app.validate_proposal(&block)
            .await
            .expect("a plain block with default extra_data validates");
    }

    /// The #797 weight residual: a forged seated-weight delta in a committed
    /// block's `extra_data` — one this node never derived from execution — is
    /// **detected** at commit (`detect_weight_extra_data_divergence` returns
    /// true). This is detection-after-final, not vote-time prevention (weights
    /// are not reliably re-derivable at vote time under deferred execution).
    #[test]
    fn commit_detects_forged_weight_not_in_pending() {
        let app = weight_app([1u8; 32], Value::Array(Vec::new()), vec![]);
        // Nothing pending: this node derived no weight delta from any execution.
        assert!(app.pending_weights.lock().is_empty());
        // A committed block whose extra_data forges a weight for [3;32].
        let forged = crate::registry_payload::RegistryPayload::new(
            vec![],
            &[ValidatorUpdate {
                node_id: [3u8; 32],
                weight: 7,
            }],
            None,
        );
        let payload = serde_json::json!({
            "extraData": format!("0x{}", hex::encode(forged.encode())),
        });
        assert!(
            app.detect_weight_extra_data_divergence(&payload, Height(5)),
            "a weight this node never derived from execution is detected as a divergence",
        );
    }

    /// The honest weight path is NOT flagged: a committed block carrying exactly
    /// the weight delta this node has pending (derived from a prior execution)
    /// passes the commit-time detector cleanly.
    #[test]
    fn commit_does_not_flag_honest_pending_weight() {
        let app = weight_app([1u8; 32], Value::Array(Vec::new()), vec![]);
        app.pending_weights.lock().insert([3u8; 32], 7);
        let honest = crate::registry_payload::RegistryPayload::new(
            vec![],
            &[ValidatorUpdate {
                node_id: [3u8; 32],
                weight: 7,
            }],
            None,
        );
        let payload = serde_json::json!({
            "extraData": format!("0x{}", hex::encode(honest.encode())),
        });
        assert!(
            !app.detect_weight_extra_data_divergence(&payload, Height(5)),
            "a weight this node derived from execution is not flagged",
        );
    }
}
