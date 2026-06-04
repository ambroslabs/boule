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
use crate::{endpoint, governance, param, registry, rotation, slashing, staking, system_account};

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
    /// the **next** block's `registryPayload` (the same one-block lag the legacy
    /// `recordWeight` tx path has). `commit` reconciles the buffer against each
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

    /// Compute the A1 EL-applied registry write set (#781) the leader carries to
    /// the custom EL on the build attributes for the block at `view`.
    ///
    /// Sourced from boule's authoritative consensus state, mirroring exactly what
    /// the legacy tx-write path in [`Self::commit`] would record:
    ///
    /// - **`settledView`** — [`registry::conservative_settled_view`]`(view)`, the
    ///   same conservative frontier (#767) `record_settled_view` advances to. The
    ///   primary, near-always-present field; on the common no-rotation block it is
    ///   the *only* one, keeping the carried `extra_data` to a handful of bytes.
    ///   `None` below the margin (genesis frontier is already 0).
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
    ///   **next** block's payload here (the same one-block lag the legacy
    ///   `recordWeight` tx path has). Snapshotting (not draining) the buffer keeps
    ///   the build idempotent if the proposal is skipped; `commit` is what clears a
    ///   delta, once it sees a committed block's `extra_data` already mirrored it.
    ///   In a consensus-canonical order (by validator id, via the `BTreeMap`).
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

    /// #732 step 2 — the registry **write** path. For each committed key
    /// rotation in `effects` that swaps the validator's BLS key, write the new
    /// key into the `Registry` predeploy (`recordKey`) so the on-chain registry
    /// faithfully mirrors what consensus applied and the slashing predeploy's
    /// `keyAt` lookup is correct for post-genesis rotations.
    ///
    /// **Proposer-only.** Called solely when this node proposed the committed
    /// block (`ctx.proposer == self_id`): exactly one node submits the system
    /// tx, avoiding N redundant pool submissions per rotation. The write is
    /// idempotent regardless — `Registry.recordKey` requires a strictly
    /// increasing `vEff`, so a duplicate (re-proposed across views, or after a
    /// restart) simply reverts harmlessly in the EVM.
    ///
    /// The new key is converted from boule's 48-byte compressed min-pk G1 to the
    /// **128-byte EIP-2537 uncompressed** form `Registry.keyAt` must return for
    /// `Slashing.sol` (`bls_pubkey_to_eip2537_g1`); a malformed rotation is
    /// logged and skipped (it must never fail the commit — consensus commits
    /// regardless of the EL).
    ///
    /// `recordKey`'s writes are unauthenticated in this MVP (anyone with the
    /// system key can author them); contract-side access control gating
    /// `recordKey` to the system account is the explicit next step (see
    /// `Registry.sol` / [`crate::system_account`]).
    async fn record_rotated_keys(&self, effects: &[ValidatorEffect]) {
        // Collect the (validator, vEff, key128) writes this block's rotations
        // imply, skipping non-BLS rotations and logging (never failing on) a
        // malformed command.
        let mut writes = Vec::new();
        for effect in effects {
            let ValidatorEffect::KeyRotation(cmd) = effect else {
                continue;
            };
            match registry::record_key_for_rotation(cmd) {
                Ok(Some(rk)) => writes.push(rk),
                Ok(None) => {} // not a BLS-key rotation — nothing to mirror
                Err(e) => tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    "registry write: undecodable rotation command; skipping recordKey",
                ),
            }
        }
        if writes.is_empty() {
            return;
        }
        // Submit each recordKey as a system tx. `submit_system_call` fetches the
        // system account's *pending* nonce per call; submitting sequentially
        // (awaiting each) lets reth's pool reflect the prior tx so the next
        // nonce is fresh. A single rotation per block is the common case.
        for rk in &writes {
            let calldata = registry::record_key_calldata(rk);
            match self
                .submit_system_call(registry::registry_address(), calldata)
                .await
            {
                Ok(hash) => tracing::info!(
                    target: "boule::reth",
                    validator = %hex::encode(rk.validator),
                    v_eff = rk.v_eff.0,
                    tx = %hash,
                    "registry write: submitted recordKey for rotated BLS key",
                ),
                Err(e) => tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    validator = %hex::encode(rk.validator),
                    v_eff = rk.v_eff.0,
                    "registry write: recordKey submission failed (idempotent — retried next time)",
                ),
            }
        }
    }

    /// #732 step 4 — the registry **weight** write path. Mirror each seated
    /// validator-weight change this block produced into the `Registry` predeploy
    /// (`recordWeight`) so the on-chain weight surface stays current. This is the
    /// value #729's stake-weighted governance tally and #746's param-update
    /// authorization read.
    ///
    /// **Proposer-only**, exactly like [`Self::record_rotated_keys`]: only the
    /// committed block's proposer submits the system txs, so one node — not all N
    /// — authors them. `updates` is the per-block weight delta the staking /
    /// slashing read path computed ([`Self::derive_validator_updates`]); the
    /// `StakeSource` emits a [`ValidatorUpdate`] only when a validator's weight
    /// actually changed, so every entry here is a genuine change and a redundant
    /// same-weight write is already avoided upstream. `recordWeight` overwrites
    /// the validator's weight and adjusts the on-chain `totalWeight` by the delta
    /// (old→new), so a removal (`weight == 0`) drains its share.
    ///
    /// A no-op same-weight write would be harmless (the contract does not reject
    /// it), but submitting one wastes a system tx, so we only submit the changes
    /// `updates` carries. A failed submission is logged, never fatal — consensus
    /// commits regardless of the EL, and the next change re-syncs the surface.
    async fn record_validator_weights(&self, updates: &[ValidatorUpdate]) {
        if updates.is_empty() {
            return;
        }
        // Submit sequentially (awaiting each) so reth's pool reflects the prior
        // tx and the next system-account nonce is fresh — same discipline as
        // `record_rotated_keys`.
        for u in updates {
            let calldata = registry::record_weight_calldata(&u.node_id, u.weight);
            match self
                .submit_system_call(registry::registry_address(), calldata)
                .await
            {
                Ok(hash) => tracing::info!(
                    target: "boule::reth",
                    validator = %hex::encode(u.node_id),
                    weight = u.weight,
                    tx = %hash,
                    "registry write: submitted recordWeight for seated-weight change",
                ),
                Err(e) => tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    validator = %hex::encode(u.node_id),
                    weight = u.weight,
                    "registry write: recordWeight submission failed (re-synced on next change)",
                ),
            }
        }
    }

    /// #732/#767 settled-frontier gate — **conservatively** advance the
    /// `Registry`'s `settledView` so the slashing predeploy can safely gate
    /// proofs (`view <= settledView`) without ever reading a key the registry
    /// has not yet recorded in executed EVM state.
    ///
    /// **Why this is not `recordSettled(committed_view)`.** `keyAt(validator,
    /// view)` is only trustworthy once *every* rotation with `vEff <= view` has
    /// **executed** in EVM state. But a rotation's `recordKey` is an async
    /// system tx that executes some blocks after its commit (the #674 EL
    /// self-sync lag), and `recordSettled` is the same kind of lagged tx — and
    /// the shared system account is written by *different* proposers across
    /// views, so there is no nonce-ordering that guarantees a view-`V` rotation's
    /// `recordKey` executes before a later proposer's `recordSettled(V)`.
    /// Advancing the frontier to the bare committed view could therefore let a
    /// slashing proof verify against a **stale** pre-rotation key. So we make the
    /// frontier conservative on **two** independent axes (prefer a false-negative
    /// — the watcher resubmits once it settles — over ever slashing on a stale
    /// key; #767):
    ///
    /// 1. **Execution confirmation.** Advance only once this node's own pending
    ///    registry writes have *executed*: the system account's `latest`
    ///    (executed) nonce has caught up to its `pending` nonce, so there is no
    ///    in-flight `recordKey` that could leave `keyAt` stale. If writes are
    ///    still in flight, hold the frontier — a later commit re-advances it.
    /// 2. **A view margin.** Even with (1), target
    ///    `committed_view − `[`SETTLED_VIEW_MARGIN`] (not the committed view),
    ///    held `>= MIN_V_EFF_DELAY` views back so a rotation effective at the
    ///    frontier has had ample committed views for its `recordKey` to clear.
    ///
    /// **Proposer-only**, exactly like [`Self::record_rotated_keys`]: only the
    /// committed block's proposer submits the system tx. Submitted *after* this
    /// block's `recordKey`s (the caller orders it last). `recordSettled` clamps
    /// monotonically, so a replayed/older view is a harmless no-op; a failed
    /// submission is logged, never fatal (consensus commits regardless of the
    /// EL, and the next commit re-advances the frontier).
    ///
    /// [`SETTLED_VIEW_MARGIN`]: crate::registry::SETTLED_VIEW_MARGIN
    async fn record_settled_view(&self, committed_view: View) {
        let target = registry::conservative_settled_view(committed_view);
        if target.0 == 0 {
            // Below the margin: nothing is settleable yet (the genesis frontier
            // is already 0). Skip the no-op write.
            return;
        }
        // Axis 1 — execution confirmation. Only advance the frontier once this
        // node's system-account writes have *executed* (no `recordKey` still
        // pending in the pool), so the registry's `keyAt` is caught up to at
        // least every rotation we have already submitted. If a registry-write tx
        // is still in flight, hold the frontier this commit and re-advance later.
        match self.system_account_writes_settled().await {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(
                    target: "boule::reth",
                    target_view = target.0,
                    "registry write: recordSettled held — system-account writes still \
                     in flight (frontier re-advanced once they execute)",
                );
                return;
            }
            Err(e) => {
                // Couldn't confirm execution — be conservative and hold the
                // frontier rather than risk advancing past an unexecuted write.
                tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    target_view = target.0,
                    "registry write: recordSettled held — could not confirm system-account \
                     writes executed (frontier re-advanced when confirmable)",
                );
                return;
            }
        }
        let calldata = registry::record_settled_calldata(target);
        match self
            .submit_system_call(registry::registry_address(), calldata)
            .await
        {
            Ok(hash) => tracing::info!(
                target: "boule::reth",
                target_view = target.0,
                committed_view = committed_view.0,
                tx = %hash,
                "registry write: submitted recordSettled (advanced conservative settled frontier)",
            ),
            Err(e) => tracing::warn!(
                target: "boule::reth",
                error = %e,
                target_view = target.0,
                "registry write: recordSettled submission failed (re-advanced next commit)",
            ),
        }
    }

    /// Whether the system account has **no in-flight** registry writes: its
    /// executed (`latest`) nonce has caught up to its pending nonce. The
    /// settled-frontier advance gates on this (#767) so it never moves
    /// `settledView` past a view whose `recordKey` is still pending in the pool
    /// (which would leave the slashing predeploy's `keyAt` stale at the
    /// frontier). `pending == executed` means every authored `recordKey` /
    /// `recordWeight` has already executed in canonical EVM state.
    async fn system_account_writes_settled(&self) -> Result<bool> {
        let pending = self
            .transport
            .eth_get_transaction_count(system_account::SYSTEM_ACCOUNT_ADDRESS)
            .await
            .context("fetching the system account's pending nonce")?;
        let executed = self
            .transport
            .eth_get_transaction_count_executed(system_account::SYSTEM_ACCOUNT_ADDRESS)
            .await
            .context("fetching the system account's executed nonce")?;
        Ok(executed >= pending)
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

    /// The EVM chain id, read once from reth (`eth_chainId`). Needed to bind a
    /// system tx's signature to this deployment's chain (EIP-155 replay
    /// protection). Reading it from reth (rather than threading the genesis
    /// `chainId` through) keeps the system-tx path self-contained.
    async fn evm_chain_id(&self) -> Result<u64> {
        let result = self
            .transport
            .eth_rpc("eth_chainId", Value::Null)
            .await
            .context("querying reth chain id")?;
        let hex = result
            .as_str()
            .context("eth_chainId result is a hex quantity")?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).context("eth_chainId result not hex")
    }

    /// Build, sign, and submit a system EVM transaction calling `(to,
    /// calldata)` from the system account ([`crate::system_account`]) — the
    /// #732 registry write path's submission primitive. Fetches the EVM chain
    /// id and the system account's pending nonce via the transport, signs an
    /// EIP-1559 tx, and pushes it to reth's pool with `eth_sendRawTransaction`,
    /// returning the transaction hash.
    ///
    /// This is the *capability* only: callers (e.g. recording a rotated key via
    /// `Registry.recordKey`) are a follow-up, as is access control on the
    /// `recordKey` side. See the module-level MVP caveat in
    /// [`crate::system_account`].
    pub async fn submit_system_call(
        &self,
        to: alloy_primitives::Address,
        calldata: alloy_primitives::Bytes,
    ) -> Result<String> {
        let chain_id = self.evm_chain_id().await?;
        let nonce = self
            .transport
            .eth_get_transaction_count(system_account::SYSTEM_ACCOUNT_ADDRESS)
            .await
            .context("fetching the system account's pending nonce")?;
        let raw = system_account::build_system_call(chain_id, nonce, to, calldata)
            .context("building the signed system tx")?;
        let result = self
            .transport
            // `build_system_call` returns alloy's `Bytes`; the transport takes
            // the workspace's `bytes::Bytes` — convert at the seam.
            .send_raw_transaction(raw.0)
            .await
            .context("submitting the system tx")?;
        let hash = result
            .as_str()
            .context("eth_sendRawTransaction returns the tx hash")?
            .to_string();
        Ok(hash)
    }
}

/// Extract the 32-byte post-state root from an execution payload.
fn state_root_of(payload: &Value) -> Result<[u8; 32]> {
    root_from_hex(payload["stateRoot"].as_str().context("payload stateRoot")?)
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
            // A1 EL-applied registry writes (#781): the leader computes the
            // authoritative `(keys, weights, settledView)` write set for this
            // block and hands it to the custom EL on the build attributes. The
            // EL transcribes it into the sealed header `extra_data` and applies
            // `recordKey`/`recordWeight`/`recordSettled` as system calls, so every
            // replica mirrors the identical registry state from the propagated
            // block (no proposer trust — see #777). The pulled-in rotation system
            // txs (`reconfig_cmds` below) feed the key writes; the settled view is
            // the conservative frontier the tx path also computes. Empty for the
            // common no-rotation block, which keeps `extra_data` (and the header)
            // small. This runs alongside the legacy tx-write path in `commit`
            // (the Registry's dual-writer accepts both); the tx path is removed in
            // Phase 3.
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
        ctx: &'a AppContext,
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
            // #732 step 2: only the committed block's proposer mirrors its
            // rotated BLS keys into the on-chain Registry (`recordKey`), so a
            // single node — not all N — authors the system tx. Idempotent
            // regardless (the monotone `vEff` guard reverts duplicates), so a
            // re-proposed block or a restart never corrupts the registry.
            // #732 step 4: the same proposer also mirrors this block's seated
            // validator-weight changes into the Registry (`recordWeight`) — the
            // on-chain weight surface #729's tally and #746's auth read. Each
            // `validator_updates` entry is a genuine weight change (the
            // StakeSource only emits changed validators), so no redundant write.
            // #732/#767 settled-frontier: after mirroring this block's rotated
            // keys, *conservatively* advance the Registry's `settledView` (held
            // a margin behind the committed view and gated on this node's
            // registry writes having executed) so the slashing predeploy never
            // accepts a proof for a view whose rotation's `recordKey` has not yet
            // executed in EVM state (which would leave `keyAt` stale). Called
            // last, after this block's `recordKey`s are submitted.
            if ctx.proposer == self.self_id {
                self.record_rotated_keys(&effects).await;
                self.record_validator_weights(&validator_updates).await;
                self.record_settled_view(block.header.view).await;
            }
            effects.extend(self.derive_endpoint_effects(&payload).await);
            effects.extend(self.derive_param_effects(&payload).await);
            effects.extend(self.derive_governance_effects(&payload).await);
            // #772: prepend the self-synced gap's submission effects (ascending
            // by height) ahead of this block's, so the materialised effect
            // sequence is byte-identical to a node that executed every block in
            // order. The gap rotations' `recordKey` registry writes already
            // executed in the EL during self-sync, so they are NOT re-recorded
            // here (only this block's `effects` feed `record_rotated_keys`).
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

    // ── #732 step 2: proposer-only registry write path ─────────────────────

    /// Transport for the registry-write tests: serves the engine fixtures (so
    /// `commit` reaches VALID), a canned rotation log for `eth_getLogs` at the
    /// rotation predeploy (empty elsewhere), `eth_chainId` / `eth_getTransactionCount`
    /// for the system-tx nonce path, and **records** every `send_raw_transaction`
    /// so a test can assert whether a `recordKey` was authored.
    struct RegistryWriteTransport {
        inner: FixtureTransport,
        rotation_logs: Value,
        sent: Arc<Mutex<Vec<Bytes>>>,
    }
    impl EngineTransport for RegistryWriteTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
            // `eth_chainId` is served as a plain quantity; `eth_getLogs` is keyed
            // on the filter address (rotation logs only at the rotation predeploy).
            if method == "eth_chainId" {
                return Box::pin(async move { Ok(Value::String("0x539".into())) }); // 1337
            }
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
        fn eth_get_transaction_count(&self, _address: &str) -> BoxFuture<'_, Result<u64>> {
            Box::pin(async move { Ok(0) })
        }
        fn eth_get_transaction_count_executed(&self, _address: &str) -> BoxFuture<'_, Result<u64>> {
            // pending == executed: no in-flight registry writes, so the
            // settled-frontier advance is not held by the #767 execution gate.
            Box::pin(async move { Ok(0) })
        }
        fn send_raw_transaction(&self, raw: Bytes) -> BoxFuture<'_, Result<Value>> {
            self.sent.lock().push(raw);
            Box::pin(async move { Ok(Value::String(format!("0x{}", "11".repeat(32)))) })
        }
    }

    /// A real `DualSignedRotation` command carrying a new BLS key, ABI-laid-out
    /// in a rotation log's `data` (signatures zeroed — the read path passes the
    /// bytes through opaquely; `record_key_for_rotation` only decodes).
    fn bls_rotation_log() -> (Value, boule_core::crypto::sig_scheme::BlsPublicKey) {
        use boule_consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};
        use boule_core::crypto::sig_scheme::BlsAggregated;
        let pk = BlsAggregated::keygen(&[0x9a; 32]).unwrap().1;
        let cmd = DualSignedRotation {
            payload: ValidatorKeyRotation {
                validator: [0x42; 32],
                new_pubkey: [0xCC; 32],
                v_eff: View(42),
                new_bls_pubkey: Some(pk),
                new_bls_pop: None,
            },
            sig_old: [0u8; 64],
            sig_new: [0u8; 64],
        }
        .encode_command();
        let logs = serde_json::json!([{
            "topics": [rotation::ROTATION_TOPIC, format!("0x{}", "42".repeat(32))],
            "data": abi_log_bytes(&cmd),
        }]);
        (logs, pk)
    }

    fn app_with_recording(
        self_id: NodeId,
        rotation_logs: Value,
        sent: Arc<Mutex<Vec<Bytes>>>,
    ) -> RethApplication {
        use boule_consensus::replication::stake_source::BondedStakeLedger;
        RethApplication::new(
            Box::new(RegistryWriteTransport {
                inner: FixtureTransport,
                rotation_logs,
                sent,
            }),
            self_id,
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

    /// When this node is the committed block's proposer, a committed BLS-key
    /// rotation writes the new key into the Registry: exactly one `recordKey`
    /// system tx is authored, and it decodes to `recordKey(validator, vEff, key)`
    /// with the key in 128-byte EIP-2537 form.
    #[tokio::test]
    async fn proposer_commit_submits_a_recordkey_for_a_bls_rotation() {
        use alloy_consensus::TxEnvelope;
        use alloy_eips::eip2718::Decodable2718;

        let self_id = [1u8; 32];
        let (rotation_logs, pk) = bls_rotation_log();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = app_with_recording(self_id, rotation_logs, Arc::clone(&sent));

        let g = genesis();
        // commit `ctx.proposer == self_id` ⇒ this node mirrors the rotation.
        let ctx = AppContext {
            proposer: self_id,
            ..Default::default()
        };
        // Commit at a view above the conservative margin so the settled frontier
        // actually advances (#767): below the margin the advance is skipped.
        let view = View(registry::SETTLED_VIEW_MARGIN + 6);
        let block = app
            .build_proposal(&ctx, &g, view, &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        let result = app.commit(&ctx, &block).await.expect("commit");
        assert_eq!(result.effects.len(), 1, "one rotation effect surfaced");

        let sent = sent.lock();
        // The proposer authors two system txs: the recordKey (first) and the
        // per-commit recordSettled frontier advance (#732/#767, last).
        assert_eq!(
            sent.len(),
            2,
            "recordKey + recordSettled system txs authored",
        );

        // Decode the first authored tx and check its calldata is the expected
        // recordKey(validator, vEff, key128).
        let env = TxEnvelope::decode_2718(&mut sent[0].as_ref()).expect("typed tx");
        let tx = match &env {
            TxEnvelope::Eip1559(s) => s.tx(),
            other => panic!("expected EIP-1559, got {other:?}"),
        };
        assert_eq!(
            tx.to,
            alloy_primitives::TxKind::Call(registry::registry_address()),
            "addressed to the Registry predeploy",
        );
        let cd = tx.input.as_ref();
        assert_eq!(
            &cd[0..4],
            &registry::RECORD_KEY_SELECTOR,
            "recordKey selector"
        );
        assert_eq!(&cd[4..36], &[0x42u8; 32], "validator id");
        let mut v_word = [0u8; 32];
        v_word[24..].copy_from_slice(&42u64.to_be_bytes());
        assert_eq!(&cd[36..68], &v_word, "vEff == 42");
        // The key is the 128-byte EIP-2537 form of the rotated pubkey.
        let want_key = boule_core::crypto::sig_scheme::bls_pubkey_to_eip2537_g1(&pk).unwrap();
        assert_eq!(&cd[132..132 + 128], &want_key, "EIP-2537 128-byte key");

        // The second tx is recordSettled(conservative view): the committed view
        // less the #767 margin, not the committed view itself.
        let env2 = TxEnvelope::decode_2718(&mut sent[1].as_ref()).expect("typed tx");
        let tx2 = match &env2 {
            TxEnvelope::Eip1559(s) => s.tx(),
            other => panic!("expected EIP-1559, got {other:?}"),
        };
        assert_eq!(
            tx2.to,
            alloy_primitives::TxKind::Call(registry::registry_address()),
            "recordSettled addressed to the Registry predeploy",
        );
        let cd2 = tx2.input.as_ref();
        assert_eq!(
            &cd2[0..4],
            &registry::RECORD_SETTLED_SELECTOR,
            "recordSettled selector",
        );
        let want = registry::conservative_settled_view(block.header.view).0;
        let mut view_word = [0u8; 32];
        view_word[24..].copy_from_slice(&want.to_be_bytes());
        assert_eq!(
            &cd2[4..36],
            &view_word,
            "recordSettled(committed_view - SETTLED_VIEW_MARGIN)",
        );
    }

    /// A non-proposer commit reads the same rotation effect but writes **nothing**
    /// — only the proposer authors the system tx (no N-fold redundant pool spam).
    #[tokio::test]
    async fn non_proposer_commit_submits_nothing() {
        let self_id = [1u8; 32];
        let (rotation_logs, _) = bls_rotation_log();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = app_with_recording(self_id, rotation_logs, Arc::clone(&sent));

        let g = genesis();
        // ctx.proposer is some *other* node, not self_id.
        let ctx = AppContext {
            proposer: [9u8; 32],
            ..Default::default()
        };
        let block = app
            .build_proposal(&ctx, &g, View(1), &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        let result = app.commit(&ctx, &block).await.expect("commit");
        assert_eq!(
            result.effects.len(),
            1,
            "the rotation effect still surfaces"
        );
        assert!(
            sent.lock().is_empty(),
            "a non-proposer must not author a recordKey",
        );
    }

    // ── #732 step 4: proposer-only registry *weight* write path ────────────

    /// Transport for the weight-write tests: engine fixtures (so `commit`
    /// reaches VALID), a canned staking log at the staking predeploy address
    /// (empty elsewhere) so `derive_validator_updates` produces a weight change,
    /// `eth_chainId` / `eth_getTransactionCount` for the system-tx nonce path,
    /// and **records** every `send_raw_transaction` so a test can assert whether
    /// a `recordWeight` was authored.
    struct WeightWriteTransport {
        inner: FixtureTransport,
        staking_logs: Value,
        sent: Arc<Mutex<Vec<Bytes>>>,
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
        fn eth_get_transaction_count(&self, _address: &str) -> BoxFuture<'_, Result<u64>> {
            Box::pin(async move { Ok(0) })
        }
        fn eth_get_transaction_count_executed(&self, _address: &str) -> BoxFuture<'_, Result<u64>> {
            // pending == executed: no in-flight registry writes (#767 gate open).
            Box::pin(async move { Ok(0) })
        }
        fn send_raw_transaction(&self, raw: Bytes) -> BoxFuture<'_, Result<Value>> {
            self.sent.lock().push(raw);
            Box::pin(async move { Ok(Value::String(format!("0x{}", "22".repeat(32)))) })
        }
    }

    fn weight_app(
        self_id: NodeId,
        staking_logs: Value,
        genesis_stake: Vec<(NodeId, u64)>,
        sent: Arc<Mutex<Vec<Bytes>>>,
    ) -> RethApplication {
        use boule_consensus::replication::stake_source::BondedStakeLedger;
        RethApplication::new(
            Box::new(WeightWriteTransport {
                inner: FixtureTransport,
                staking_logs,
                sent,
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

    /// When this node is the committed block's proposer and the block carries a
    /// seated-weight change (here a Withdraw that drops the validator to weight
    /// 0), it authors exactly one `recordWeight(validator, newWeight)` system tx
    /// addressed to the Registry, with the new (absolute) weight right-aligned.
    #[tokio::test]
    async fn proposer_commit_submits_a_recordweight_for_a_weight_change() {
        use alloy_consensus::TxEnvelope;
        use alloy_eips::eip2718::Decodable2718;

        let self_id = [1u8; 32];
        let node = [2u8; 32];
        // A Withdraw of the full genesis stake (3) → weight 0 (a removal).
        let staking_logs = serde_json::json!([{
            "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": format!("0x{:064x}", 3u64),
        }]);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = weight_app(self_id, staking_logs, vec![(node, 3u64)], Arc::clone(&sent));

        let g = genesis();
        let ctx = AppContext {
            proposer: self_id,
            ..Default::default()
        };
        // Commit above the conservative margin so the frontier advances (#767).
        let view = View(registry::SETTLED_VIEW_MARGIN + 6);
        let block = app
            .build_proposal(&ctx, &g, view, &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        let result = app.commit(&ctx, &block).await.expect("commit");
        assert_eq!(
            result.validator_updates,
            vec![ValidatorUpdate {
                node_id: node,
                weight: 0,
            }],
            "the full Withdraw removes the validator (weight 0)",
        );

        let sent = sent.lock();
        // recordWeight (first) + the per-commit recordSettled frontier advance.
        assert_eq!(
            sent.len(),
            2,
            "recordWeight + recordSettled system txs authored",
        );
        let env = TxEnvelope::decode_2718(&mut sent[0].as_ref()).expect("typed tx");
        let tx = match &env {
            TxEnvelope::Eip1559(s) => s.tx(),
            other => panic!("expected EIP-1559, got {other:?}"),
        };
        assert_eq!(
            tx.to,
            alloy_primitives::TxKind::Call(registry::registry_address()),
            "addressed to the Registry predeploy",
        );
        let cd = tx.input.as_ref();
        assert_eq!(
            &cd[0..4],
            &registry::RECORD_WEIGHT_SELECTOR,
            "recordWeight selector",
        );
        assert_eq!(&cd[4..36], &node, "validator id");
        assert!(cd[36..68].iter().all(|b| *b == 0), "newWeight == 0 word");
        assert_eq!(cd.len(), 4 + 32 * 2, "recordWeight has no dynamic tail");

        // The trailing tx is recordSettled(view) for the committed view (#732).
        let env2 = TxEnvelope::decode_2718(&mut sent[1].as_ref()).expect("typed tx");
        let cd2 = match &env2 {
            TxEnvelope::Eip1559(s) => s.tx().input.as_ref().to_vec(),
            other => panic!("expected EIP-1559, got {other:?}"),
        };
        assert_eq!(
            &cd2[0..4],
            &registry::RECORD_SETTLED_SELECTOR,
            "recordSettled selector",
        );
    }

    /// A non-proposer commit computes the same weight change but writes
    /// **nothing** — only the proposer authors the `recordWeight` tx.
    #[tokio::test]
    async fn non_proposer_commit_submits_no_recordweight() {
        let self_id = [1u8; 32];
        let node = [2u8; 32];
        let staking_logs = serde_json::json!([{
            "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": format!("0x{:064x}", 3u64),
        }]);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = weight_app(self_id, staking_logs, vec![(node, 3u64)], Arc::clone(&sent));

        let g = genesis();
        let ctx = AppContext {
            proposer: [9u8; 32],
            ..Default::default()
        };
        let block = app
            .build_proposal(&ctx, &g, View(1), &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        let result = app.commit(&ctx, &block).await.expect("commit");
        assert_eq!(result.validator_updates.len(), 1, "weight change computed");
        assert!(
            sent.lock().is_empty(),
            "a non-proposer must not author a recordWeight",
        );
    }

    /// A commit with no seated-weight change and no rotation authors no
    /// `recordWeight`/`recordKey` — but the proposer still advances the settled
    /// frontier every commit, so the one and only system tx is `recordSettled`.
    #[tokio::test]
    async fn proposer_commit_with_no_change_writes_only_record_settled() {
        use alloy_consensus::TxEnvelope;
        use alloy_eips::eip2718::Decodable2718;

        let self_id = [1u8; 32];
        let sent = Arc::new(Mutex::new(Vec::new()));
        // No staking logs ⇒ no weight delta; no rotation logs ⇒ no recordKey.
        let app = weight_app(self_id, Value::Array(Vec::new()), vec![], Arc::clone(&sent));

        let g = genesis();
        let ctx = AppContext {
            proposer: self_id,
            ..Default::default()
        };
        // Above the conservative margin so the frontier advance fires (#767).
        let view = View(registry::SETTLED_VIEW_MARGIN + 6);
        let block = app
            .build_proposal(&ctx, &g, view, &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        let result = app.commit(&ctx, &block).await.expect("commit");
        assert!(result.validator_updates.is_empty(), "no weight change");

        let sent = sent.lock();
        assert_eq!(
            sent.len(),
            1,
            "only the per-commit recordSettled frontier advance",
        );
        let env = TxEnvelope::decode_2718(&mut sent[0].as_ref()).expect("typed tx");
        let cd = match &env {
            TxEnvelope::Eip1559(s) => s.tx().input.as_ref().to_vec(),
            other => panic!("expected EIP-1559, got {other:?}"),
        };
        assert_eq!(
            &cd[0..4],
            &registry::RECORD_SETTLED_SELECTOR,
            "the lone system tx is recordSettled",
        );
        let want = registry::conservative_settled_view(block.header.view).0;
        let mut view_word = [0u8; 32];
        view_word[24..].copy_from_slice(&want.to_be_bytes());
        assert_eq!(
            &cd[4..36],
            &view_word,
            "recordSettled(committed_view - SETTLED_VIEW_MARGIN)",
        );
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
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = weight_app(self_id, staking_logs, vec![(node, 3u64)], Arc::clone(&sent));

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
        let app = weight_app(
            self_id,
            Value::Array(Vec::new()),
            vec![],
            Arc::new(Mutex::new(Vec::new())),
        );
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

    /// #767 — below the conservative margin nothing is settleable, so the
    /// proposer authors **no** recordSettled (the frontier stays at the genesis
    /// 0). A commit at view 1 (< SETTLED_VIEW_MARGIN) writes nothing.
    #[tokio::test]
    async fn proposer_commit_below_margin_writes_no_record_settled() {
        let self_id = [1u8; 32];
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = weight_app(self_id, Value::Array(Vec::new()), vec![], Arc::clone(&sent));

        let g = genesis();
        let ctx = AppContext {
            proposer: self_id,
            ..Default::default()
        };
        // View 1 is below the margin → conservative_settled_view == 0 → skipped.
        let block = app
            .build_proposal(&ctx, &g, View(1), &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        app.commit(&ctx, &block).await.expect("commit");
        assert!(
            sent.lock().is_empty(),
            "no recordSettled below the conservative margin",
        );
    }

    /// #767 execution gate — when the system account has **in-flight** registry
    /// writes (its pending nonce is ahead of its executed nonce), the proposer
    /// holds the settled frontier and authors no recordSettled, even above the
    /// margin: advancing then could leave `keyAt` stale for a not-yet-executed
    /// `recordKey`.
    #[tokio::test]
    async fn proposer_holds_settled_frontier_while_writes_in_flight() {
        let self_id = [1u8; 32];
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = RethApplication::new(
            Box::new(InFlightWritesTransport {
                inner: FixtureTransport,
                sent: Arc::clone(&sent),
            }),
            self_id,
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
        let ctx = AppContext {
            proposer: self_id,
            ..Default::default()
        };
        // Above the margin, so only the execution gate can hold the advance.
        let view = View(registry::SETTLED_VIEW_MARGIN + 6);
        let block = app
            .build_proposal(&ctx, &g, view, &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        app.commit(&ctx, &block).await.expect("commit");
        assert!(
            sent.lock().is_empty(),
            "recordSettled held while system-account writes are still pending (#767)",
        );
    }

    /// Transport modelling a system account with an in-flight registry write:
    /// `pending` nonce (5) is ahead of the `latest`/executed nonce (3). No
    /// staking/rotation logs, so the only thing a proposer commit could write is
    /// recordSettled — which the #767 execution gate must hold.
    struct InFlightWritesTransport {
        inner: FixtureTransport,
        sent: Arc<Mutex<Vec<Bytes>>>,
    }
    impl EngineTransport for InFlightWritesTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, method: &str, _params: Value) -> BoxFuture<'_, Result<Value>> {
            if method == "eth_chainId" {
                return Box::pin(async move { Ok(Value::String("0x539".into())) });
            }
            Box::pin(async move { Ok(Value::Array(Vec::new())) })
        }
        fn eth_get_transaction_count(&self, _address: &str) -> BoxFuture<'_, Result<u64>> {
            Box::pin(async move { Ok(5) }) // pending ahead of executed
        }
        fn eth_get_transaction_count_executed(&self, _address: &str) -> BoxFuture<'_, Result<u64>> {
            Box::pin(async move { Ok(3) }) // executed lags pending → writes in flight
        }
        fn send_raw_transaction(&self, raw: Bytes) -> BoxFuture<'_, Result<Value>> {
            // Record so an accidental recordSettled submission is observable
            // (the test asserts none is authored while writes are in flight).
            self.sent.lock().push(raw);
            Box::pin(async move { Ok(Value::String(format!("0x{}", "33".repeat(32)))) })
        }
    }
}
