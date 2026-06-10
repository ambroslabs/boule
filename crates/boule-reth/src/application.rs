use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::reconfig::ReconfigCommand;
use boule_consensus::replication::application::{
    AppContext, Application, CommitResult, IntegrationCapability, RecentBlocks, ValidatorEffect,
    ValidatorUpdate,
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

const SYSTEM_TX_LIMIT: usize = 16;

struct Committed {
    height: Height,
    state_root: [u8; 32],
}

pub struct RethApplication {
    transport: Box<dyn EngineTransport>,
    self_id: NodeId,
    fee_recipient: String,

    reth_genesis_hash: String,

    build_wait: Duration,
    committed: Mutex<Committed>,

    stake_source: Mutex<Box<dyn StakeSource>>,

    mempool: Arc<dyn Mempool>,

    pending_weights: Mutex<std::collections::BTreeMap<NodeId, u64>>,

    recent_committed: Mutex<std::collections::VecDeque<(BlockHash, String)>>,
}

impl RethApplication {
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
            recent_committed: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    fn engine(&self) -> RethEngine<'_> {
        RethEngine::new(&*self.transport, self.fee_recipient.clone())
    }

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
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    target: "boule::reth",
                    error = %e,
                    "EL registry write: undecodable rotation command at build; skipping recordKey",
                ),
            }
        }

        let weights: Vec<ValidatorUpdate> = self
            .pending_weights
            .lock()
            .iter()
            .map(|(&node_id, &weight)| ValidatorUpdate { node_id, weight })
            .collect();

        crate::registry_payload::RegistryPayload::new(keys, &weights, settled_view)
    }

    fn validate_registry_extra_data(&self, block: &Block, recent: &dyn RecentBlocks) -> Result<()> {
        let Some(cmd) = block.commands.first() else {
            return Ok(());
        };
        let payload: Value = serde_json::from_slice(cmd)
            .context("proposed block command is not a JSON execution payload")?;
        let proposed = extra_data_registry_payload(&payload);

        let expected_keys = registry_keys_from_commands(&block.commands);
        let expected_settled = {
            let settled = registry::conservative_settled_view(block.header.view);
            if settled.0 == 0 { None } else { Some(settled) }
        };

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

        let proposed_weights = proposed
            .as_ref()
            .map(|p| p.weights.clone())
            .unwrap_or_default();
        self.validate_weight_proofs(block, recent, &proposed_weights)?;
        Ok(())
    }

    fn validate_weight_proofs(
        &self,
        block: &Block,
        recent: &dyn RecentBlocks,
        proposed_weights: &[(NodeId, u64)],
    ) -> Result<()> {
        if proposed_weights.is_empty() {
            return Ok(());
        }

        let proof_set = block
            .commands
            .iter()
            .find(|c| crate::weight_proof::WeightProofSet::is_weight_proof_command(c))
            .and_then(|c| crate::weight_proof::WeightProofSet::decode(c))
            .unwrap_or_default();

        let resolve = |anchor: &BlockHash| -> Option<([u8; 32], Height)> {
            let src = recent.get(anchor)?;
            let root = block_receipts_root(&src)?;
            Some((root, src.header.height))
        };
        proof_set.verify_against_recent(proposed_weights, block.header.height, &resolve)
    }

    async fn build_weight_proofs(
        &self,
        weights: &[(NodeId, u64)],
        candidates: &[(BlockHash, String)],
    ) -> Result<crate::weight_proof::WeightProofSet> {
        let mut receipts_cache: Vec<Option<Value>> = vec![None; candidates.len()];
        let mut proofs = Vec::new();
        'delta: for &(node_id, weight) in weights {
            for (i, (boule_hash, evm_hash)) in candidates.iter().enumerate() {
                if receipts_cache[i].is_none() {
                    match self
                        .transport
                        .eth_rpc("eth_getBlockReceipts", serde_json::json!([evm_hash]))
                        .await
                    {
                        Ok(r) => receipts_cache[i] = Some(r),
                        Err(e) => {
                            tracing::warn!(
                                target: "boule::reth",
                                error = %e,
                                evm_block = %evm_hash,
                                "weight proof: eth_getBlockReceipts(source candidate) failed",
                            );

                            receipts_cache[i] = Some(serde_json::json!([]));
                        }
                    }
                }
                let receipts = receipts_cache[i].as_ref().expect("just populated");
                if let Some(proof) = crate::weight_proof::WeightProof::generate_one(
                    node_id,
                    weight,
                    *boule_hash,
                    receipts,
                )? {
                    proofs.push(proof);
                    continue 'delta;
                }
            }

            tracing::warn!(
                target: "boule::reth",
                validator = %hex::encode(node_id),
                weight,
                candidate_blocks = candidates.len(),
                "weight proof: NO backing receipt found for delta across the source-candidate \
                 window; voters will reject this weight (#797) — liveness risk",
            );
        }
        Ok(crate::weight_proof::WeightProofSet { proofs })
    }

    fn detect_weight_extra_data_divergence(&self, payload: &Value, height: Height) -> bool {
        let carried: Vec<(NodeId, u64)> = extra_data_registry_payload(payload)
            .map(|p| p.weights)
            .unwrap_or_default();

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

    fn reconcile_pending_weights(&self, payload: &Value, new_updates: &[ValidatorUpdate]) {
        let carried = payload["extraData"]
            .as_str()
            .map(|s| s.trim_start_matches("0x"))
            .and_then(|s| hex::decode(s).ok())
            .and_then(|bytes| crate::registry_payload::RegistryPayload::decode(&bytes))
            .map(|p| p.weights)
            .unwrap_or_default();

        let mut pending = self.pending_weights.lock();

        for (validator, weight) in carried {
            if pending.get(&validator) == Some(&weight) {
                pending.remove(&validator);
            }
        }

        for u in new_updates {
            pending.insert(u.node_id, u.weight);
        }
    }

    async fn get_logs_retry(&self, filter: Value, kind: &str) -> Result<Value> {
        const ATTEMPTS: u32 = 4;
        const BASE: Duration = Duration::from_millis(80);
        let mut last_err = None;
        for attempt in 0..ATTEMPTS {
            match self.transport.eth_rpc("eth_getLogs", filter.clone()).await {
                Ok(logs) => return Ok(logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        kind,
                        attempt = attempt + 1,
                        max_attempts = ATTEMPTS,
                        error = %e,
                        "eth_getLogs failed; retrying (validator-set deltas must not be dropped)",
                    );
                    last_err = Some(e);
                    if attempt + 1 < ATTEMPTS {
                        let wait = BASE.saturating_mul(1 << attempt);
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
        let err = last_err.unwrap_or_else(|| anyhow::anyhow!("eth_getLogs exhausted retries"));
        tracing::error!(
            target: "boule::reth",
            kind,
            error = %err,
            "BFT-SAFETY: eth_getLogs for validator-set deltas FAILED after all retries; \
             this node may drop a delta others applied — registry divergence risk (#803/#772)",
        );
        Err(err)
    }

    async fn derive_validator_updates(
        &self,
        payload: &Value,
        height: Height,
    ) -> Vec<ValidatorUpdate> {
        let block_hash = payload["blockHash"].as_str();

        let ops = match block_hash {
            Some(block_hash) => match self
                .get_logs_retry(staking::logs_filter(block_hash), "staking")
                .await
            {
                Ok(logs) => staking::parse_stake_logs(&logs),

                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };

        let slashed = match block_hash {
            Some(block_hash) => match self
                .get_logs_retry(slashing::logs_filter(block_hash), "slashing")
                .await
            {
                Ok(logs) => slashing::parse_slashed_logs(&logs),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        let mut src = self.stake_source.lock();

        src.advance_to_height(height);
        for (node_id, op) in ops {
            src.apply(node_id, op);
        }

        for node_id in slashed {
            src.slash(node_id);
        }
        src.take_updates()
    }

    async fn derive_predeploy_effects(
        &self,
        block_hash: &str,
        filter: Value,
        parse: fn(&Value) -> Vec<bytes::Bytes>,
        wrap: fn(bytes::Bytes) -> ValidatorEffect,
        kind: &str,
    ) -> Vec<ValidatorEffect> {
        let _ = block_hash;
        let logs = match self.get_logs_retry(filter, kind).await {
            Ok(logs) => logs,

            Err(_) => return Vec::new(),
        };
        parse(&logs).into_iter().map(wrap).collect()
    }

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

    async fn backfill_self_synced_gap(
        &self,
        payload: &Value,
        prev_height: Height,
        height: Height,
    ) -> Vec<ValidatorEffect> {
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

        for h in (prev_height.0 + 1)..height.0 {
            let evm_number = current_number - (height.0 - h);

            let ops = match self
                .get_logs_retry(
                    staking::logs_filter_by_number(evm_number),
                    "staking (self-sync gap)",
                )
                .await
            {
                Ok(logs) => staking::parse_stake_logs(&logs),
                Err(_) => Vec::new(),
            };
            let slashed = match self
                .get_logs_retry(
                    slashing::logs_filter_by_number(evm_number),
                    "slashing (self-sync gap)",
                )
                .await
            {
                Ok(logs) => slashing::parse_slashed_logs(&logs),
                Err(_) => Vec::new(),
            };
            {
                let mut src = self.stake_source.lock();

                src.advance_to_height(Height(h));
                for (node_id, op) in ops {
                    src.apply(node_id, op);
                }
                for node_id in slashed {
                    src.slash(node_id);
                }
            }

            gap_effects.extend(self.derive_gap_predeploy_effects(evm_number).await);
        }
        gap_effects
    }

    async fn derive_gap_predeploy_effects(&self, evm_number: u64) -> Vec<ValidatorEffect> {
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

    pub fn recover_frontier(&self, height: Height, state_root: [u8; 32]) {
        let mut c = self.committed.lock();
        c.height = height;
        c.state_root = state_root;
    }

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

fn state_root_of(payload: &Value) -> Result<[u8; 32]> {
    root_from_hex(payload["stateRoot"].as_str().context("payload stateRoot")?)
}

fn parse_block_number(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn block_receipts_root(block: &Block) -> Option<[u8; 32]> {
    let cmd = block.commands.first()?;
    let payload: Value = serde_json::from_slice(cmd).ok()?;
    let root_hex = payload["receiptsRoot"].as_str()?;
    root_from_hex(root_hex).ok()
}

fn extra_data_registry_payload(
    payload: &Value,
) -> Option<crate::registry_payload::RegistryPayload> {
    payload["extraData"]
        .as_str()
        .map(|s| s.trim_start_matches("0x"))
        .and_then(|s| hex::decode(s).ok())
        .and_then(|bytes| crate::registry_payload::RegistryPayload::decode(&bytes))
}

fn registry_keys_from_commands(commands: &[Bytes]) -> Vec<crate::registry::RecordKey> {
    commands
        .iter()
        .filter_map(|cmd| registry::record_key_for_rotation(cmd).ok().flatten())
        .collect()
}

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

fn weight_proof_source_candidates(
    parent: &Block,
    pending_blocks: &HashMap<BlockHash, Block>,
    committed_height: Height,
    parent_evm_hash: String,
    recent_committed: &std::collections::VecDeque<(BlockHash, String)>,
) -> Vec<(BlockHash, String)> {
    let max = crate::weight_proof::MAX_WEIGHT_PROOF_ANCHOR_LAG as usize;
    let mut out = Vec::new();
    let mut cursor = parent;

    out.push((parent.hash(), parent_evm_hash));

    while out.len() < max {
        if cursor.header.height.0 <= committed_height.0 {
            break;
        }
        let Some(next) = pending_blocks.get(&cursor.header.parent_hash) else {
            break;
        };
        cursor = next;
        if let Some(evm_hash) = evm_block_hash_of(cursor) {
            out.push((cursor.hash(), evm_hash));
        }
    }

    for (boule_hash, evm_hash) in recent_committed.iter().rev() {
        if out.len() >= max {
            break;
        }
        if out.iter().any(|(h, _)| h == boule_hash) {
            continue;
        }
        out.push((*boule_hash, evm_hash.clone()));
    }
    out
}

fn evm_block_hash_of(block: &Block) -> Option<String> {
    let cmd = block.commands.first()?;
    let payload: Value = serde_json::from_slice(cmd).ok()?;
    payload["blockHash"].as_str().map(|s| s.to_string())
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
            let (committed_height, committed_state_root) = {
                let c = self.committed.lock();
                (c.height, c.state_root)
            };

            let (parent_evm_hash, parent_evm_ts) = self.parent_evm_anchor(parent)?;

            let evm_ts = (parent_evm_ts + 1).max(timestamp / 1000);

            let engine = self.engine();

            for ancestor in uncommitted_chain(parent, pending_blocks, committed_height) {
                if let Some(cmd) = ancestor.commands.first() {
                    let payload: Value = serde_json::from_slice(cmd)
                        .context("uncommitted ancestor command is not a JSON execution payload")?;
                    if engine.register_payload(&payload).await? == ElStatus::Syncing {
                        anyhow::bail!(
                            "reth EL still syncing the uncommitted ancestor chain (height {}); \
                             skipping proposal for view {}",
                            ancestor.header.height.0,
                            view.0,
                        );
                    }
                }
            }

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

            engine.register_payload(&built.execution_payload).await?;

            let mut commands = vec![Bytes::from(
                serde_json::to_vec(&built.execution_payload)
                    .context("serializing the EVM execution payload")?,
            )];

            for cmd in reconfig_cmds {
                if ReconfigCommand::is_reconfig_payload(&cmd)
                    || DualSignedRotation::is_rotation_payload(&cmd)
                    || boule_consensus::validator_rotation::DualSignedRotationCancel::is_cancel_payload(&cmd)
                    || boule_consensus::validator_rotation::OperatorSignedRotation::is_operator_rotation_payload(&cmd)
                    || boule_consensus::validator_rotation::DualSignedOperatorRotation::is_operator_key_rotation_payload(&cmd)

                    || boule_consensus::equivocation_evidence::is_evidence_payload(&cmd)

                    || boule_consensus::endpoint_registry::SignedEndpointCommand::is_endpoint_payload(&cmd)

                    || boule_consensus::consensus_params::ConsensusParamUpdate::is_param_update_payload(&cmd)
                {
                    commands.push(cmd);
                }
            }

            if !registry_payload.weights.is_empty() {
                let recent_committed = self.recent_committed.lock().clone();
                let candidates = weight_proof_source_candidates(
                    parent,
                    pending_blocks,
                    committed_height,
                    parent_evm_hash.clone(),
                    &recent_committed,
                );
                match self
                    .build_weight_proofs(&registry_payload.weights, &candidates)
                    .await
                {
                    Ok(set) if !set.is_empty() => commands.push(Bytes::from(set.encode())),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        target: "boule::reth",
                        error = %e,
                        "weight proof: failed to build receipt proofs; \
                         weights deferred to commit-time detection (#797)",
                    ),
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
                return Ok(CommitResult::default());
            };
            let payload: Value = serde_json::from_slice(cmd)
                .context("committed block command is not a JSON execution payload")?;
            let new_root = state_root_of(&payload)?;

            let exec = self.engine().register_payload(&payload).await?;
            let status = if exec == ElStatus::Valid {
                self.engine().forkchoice(&payload).await?
            } else {
                ElStatus::Syncing
            };

            let mut gap_effects: Vec<ValidatorEffect>;
            match status {
                ElStatus::Valid => {
                    let prev_height = {
                        let mut c = self.committed.lock();
                        let prev = c.height;
                        c.height = block.header.height;
                        c.state_root = new_root;
                        prev
                    };

                    gap_effects = self
                        .backfill_self_synced_gap(&payload, prev_height, block.header.height)
                        .await;

                    if let Some(evm_hash) = payload["blockHash"].as_str() {
                        let mut ring = self.recent_committed.lock();
                        ring.push_back((block.hash(), evm_hash.to_string()));

                        let cap = (crate::weight_proof::MAX_WEIGHT_PROOF_ANCHOR_LAG as usize) + 2;
                        while ring.len() > cap {
                            ring.pop_front();
                        }
                    }
                }
                ElStatus::Syncing => {
                    tracing::info!(
                        target: "boule::reth",
                        height = block.header.height.0,
                        "reth EL syncing toward committed block; frontier + staking held until VALID",
                    );
                    return Ok(CommitResult::default());
                }
            }

            let validator_updates = self
                .derive_validator_updates(&payload, block.header.height)
                .await;

            self.detect_weight_extra_data_divergence(&payload, block.header.height);

            self.reconcile_pending_weights(&payload, &validator_updates);

            let mut effects = self.derive_rotation_effects(&payload).await;

            effects.extend(self.derive_endpoint_effects(&payload).await);
            effects.extend(self.derive_param_effects(&payload).await);
            effects.extend(self.derive_governance_effects(&payload).await);

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

    fn validate_proposal<'a>(
        &'a self,
        block: &'a Block,
        recent: &'a dyn RecentBlocks,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.validate_registry_extra_data(block, recent) })
    }

    fn check(&self, cmd: &[u8]) -> Result<()> {
        if crate::weight_proof::WeightProofSet::is_weight_proof_command(cmd) {
            return Ok(());
        }

        let payload: Value =
            serde_json::from_slice(cmd).context("command is not a JSON execution payload")?;
        payload
            .get("blockHash")
            .and_then(|v| v.as_str())
            .context("execution payload is missing blockHash")?;
        Ok(())
    }

    fn slash(&self, node_id: NodeId) {
        self.stake_source.lock().slash(node_id);
    }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        vec![
            IntegrationCapability::Membership,
            IntegrationCapability::Slashing,
            IntegrationCapability::KeyRotation,
            IntegrationCapability::EndpointAdvertisement,
            IntegrationCapability::ParameterUpdates,
        ]
    }

    fn executed_height(&self) -> Option<Height> {
        Some(self.committed.lock().height)
    }

    fn el_head<'a>(&'a self) -> BoxFuture<'a, Option<Height>> {
        Box::pin(async move {
            match self
                .transport
                .eth_rpc("eth_blockNumber", serde_json::json!([]))
                .await
            {
                Ok(v) => match parse_block_number(&v) {
                    Some(h) => Some(Height(h)),
                    None => {
                        tracing::warn!(
                            target: "boule::reth",
                            result = %v,
                            "el_head: eth_blockNumber returned an unparseable result; \
                             EL-catch-up will fall back to the tracked frontier",
                        );
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        error = %e,
                        "el_head: eth_blockNumber query failed; \
                         EL-catch-up will fall back to the tracked frontier",
                    );
                    None
                }
            }
        })
    }

    fn el_devp2p_handoff<'a>(&'a self, tip: &'a Block) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(cmd) = tip.commands.first() else {
                return Ok(());
            };
            let payload: Value = serde_json::from_slice(cmd)
                .context("el_devp2p_handoff: tip is not a JSON payload")?;
            let _ = self.engine().register_payload(&payload).await?;
            let status = self.engine().forkchoice(&payload).await?;
            tracing::info!(
                target: "boule::reth",
                height = tip.header.height.0,
                ?status,
                "el_devp2p_handoff: pointed reth at the committed tip for devp2p self-sync (#831)",
            );
            Ok(())
        })
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
