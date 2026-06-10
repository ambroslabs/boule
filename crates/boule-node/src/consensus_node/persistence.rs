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

pub const STORAGE_KEY_LAST_VOTED_VIEW: &[u8] = b"consensus/last_voted_view";

pub const STORAGE_KEY_LOCKED: &[u8] = b"consensus/locked";

pub const STORAGE_KEY_HIGH_QC: &[u8] = b"consensus/high_qc";

pub const STORAGE_KEY_PROPOSED_IN_VIEW: &[u8] = b"consensus/proposed_in_view";

pub const STORAGE_KEY_LAST_TIMEOUT_VOTE: &[u8] = b"consensus/last_timeout_vote";

pub const STORAGE_KEY_BLOCK_PREFIX: &[u8] = b"consensus/block/";

pub const STORAGE_KEY_HEIGHT_PREFIX: &[u8] = b"consensus/height/";

pub const STORAGE_KEY_LAST_COMMITTED: &[u8] = b"consensus/last_committed";

pub const STORAGE_KEY_VALIDATOR_HISTORY: &[u8] = b"consensus/validator_history";

pub const STORAGE_KEY_VALIDATOR_KEY_HISTORY: &[u8] = b"consensus/validator_key_history";

pub const STORAGE_KEY_BLS_KEY_HISTORY: &[u8] = b"consensus/bls_key_history";

pub const STORAGE_KEY_OPERATOR_KEY_HISTORY: &[u8] = b"consensus/operator_key_history";

pub const STORAGE_KEY_COMMITTED_EVIDENCE: &[u8] = b"consensus/committed_evidence";

pub const STORAGE_KEY_PARAM_HISTORY: &[u8] = b"consensus/param_history";

pub const STORAGE_KEY_ENDPOINT_REGISTRY: &[u8] = b"consensus/endpoint_registry";

pub const RECENT_QC_CACHE_CAPACITY: usize = 32;

#[derive(Default)]
pub(super) struct RecentQcCache {
    map: HashMap<BlockHash, QuorumCertificate>,
    order: VecDeque<BlockHash>,
}

impl RecentQcCache {
    pub(super) fn insert(&mut self, hash: BlockHash, qc: QuorumCertificate, capacity: usize) {
        if self.map.insert(hash, qc).is_none() {
            self.order.push_back(hash);

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

pub fn encode_voted_view(view: View) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&view).context("encode last_voted_view")
}

pub fn decode_voted_view(bytes: &[u8]) -> anyhow::Result<View> {
    postcard::from_bytes(bytes).context("decode last_voted_view")
}

pub fn encode_locked(locked: &Locked) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(locked).context("encode locked")
}

pub fn decode_locked(bytes: &[u8]) -> anyhow::Result<Locked> {
    postcard::from_bytes(bytes).context("decode locked")
}

pub fn encode_high_qc(qc: &QuorumCertificate) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(qc).context("encode high_qc")
}

pub fn decode_high_qc(bytes: &[u8]) -> anyhow::Result<QuorumCertificate> {
    postcard::from_bytes(bytes).context("decode high_qc")
}

pub fn encode_proposed_in_view(view: View) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&view).context("encode proposed_in_view")
}

pub fn decode_proposed_in_view(bytes: &[u8]) -> anyhow::Result<View> {
    postcard::from_bytes(bytes).context("decode proposed_in_view")
}

pub fn encode_last_timeout_vote(payload: &TimeoutVote) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(payload).context("encode last_timeout_vote")
}

pub fn decode_last_timeout_vote(bytes: &[u8]) -> anyhow::Result<TimeoutVote> {
    postcard::from_bytes(bytes).context("decode last_timeout_vote")
}

pub fn block_storage_key(hash: &BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_BLOCK_PREFIX.len() + hash.len());
    key.extend_from_slice(STORAGE_KEY_BLOCK_PREFIX);
    key.extend_from_slice(hash);
    key
}

pub fn height_storage_key(height: Height) -> Vec<u8> {
    let raw = height.0.to_be_bytes();
    let mut key = Vec::with_capacity(STORAGE_KEY_HEIGHT_PREFIX.len() + raw.len());
    key.extend_from_slice(STORAGE_KEY_HEIGHT_PREFIX);
    key.extend_from_slice(&raw);
    key
}

pub fn decode_height_storage_key(key: &[u8]) -> Option<Height> {
    let suffix = key.strip_prefix(STORAGE_KEY_HEIGHT_PREFIX)?;
    let bytes: [u8; 8] = suffix.try_into().ok()?;
    Some(Height(u64::from_be_bytes(bytes)))
}

pub fn encode_block(block: &Block) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(block).context("encode committed block")
}

pub fn decode_block(bytes: &[u8]) -> anyhow::Result<Block> {
    postcard::from_bytes(bytes).context("decode committed block")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCommitted {
    pub height: Height,
    pub view: View,
    pub last_committed_hash: BlockHash,
}

pub fn encode_last_committed(lc: &LastCommitted) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(lc).context("encode last_committed")
}

pub fn decode_last_committed(bytes: &[u8]) -> anyhow::Result<LastCommitted> {
    postcard::from_bytes(bytes).context("decode last_committed")
}

pub fn recover_state(
    storage: &dyn Storage,
    validator_set: ValidatorSet,
    genesis: Block,
) -> anyhow::Result<HotStuffState> {
    let boot_qc = genesis_qc(&genesis, &validator_set);
    let mut state = HotStuffState::new(validator_set, genesis);

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
        state.high_qc = Some(VerifiedQc::unchecked(decode_high_qc(&raw)?));
    }

    if let Some(qc) = state.high_qc.as_ref().cloned() {
        rehydrate_ancestors(storage, &mut state, qc.block_hash())?;
    }
    if let Some(locked) = state.locked {
        rehydrate_ancestors(storage, &mut state, locked.block_hash)?;
    }

    Ok(state)
}

const RECOVER_PARENT_HOPS: usize = 2;

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

        if h == Height::ZERO {
            break;
        }
        cursor = parent;
    }

    collected.reverse();
    Ok(collected)
}

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
                    None
                } else {
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

pub(super) fn genesis_only_operator_seed(
    loaded: &boule_consensus::operator_key_history::OperatorKeyHistory,
) -> boule_consensus::operator_key_history::OperatorKeyHistory {
    use boule_consensus::operator_key_history::{
        OperatorKeyHistory, PersistedOperatorKeyEntry, PersistedOperatorKeyHistory,
        PersistedOperatorValidator,
    };
    let persisted = loaded.to_persisted();
    let genesis_only = PersistedOperatorKeyHistory {
        validators: persisted
            .validators
            .into_iter()
            .filter_map(|v| {
                let mut v0_entries: Vec<PersistedOperatorKeyEntry> = v
                    .entries
                    .into_iter()
                    .filter(|e| e.v_eff == View::ZERO)
                    .collect();
                if v0_entries.is_empty() {
                    None
                } else {
                    v0_entries.truncate(1);
                    Some(PersistedOperatorValidator {
                        stable_id: v.stable_id,
                        entries: v0_entries,
                    })
                }
            })
            .collect(),
    };
    OperatorKeyHistory::from_persisted(genesis_only)
        .expect("genesis-only operator seed has valid invariants by construction")
}

impl ConsensusNode {
    pub fn verify_persisted_history_consistency(&self) -> anyhow::Result<()> {
        use boule_consensus::history_commitment::{
            apply_reconfig_commands_to_set_history, apply_rotation_commands_to_histories,
            validator_history_commitment_v2,
        };
        use boule_consensus::validator_history::ValidatorSetHistory;
        use boule_consensus::validator_key_history::ValidatorKeyHistory;

        let last_committed = match self
            .storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .context("read last_committed from storage")?
        {
            Some(raw) => decode_last_committed(&raw)?,
            None => return Ok(()),
        };
        if last_committed.height == Height::ZERO {
            return Ok(());
        }

        let configured_genesis_hash = self.core.state().genesis_hash;
        let mut chain: Vec<Block> = Vec::new();
        let mut cursor = last_committed.last_committed_hash;
        loop {
            let block = if cursor == configured_genesis_hash {
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

        let genesis_weighted: Vec<(boule_consensus::validator_set::ValidatorId, u64)> = self
            .validator_history
            .iter()
            .next()
            .map(|(_, set)| set.iter_weighted().map(|(id, w)| (*id, w)).collect())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator history rebuild: loaded validator_history is empty (no genesis \
                     boundary)"
                )
            })?;

        let genesis_seed_set = ValidatorSet::with_weights(genesis_weighted).map_err(|e| {
            anyhow::anyhow!("validator history rebuild: genesis seed set construction failed: {e}")
        })?;
        let _ = chain.first().expect("non-empty chain");
        let mut rebuilt_set = ValidatorSetHistory::from_genesis(genesis_seed_set.clone());
        let mut rebuilt_key = ValidatorKeyHistory::new(genesis_seed_set.iter().copied());

        let mut rebuilt_bls = self.bls_key_history.as_ref().map(genesis_only_bls_seed);

        let mut rebuilt_operator = genesis_only_operator_seed(&self.operator_key_history);

        for block in &chain {
            apply_reconfig_commands_to_set_history(
                block,
                &mut rebuilt_set,
                &mut rebuilt_key,
                Some(&mut rebuilt_operator),
                rebuilt_bls.as_mut(),
                self.min_v_eff_delay,
                &self.chain_id,
            );
            apply_rotation_commands_to_histories(
                block,
                &rebuilt_set,
                &mut rebuilt_key,
                rebuilt_bls.as_mut(),
                Some(&mut rebuilt_operator),
                &self.chain_id,
            );
            let claimed = block.header.validator_history_commitment;

            let actual = validator_history_commitment_v2(
                &rebuilt_set,
                &rebuilt_key,
                rebuilt_bls.as_ref(),
                Some(&rebuilt_operator),
            );
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

    pub fn persist_updates(&self, updates: &[StateUpdate]) -> anyhow::Result<()> {
        if updates.is_empty() {
            return Ok(());
        }

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
