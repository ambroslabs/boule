use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hotstuff::QuorumCertificate;
use crate::replication::block::{Block, BlockHash};
use crate::validator_set::ValidatorSet;
use crate::{Height, View};
use boule_core::identity::NodeId;
use boule_core::storage::{Storage, StorageExt};

pub const STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX: &[u8] = b"consensus/snap/manifest/";

pub const STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX: &[u8] = b"consensus/snap/chunk/";

pub const STORAGE_KEY_SNAPSHOT_LATEST: &[u8] = b"consensus/snap/latest";

pub const SNAPSHOT_FORMAT_VERSION: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub version: u8,

    pub height: Height,

    pub view: View,

    pub block_hash: BlockHash,

    pub state_commitment: [u8; 32],

    pub validator_set: Vec<NodeId>,

    pub chunk_size: u32,

    pub chunk_count: u32,

    pub chunk_hashes: Vec<[u8; 32]>,

    pub commit_qc: QuorumCertificate,

    pub block: Block,

    pub created_unix_secs: u64,

    pub validator_history: crate::validator_history::PersistedValidatorHistory,

    pub validator_key_history: crate::validator_key_history::PersistedValidatorKeyHistory,

    pub bls_key_history: Option<crate::bls_key_history::PersistedBlsKeyHistory>,

    pub operator_key_history: Option<crate::operator_key_history::PersistedOperatorKeyHistory>,
}

impl SnapshotManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        block: Block,
        validator_set: &ValidatorSet,
        chunk_size: u32,
        chunk_hashes: Vec<[u8; 32]>,
        commit_qc: QuorumCertificate,
        created_unix_secs: u64,
        validator_history: crate::validator_history::PersistedValidatorHistory,
        validator_key_history: crate::validator_key_history::PersistedValidatorKeyHistory,
        bls_key_history: Option<crate::bls_key_history::PersistedBlsKeyHistory>,
        operator_key_history: Option<crate::operator_key_history::PersistedOperatorKeyHistory>,
    ) -> Self {
        let chunk_count: u32 = chunk_hashes
            .len()
            .try_into()
            .expect("snapshot chunk count must fit in u32 — manifest layout pins this bound");
        let validator_set: Vec<NodeId> = validator_set.iter().map(|v| v.into_node_id()).collect();
        let height = block.header.height;
        let view = block.header.view;
        let block_hash = block.hash();
        let state_commitment = block.header.state_commitment;
        Self {
            version: SNAPSHOT_FORMAT_VERSION,
            height,
            view,
            block_hash,
            state_commitment,
            validator_set,
            chunk_size,
            chunk_count,
            chunk_hashes,
            commit_qc,
            block,
            created_unix_secs,
            validator_history,
            validator_key_history,
            bls_key_history,
            operator_key_history,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes =
            postcard::to_stdvec(self).expect("postcard encoding of SnapshotManifest cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    pub fn validator_set(&self) -> ValidatorSet {
        let members: Vec<crate::validator_set::ValidatorId> = self
            .validator_set
            .iter()
            .copied()
            .map(crate::validator_set::ValidatorId::from_genesis_pubkey)
            .collect();
        ValidatorSet::new(members)
    }

    pub fn verify(&self, local_validator_set: &ValidatorSet) -> Result<(), ManifestError> {
        if self.version != SNAPSHOT_FORMAT_VERSION {
            return Err(ManifestError::UnsupportedVersion {
                got: self.version,
                expected: SNAPSHOT_FORMAT_VERSION,
            });
        }
        let embedded_set = self.validator_set();
        if &embedded_set != local_validator_set {
            return Err(ManifestError::ValidatorSetMismatch);
        }
        if !self.commit_qc.is_well_formed(local_validator_set) {
            return Err(ManifestError::QcMalformed);
        }
        if !self.commit_qc.has_quorum(local_validator_set) {
            return Err(ManifestError::QcInsufficientQuorum {
                signers: self.commit_qc.signer_count(),
                quorum: crate::hotstuff::qc::quorum_size(local_validator_set.len()),
            });
        }
        if self.commit_qc.block_hash != self.block_hash {
            return Err(ManifestError::QcBlockHashMismatch);
        }
        if self.chunk_count as usize != self.chunk_hashes.len() {
            return Err(ManifestError::ChunkCountMismatch {
                chunk_count: self.chunk_count,
                hashes_len: self.chunk_hashes.len(),
            });
        }
        if self.chunk_size == 0 {
            return Err(ManifestError::InvalidChunkSize);
        }

        if self.block.hash() != self.block_hash {
            return Err(ManifestError::BlockHashMismatch);
        }
        if self.block.header.height != self.height {
            return Err(ManifestError::BlockHeightMismatch);
        }
        if self.block.header.view != self.view {
            return Err(ManifestError::BlockViewMismatch);
        }
        if self.block.header.state_commitment != self.state_commitment {
            return Err(ManifestError::BlockStateCommitmentMismatch);
        }

        let rebuilt_set = crate::validator_history::ValidatorSetHistory::from_persisted(
            self.validator_history.clone(),
        )
        .map_err(|_| ManifestError::ValidatorHistoryCommitmentMismatch)?;
        let rebuilt_key = crate::validator_key_history::ValidatorKeyHistory::from_persisted(
            self.validator_key_history.clone(),
        )
        .map_err(|_| ManifestError::ValidatorHistoryCommitmentMismatch)?;
        let rebuilt_bls = match &self.bls_key_history {
            Some(p) => Some(
                crate::bls_key_history::BlsKeyHistory::from_persisted(p.clone())
                    .map_err(|_| ManifestError::ValidatorHistoryCommitmentMismatch)?,
            ),
            None => None,
        };

        let rebuilt_operator = match &self.operator_key_history {
            Some(p) => Some(
                crate::operator_key_history::OperatorKeyHistory::from_persisted(p.clone())
                    .map_err(|_| ManifestError::ValidatorHistoryCommitmentMismatch)?,
            ),
            None => None,
        };
        let actual = crate::history_commitment::validator_history_commitment_v2(
            &rebuilt_set,
            &rebuilt_key,
            rebuilt_bls.as_ref(),
            rebuilt_operator.as_ref(),
        );
        if actual != self.block.header.validator_history_commitment {
            return Err(ManifestError::ValidatorHistoryCommitmentMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    UnsupportedVersion { got: u8, expected: u8 },

    ValidatorSetMismatch,

    QcMalformed,

    QcInsufficientQuorum { signers: usize, quorum: usize },

    QcBlockHashMismatch,

    ChunkCountMismatch { chunk_count: u32, hashes_len: usize },

    InvalidChunkSize,

    BlockHashMismatch,

    BlockHeightMismatch,

    BlockViewMismatch,

    BlockStateCommitmentMismatch,

    ValidatorHistoryCommitmentMismatch,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { got, expected } => write!(
                f,
                "unsupported snapshot manifest version {got} (expected {expected})",
            ),
            Self::ValidatorSetMismatch => write!(
                f,
                "manifest's embedded validator set does not match the local validator set",
            ),
            Self::QcMalformed => write!(
                f,
                "manifest's commit_qc is malformed under the local validator set",
            ),
            Self::QcInsufficientQuorum { signers, quorum } => write!(
                f,
                "manifest's commit_qc has {signers} signers; quorum requires {quorum}",
            ),
            Self::QcBlockHashMismatch => write!(
                f,
                "manifest's commit_qc.block_hash does not match manifest.block_hash",
            ),
            Self::ChunkCountMismatch {
                chunk_count,
                hashes_len,
            } => write!(
                f,
                "manifest chunk_count {chunk_count} disagrees with chunk_hashes.len() = {hashes_len}",
            ),
            Self::InvalidChunkSize => write!(f, "manifest chunk_size is zero"),
            Self::BlockHashMismatch => write!(
                f,
                "manifest.block.hash() does not match manifest.block_hash",
            ),
            Self::BlockHeightMismatch => write!(
                f,
                "manifest.block.header.height does not match manifest.height",
            ),
            Self::BlockViewMismatch => {
                write!(f, "manifest.block.header.view does not match manifest.view",)
            }
            Self::BlockStateCommitmentMismatch => write!(
                f,
                "manifest.block.header.state_commitment does not match manifest.state_commitment",
            ),
            Self::ValidatorHistoryCommitmentMismatch => write!(
                f,
                "manifest's embedded validator-history triple does not match \
                 block.header.validator_history_commitment (snapshot tampered or rolled back; \
                 audit #325 PR D / 7-F2)",
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

pub fn verify_chunk(
    manifest: &SnapshotManifest,
    chunk_idx: u32,
    payload: &[u8],
) -> Result<(), ChunkError> {
    let idx = chunk_idx as usize;
    let expected = manifest
        .chunk_hashes
        .get(idx)
        .ok_or(ChunkError::IndexOutOfRange {
            chunk_idx,
            chunk_count: manifest.chunk_count,
        })?;
    let actual = sha256_of(payload);
    if &actual != expected {
        return Err(ChunkError::HashMismatch {
            chunk_idx,
            expected: *expected,
            actual,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
    IndexOutOfRange {
        chunk_idx: u32,
        chunk_count: u32,
    },

    HashMismatch {
        chunk_idx: u32,
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexOutOfRange {
                chunk_idx,
                chunk_count,
            } => write!(
                f,
                "snapshot chunk index {chunk_idx} is out of range; manifest has {chunk_count} chunks",
            ),
            Self::HashMismatch {
                chunk_idx,
                expected,
                actual,
            } => write!(
                f,
                "snapshot chunk {chunk_idx} hash mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
        }
    }
}

impl std::error::Error for ChunkError {}

pub fn chunk_snapshot(payload: &[u8], chunk_size: u32) -> Vec<(Bytes, [u8; 32])> {
    assert!(chunk_size > 0, "chunk_size must be > 0");
    if payload.is_empty() {
        let hash = sha256_of(&[]);
        return vec![(Bytes::new(), hash)];
    }
    let chunk_size = chunk_size as usize;
    let mut out = Vec::with_capacity(payload.len().div_ceil(chunk_size));
    for window in payload.chunks(chunk_size) {
        let bytes = Bytes::copy_from_slice(window);
        let hash = sha256_of(window);
        out.push((bytes, hash));
    }
    out
}

pub fn assemble_chunks(chunks: &[Bytes]) -> Bytes {
    if chunks.len() == 1 && chunks[0].is_empty() {
        return Bytes::new();
    }
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out = Vec::with_capacity(total);
    for c in chunks {
        out.extend_from_slice(c);
    }
    Bytes::from(out)
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn manifest_storage_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX.len() + 8);
    key.extend_from_slice(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

pub fn chunk_storage_key(height: u64, idx: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX.len() + 8 + 4);
    key.extend_from_slice(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&idx.to_be_bytes());
    key
}

pub fn parse_manifest_storage_key(key: &[u8]) -> Option<u64> {
    let suffix = key.strip_prefix(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX)?;
    if suffix.len() != 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(suffix);
    Some(u64::from_be_bytes(buf))
}

pub fn parse_chunk_storage_key(key: &[u8]) -> Option<(u64, u32)> {
    let suffix = key.strip_prefix(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX)?;
    if suffix.len() != 12 {
        return None;
    }
    let mut h = [0u8; 8];
    h.copy_from_slice(&suffix[..8]);
    let mut i = [0u8; 4];
    i.copy_from_slice(&suffix[8..]);
    Some((u64::from_be_bytes(h), u32::from_be_bytes(i)))
}

fn chunk_height_prefix(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX.len() + 8);
    key.extend_from_slice(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

#[derive(Clone)]
pub struct SnapshotStore {
    storage: Arc<dyn Storage>,
}

impl SnapshotStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    pub fn storage(&self) -> Arc<dyn Storage> {
        Arc::clone(&self.storage)
    }

    pub fn save(&self, manifest: &SnapshotManifest, chunks: &[Bytes]) -> anyhow::Result<()> {
        if chunks.len() != manifest.chunk_count as usize {
            anyhow::bail!(
                "snapshot chunks length {} does not match manifest chunk_count {}",
                chunks.len(),
                manifest.chunk_count,
            );
        }
        for (idx, chunk) in chunks.iter().enumerate() {
            let actual = sha256_of(chunk);
            if actual != manifest.chunk_hashes[idx] {
                anyhow::bail!(
                    "snapshot chunk {idx} hash {} does not match manifest hash {}",
                    hex::encode(actual),
                    hex::encode(manifest.chunk_hashes[idx]),
                );
            }
        }
        let manifest_bytes = postcard::to_stdvec(manifest)?;
        self.storage.batch(|b| {
            b.put(&manifest_storage_key(manifest.height.0), &manifest_bytes);
            for (idx, chunk) in chunks.iter().enumerate() {
                b.put(
                    &chunk_storage_key(manifest.height.0, idx as u32),
                    chunk.as_ref(),
                );
            }
            b.put(
                STORAGE_KEY_SNAPSHOT_LATEST,
                &manifest.height.0.to_be_bytes(),
            );
            Ok(())
        })?;
        Ok(())
    }

    pub fn load_manifest(&self, height: u64) -> anyhow::Result<Option<SnapshotManifest>> {
        let key = manifest_storage_key(height);
        let Some(bytes) = self.storage.get(&key)? else {
            return Ok(None);
        };
        let manifest: SnapshotManifest = postcard::from_bytes(&bytes)?;
        Ok(Some(manifest))
    }

    pub fn load_chunk(&self, height: u64, idx: u32) -> anyhow::Result<Option<Bytes>> {
        let key = chunk_storage_key(height, idx);
        self.storage.get(&key)
    }

    pub fn list_heights(&self) -> anyhow::Result<Vec<u64>> {
        let rows = self
            .storage
            .scan_prefix(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX)?;
        let mut heights = Vec::with_capacity(rows.len());
        for (k, _v) in rows {
            if let Some(h) = parse_manifest_storage_key(&k) {
                heights.push(h);
            }
        }

        heights.sort();
        Ok(heights)
    }

    pub fn latest_height(&self) -> anyhow::Result<Option<u64>> {
        let Some(raw) = self.storage.get(STORAGE_KEY_SNAPSHOT_LATEST)? else {
            return Ok(None);
        };
        if raw.len() != 8 {
            anyhow::bail!(
                "consensus/snap/latest has unexpected length {} (expected 8)",
                raw.len(),
            );
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw);
        let height = u64::from_be_bytes(buf);

        if self.load_manifest(height)?.is_none() {
            return Ok(None);
        }
        Ok(Some(height))
    }

    pub fn delete(&self, height: u64) -> anyhow::Result<()> {
        let chunk_keys = self
            .storage
            .scan_prefix(&chunk_height_prefix(height))?
            .into_iter()
            .map(|(k, _v)| k)
            .collect::<Vec<_>>();
        let new_latest = self.list_heights()?.into_iter().rfind(|h| *h != height);
        self.storage.batch(|b| {
            b.delete(&manifest_storage_key(height));
            for k in &chunk_keys {
                b.delete(k);
            }
            match new_latest {
                Some(h) => b.put(STORAGE_KEY_SNAPSHOT_LATEST, &h.to_be_bytes()),
                None => b.delete(STORAGE_KEY_SNAPSHOT_LATEST),
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn prune_older_than(&self, retain_n: usize) -> anyhow::Result<Vec<u64>> {
        if retain_n == 0 {
            return Ok(Vec::new());
        }
        let heights = self.list_heights()?;
        if heights.len() <= retain_n {
            return Ok(Vec::new());
        }
        let to_delete: Vec<u64> = heights[..heights.len() - retain_n].to_vec();
        for h in &to_delete {
            self.delete(*h)?;
        }
        Ok(to_delete)
    }
}

pub const EXPORT_MANIFEST_FILENAME: &str = "manifest.bin";

pub fn export_chunk_filename(idx: u32) -> String {
    format!("chunk-{idx:08}.bin")
}

pub fn export_to_directory(
    manifest: &SnapshotManifest,
    chunks: &[Bytes],
    out_dir: &std::path::Path,
) -> anyhow::Result<u32> {
    if chunks.len() != manifest.chunk_count as usize {
        anyhow::bail!(
            "chunks length {} does not match manifest chunk_count {}",
            chunks.len(),
            manifest.chunk_count,
        );
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| anyhow::anyhow!("creating output dir {}: {e}", out_dir.display()))?;
    let manifest_bytes =
        postcard::to_stdvec(manifest).map_err(|e| anyhow::anyhow!("encoding manifest: {e}"))?;
    std::fs::write(out_dir.join(EXPORT_MANIFEST_FILENAME), &manifest_bytes)
        .map_err(|e| anyhow::anyhow!("writing manifest.bin: {e}"))?;
    for (idx, chunk) in chunks.iter().enumerate() {
        let path = out_dir.join(export_chunk_filename(idx as u32));
        std::fs::write(&path, chunk)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    }
    Ok(manifest.chunk_count)
}

pub fn import_from_directory(
    in_dir: &std::path::Path,
) -> anyhow::Result<(SnapshotManifest, Vec<Bytes>)> {
    let manifest_path = in_dir.join(EXPORT_MANIFEST_FILENAME);
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", manifest_path.display()))?;
    let manifest: SnapshotManifest = postcard::from_bytes(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("decoding manifest.bin: {e}"))?;
    if manifest.version != SNAPSHOT_FORMAT_VERSION {
        anyhow::bail!(
            "manifest version {} not supported (expected {})",
            manifest.version,
            SNAPSHOT_FORMAT_VERSION,
        );
    }
    let mut chunks: Vec<Bytes> = Vec::with_capacity(manifest.chunk_count as usize);
    for idx in 0..manifest.chunk_count {
        let path = in_dir.join(export_chunk_filename(idx));
        let raw =
            std::fs::read(&path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        chunks.push(Bytes::from(raw));
    }
    Ok((manifest, chunks))
}

pub fn open_snapshot_store(config: &boule_core::config::Config) -> anyhow::Result<SnapshotStore> {
    let cons_cfg = config
        .consensus
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("snapshot subcommands require [consensus] in the config"))?;
    let dir = cons_cfg.storage_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "snapshot subcommands require [consensus] storage_dir to be set; \
             in-memory storage has nothing to export from / import into"
        )
    })?;
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("creating consensus storage_dir {}: {e}", dir.display()))?;
    let storage: Arc<dyn Storage> =
        Arc::new(boule_core::storage::DiskStorage::open(dir.join("kv.redb"))?);
    Ok(SnapshotStore::new(storage))
}

pub fn export_snapshot(
    store: &SnapshotStore,
    height: Option<u64>,
    out_dir: &std::path::Path,
) -> anyhow::Result<SnapshotManifest> {
    let height = match height {
        Some(h) => h,
        None => store.latest_height()?.ok_or_else(|| {
            anyhow::anyhow!("no snapshots found in consensus storage_dir; nothing to export")
        })?,
    };
    let manifest = store.load_manifest(height)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no snapshot at height {height}; available: {:?}",
            store.list_heights().unwrap_or_default(),
        )
    })?;
    let mut chunks: Vec<Bytes> = Vec::with_capacity(manifest.chunk_count as usize);
    for idx in 0..manifest.chunk_count {
        let chunk = store
            .load_chunk(height, idx)?
            .ok_or_else(|| anyhow::anyhow!("snapshot at height {height} is missing chunk {idx}"))?;
        chunks.push(chunk);
    }
    export_to_directory(&manifest, &chunks, out_dir)?;
    Ok(manifest)
}

pub fn import_snapshot(
    store: &SnapshotStore,
    in_dir: &std::path::Path,
) -> anyhow::Result<SnapshotManifest> {
    let (manifest, chunks) = import_from_directory(in_dir)?;
    store.save(&manifest, &chunks)?;
    Ok(manifest)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotPolicy {
    pub interval_blocks: u64,
    pub retention_count: usize,
    pub chunk_size_bytes: u32,
}

impl SnapshotPolicy {
    pub fn disabled() -> Self {
        Self {
            interval_blocks: 0,
            retention_count: 0,
            chunk_size_bytes: 1,
        }
    }

    pub fn production_defaults() -> Self {
        Self {
            interval_blocks: 10_000,
            retention_count: 3,
            chunk_size_bytes: 1024 * 1024,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.interval_blocks > 0
    }

    pub fn should_snapshot_at(&self, committed_height: Height) -> bool {
        self.is_enabled()
            && committed_height > Height::ZERO
            && committed_height.0 % self.interval_blocks == 0
    }
}
