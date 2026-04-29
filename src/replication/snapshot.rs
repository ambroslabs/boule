//! Periodic state snapshots for fast joiner catch-up (#139, sub-task #227).
//!
//! A snapshot is an opaque [`StateMachine::snapshot`] blob — sliced into
//! fixed-size chunks for chunked transfer over the wire — together with
//! a [`SnapshotManifest`] that names the chunks, the validator set
//! that was active at the snapshot height, and a quorum-bearing
//! [`QuorumCertificate`] proving the snapshot block was supported.
//!
//! This module owns the on-disk layout and the manifest/chunk types;
//! the wire protocol that transports them lands in sub-task #228, the
//! joiner-side fetch in #229 / #230. See issue #139 for the broader
//! design discussion.
//!
//! # Storage layout
//!
//! Snapshots ride on top of the [`Storage`] trait — the same KV layer
//! that already holds committed blocks under [`STORAGE_KEY_BLOCK_PREFIX`]
//! — rather than introducing redb-specific tables. Two prefix spaces
//! are reserved:
//!
//! | Prefix                          | Key tail                                      | Value                            |
//! | ------------------------------- | --------------------------------------------- | -------------------------------- |
//! | `consensus/snap/manifest/`      | `height: u64` (big-endian)                    | postcard-encoded [`SnapshotManifest`] |
//! | `consensus/snap/chunk/`         | `height: u64 BE` ‖ `chunk_idx: u32 BE`        | raw chunk bytes                  |
//! | `consensus/snap/latest`         | (singleton)                                   | u64 big-endian height            |
//!
//! All writes for one snapshot land in a single [`StorageExt::batch`],
//! preserving the "snapshot is observable atomically" property —
//! readers either see the new manifest plus all its chunks plus the
//! updated `latest` pointer, or none of them.
//!
//! # Validator-set encoding
//!
//! [`ValidatorSet`] does not derive `Serialize`/`Deserialize` itself
//! (its internal `Arc<[NodeId]>` representation is not directly
//! serde-friendly). Manifests carry the set as `Vec<NodeId>` and
//! reconstruct via [`ValidatorSet::new`] on load — the constructor's
//! sort+dedup invariant means equal logical sets round-trip to byte-
//! identical encodings.

use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::consensus::View;
use crate::consensus::hotstuff::QuorumCertificate;
use crate::consensus::validator_set::ValidatorSet;
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash};
use crate::storage::{Storage, StorageExt};

/// Storage-key prefix under which [`SnapshotManifest`] values are
/// persisted, keyed by height (big-endian `u64`).
pub const STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX: &[u8] = b"consensus/snap/manifest/";

/// Storage-key prefix under which raw snapshot chunks are persisted,
/// keyed by `(height: u64 BE, chunk_idx: u32 BE)`.
pub const STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX: &[u8] = b"consensus/snap/chunk/";

/// Storage key holding the height of the most recently committed
/// snapshot. Optional: a fresh node simply has no key here.
pub const STORAGE_KEY_SNAPSHOT_LATEST: &[u8] = b"consensus/snap/latest";

/// Current snapshot-format version. Bumped when the manifest schema
/// or chunk hashing changes in a non-backwards-compatible way; readers
/// must reject manifests whose `version` does not match a version they
/// implement.
///
/// History:
/// - `1`: original. Manifest carried `block_hash` but not the block
///   itself.
/// - `2`: adds the snapshot block as `block: Block` so the joiner can
///   restore `pending_blocks` without an extra round-trip — required
///   by the safety core's parent-walks (#229).
pub const SNAPSHOT_FORMAT_VERSION: u8 = 2;

/// Manifest describing one snapshot at `(height, view)`.
///
/// Postcard-encoded on the wire and on disk. The hash returned by
/// [`SnapshotManifest::hash`] is `sha256(postcard(self))` — equal
/// manifests produce equal hashes across processes and architectures.
///
/// Fields are immutable after construction; populate them in one go
/// via [`SnapshotManifest::build`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Schema version. Must equal [`SNAPSHOT_FORMAT_VERSION`] today.
    pub version: u8,
    /// Block height the snapshot was taken at. Equal to
    /// `block.header.height` for a well-formed manifest.
    pub height: u64,
    /// View of the snapshot block. Equal to `block.header.view`.
    pub view: View,
    /// Content-hash of the snapshot block. Equal to `block.hash()`.
    pub block_hash: BlockHash,
    /// `StateMachine::state_commitment` after the snapshot block's
    /// commands were applied. Equal to `block.header.state_commitment`.
    pub state_commitment: [u8; 32],
    /// Validator set active at the snapshot height. See module docs.
    pub validator_set: Vec<NodeId>,
    /// Bytes per chunk. The last chunk may be shorter.
    pub chunk_size: u32,
    /// Number of chunks (must equal `chunk_hashes.len()`).
    pub chunk_count: u32,
    /// `sha256` of each chunk's raw payload, in order.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// Quorum-bearing QC over the snapshot block. See [`SnapshotManifest::block_hash`].
    pub commit_qc: QuorumCertificate,
    /// The snapshot block itself. Carried inside the manifest so a
    /// joiner can populate `pending_blocks` for the safety core's
    /// parent-walks without an extra `BlockRequest` round-trip
    /// (#229). Sized at most a few hundred bytes for an empty
    /// production state machine; payload commands grow the size
    /// linearly.
    pub block: Block,
    /// Wall-clock seconds-since-Unix-epoch at creation. Informational
    /// only — verifiers do not key safety on this field.
    pub created_unix_secs: u64,
}

impl SnapshotManifest {
    /// Build a manifest from the snapshot block's identifying fields,
    /// the validator set, the snapshot bytes (chunked by the caller),
    /// and a QC over the block.
    ///
    /// # Determinism
    ///
    /// Given identical inputs, two callers produce byte-identical
    /// manifests; the only non-deterministic field is
    /// `created_unix_secs`, supplied by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        block: Block,
        validator_set: &ValidatorSet,
        chunk_size: u32,
        chunk_hashes: Vec<[u8; 32]>,
        commit_qc: QuorumCertificate,
        created_unix_secs: u64,
    ) -> Self {
        let chunk_count: u32 = chunk_hashes
            .len()
            .try_into()
            .expect("snapshot chunk count must fit in u32 — manifest layout pins this bound");
        let validator_set: Vec<NodeId> = validator_set.iter().copied().collect();
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
        }
    }

    /// `sha256(postcard(self))`. Stable across processes — postcard is
    /// deterministic for fixed-shape structs, and every field of
    /// [`SnapshotManifest`] is fixed-shape.
    pub fn hash(&self) -> [u8; 32] {
        let bytes =
            postcard::to_stdvec(self).expect("postcard encoding of SnapshotManifest cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    /// Reconstruct a [`ValidatorSet`] from the embedded `validator_set`
    /// vector. Cheap; clones the underlying NodeIds once.
    pub fn validator_set(&self) -> ValidatorSet {
        ValidatorSet::new(self.validator_set.clone())
    }

    /// Verify the manifest is internally consistent and trustworthy
    /// against `local_validator_set` — the validator set the verifier
    /// already knows.
    ///
    /// Checks (in order; first failure wins):
    ///
    /// 1. `version == SNAPSHOT_FORMAT_VERSION` — reject schemas this
    ///    binary doesn't implement.
    /// 2. The embedded `validator_set` byte-equals `local_validator_set`.
    ///    Static-membership clusters require an exact match; when
    ///    dynamic membership lands (#23), this generalizes to a
    ///    chain-verify against a trust anchor.
    /// 3. `commit_qc.is_well_formed(local_validator_set)` —
    ///    bitmap/signature shape matches the validator set.
    /// 4. `commit_qc.has_quorum(local_validator_set)` — the QC
    ///    actually demonstrates ≥ quorum support.
    /// 5. `commit_qc.block_hash == block_hash` — the QC is over the
    ///    snapshot block, not some descendant or unrelated block.
    /// 6. `chunk_count == chunk_hashes.len()` — the chunk-count
    ///    field and the hash vector agree.
    /// 7. `chunk_size > 0`.
    ///
    /// Note: this does **not** verify Ed25519 signatures inside the
    /// QC. The QC's `signatures` are validated at envelope ingress in
    /// production; the snapshot path inherits that trust gradient.
    /// The chunk hashes are verified separately by
    /// [`SnapshotChunk::verify`].
    pub fn verify(&self, local_validator_set: &ValidatorSet) -> Result<(), ManifestError> {
        if self.version != SNAPSHOT_FORMAT_VERSION {
            return Err(ManifestError::UnsupportedVersion {
                got: self.version,
                expected: SNAPSHOT_FORMAT_VERSION,
            });
        }
        let embedded: Vec<NodeId> = self.validator_set.clone();
        let embedded_set = ValidatorSet::new(embedded);
        if &embedded_set != local_validator_set {
            return Err(ManifestError::ValidatorSetMismatch);
        }
        if !self.commit_qc.is_well_formed(local_validator_set) {
            return Err(ManifestError::QcMalformed);
        }
        if !self.commit_qc.has_quorum(local_validator_set) {
            return Err(ManifestError::QcInsufficientQuorum {
                signers: self.commit_qc.signer_count(),
                quorum: crate::consensus::hotstuff::qc::quorum_size(local_validator_set.len()),
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
        // The embedded block must be self-consistent with the
        // standalone height/view/hash/state-commitment fields. A
        // mismatched block would let a malicious peer corrupt the
        // joiner's safety state by feeding a block whose header
        // disagrees with what they're claiming the snapshot
        // committed.
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
        Ok(())
    }
}

/// Reasons a [`SnapshotManifest`] can be rejected by [`SnapshotManifest::verify`].
///
/// Each variant is distinct so test assertions and operator logs can
/// distinguish "wrong validator set" from "QC missing quorum" without
/// string-matching error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// `version` does not equal [`SNAPSHOT_FORMAT_VERSION`].
    UnsupportedVersion { got: u8, expected: u8 },
    /// Embedded validator set does not byte-equal the local one.
    ValidatorSetMismatch,
    /// QC bitmap or signature shape does not match the validator set.
    QcMalformed,
    /// QC has fewer signers than the quorum threshold.
    QcInsufficientQuorum { signers: usize, quorum: usize },
    /// QC's `block_hash` does not match the manifest's `block_hash`.
    QcBlockHashMismatch,
    /// `chunk_count` field disagrees with `chunk_hashes.len()`.
    ChunkCountMismatch { chunk_count: u32, hashes_len: usize },
    /// `chunk_size == 0`. Snapshots with zero-size chunks can't be
    /// transferred meaningfully.
    InvalidChunkSize,
    /// `manifest.block.hash() != manifest.block_hash`.
    BlockHashMismatch,
    /// `manifest.block.header.height != manifest.height`.
    BlockHeightMismatch,
    /// `manifest.block.header.view != manifest.view`.
    BlockViewMismatch,
    /// `manifest.block.header.state_commitment != manifest.state_commitment`.
    BlockStateCommitmentMismatch,
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
        }
    }
}

impl std::error::Error for ManifestError {}

/// Verify a chunk payload against the manifest's recorded hash for
/// that chunk index.
///
/// Returns `Err(ChunkError)` if `chunk_idx` is out of range or if
/// `sha256(payload)` does not match `manifest.chunk_hashes[chunk_idx]`.
/// On success, the chunk is bit-identical to what the snapshot
/// producer wrote.
///
/// Callers are expected to have run [`SnapshotManifest::verify`]
/// against the manifest first; this helper trusts the manifest's
/// integrity.
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

/// Reasons a snapshot chunk can be rejected by [`verify_chunk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
    /// `chunk_idx` is `>= chunk_count`.
    IndexOutOfRange { chunk_idx: u32, chunk_count: u32 },
    /// `sha256(payload)` does not match `manifest.chunk_hashes[chunk_idx]`.
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

/// Slice `payload` into fixed-size chunks of at most `chunk_size`
/// bytes, returning each chunk's `sha256` alongside the bytes.
///
/// The last chunk may be shorter than `chunk_size`; an empty `payload`
/// produces a single zero-length chunk so `chunk_count >= 1` is always
/// true (lets callers index `chunk_hashes[0]` without a special case
/// for "no state to snapshot").
///
/// Panics if `chunk_size == 0` — callers must validate the policy
/// before reaching this helper (see
/// [`crate::config::ConsensusConfig::validate_snapshot_policy`]).
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

/// Reassemble a payload from its chunks in order.
///
/// Caller must have verified each chunk's hash against the manifest;
/// this helper does not re-verify. Returns the concatenated bytes.
pub fn assemble_chunks(chunks: &[Bytes]) -> Bytes {
    if chunks.len() == 1 && chunks[0].is_empty() {
        // The empty-payload special case from [`chunk_snapshot`].
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

/// Compose the storage key for a manifest at `height`.
pub fn manifest_storage_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX.len() + 8);
    key.extend_from_slice(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

/// Compose the storage key for chunk `idx` of the snapshot at `height`.
pub fn chunk_storage_key(height: u64, idx: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX.len() + 8 + 4);
    key.extend_from_slice(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&idx.to_be_bytes());
    key
}

/// Decode the height embedded in a manifest storage key produced by
/// [`manifest_storage_key`]. Returns `None` for keys whose length or
/// prefix doesn't match.
pub fn parse_manifest_storage_key(key: &[u8]) -> Option<u64> {
    let suffix = key.strip_prefix(STORAGE_KEY_SNAPSHOT_MANIFEST_PREFIX)?;
    if suffix.len() != 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(suffix);
    Some(u64::from_be_bytes(buf))
}

/// Decode the `(height, chunk_idx)` pair embedded in a chunk storage
/// key produced by [`chunk_storage_key`].
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

/// Per-snapshot prefix for sweeping all chunks at a given height — used
/// by the pruner to identify everything to delete in one
/// [`Storage::scan_prefix`] call.
fn chunk_height_prefix(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX.len() + 8);
    key.extend_from_slice(STORAGE_KEY_SNAPSHOT_CHUNK_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

/// On-disk snapshot store layered on top of an `Arc<dyn Storage>`.
///
/// This type owns no state of its own; it is a thin namespacing /
/// encoding wrapper so callers don't need to know the prefix layout.
#[derive(Clone)]
pub struct SnapshotStore {
    storage: Arc<dyn Storage>,
}

impl SnapshotStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// Return a clone of the underlying `Storage` handle. Useful for
    /// tests that want to assert on raw key presence.
    pub fn storage(&self) -> Arc<dyn Storage> {
        Arc::clone(&self.storage)
    }

    /// Persist `manifest` together with all its `chunks` atomically.
    ///
    /// `chunks.len()` must equal `manifest.chunk_count` and each
    /// chunk's `sha256` must match `manifest.chunk_hashes[i]` —
    /// callers normally produce both via [`chunk_snapshot`] so the
    /// invariants hold by construction.
    ///
    /// Updates [`STORAGE_KEY_SNAPSHOT_LATEST`] to point at this
    /// manifest's height. The whole batch — manifest, chunks, latest
    /// pointer — commits in one [`Storage::apply_batch`], so a reader
    /// either sees the complete new snapshot or none of it.
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
            b.put(&manifest_storage_key(manifest.height), &manifest_bytes);
            for (idx, chunk) in chunks.iter().enumerate() {
                b.put(
                    &chunk_storage_key(manifest.height, idx as u32),
                    chunk.as_ref(),
                );
            }
            b.put(STORAGE_KEY_SNAPSHOT_LATEST, &manifest.height.to_be_bytes());
            Ok(())
        })?;
        Ok(())
    }

    /// Load the manifest at `height`, or `None` if no such snapshot
    /// exists.
    pub fn load_manifest(&self, height: u64) -> anyhow::Result<Option<SnapshotManifest>> {
        let key = manifest_storage_key(height);
        let Some(bytes) = self.storage.get(&key)? else {
            return Ok(None);
        };
        let manifest: SnapshotManifest = postcard::from_bytes(&bytes)?;
        Ok(Some(manifest))
    }

    /// Load chunk `idx` of the snapshot at `height`, or `None` if it
    /// doesn't exist.
    pub fn load_chunk(&self, height: u64, idx: u32) -> anyhow::Result<Option<Bytes>> {
        let key = chunk_storage_key(height, idx);
        self.storage.get(&key)
    }

    /// Return all snapshot heights present on disk, ascending.
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
        // `scan_prefix` already returns ascending; the assignment from
        // big-endian-encoded heights preserves the order. Belt-and-
        // suspenders sort guards against backend changes.
        heights.sort();
        Ok(heights)
    }

    /// Height of the most recently committed snapshot, or `None` on a
    /// fresh store. Source of truth is the
    /// [`STORAGE_KEY_SNAPSHOT_LATEST`] pointer; a pointer that
    /// references a missing manifest is treated as if it were absent.
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
        // Cross-check that the manifest still exists; if it was pruned
        // out from under the pointer (corrupt store / bug), report
        // "no latest" rather than returning a dangling height.
        if self.load_manifest(height)?.is_none() {
            return Ok(None);
        }
        Ok(Some(height))
    }

    /// Delete the snapshot at `height` (manifest + every chunk),
    /// atomically. If `height` was the latest, the
    /// [`STORAGE_KEY_SNAPSHOT_LATEST`] pointer is updated to the next
    /// most recent height (or removed if no snapshots remain).
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

    /// Keep only the `retain_n` most recent snapshots, pruning older
    /// ones. `retain_n == 0` is a no-op (snapshots accumulate without
    /// bound — useful for tests).
    ///
    /// Returns the heights that were deleted, ascending.
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

/// Filename of the manifest inside an exported snapshot directory.
pub const EXPORT_MANIFEST_FILENAME: &str = "manifest.bin";

/// Format a chunk filename: `chunk-NNNNNNNN.bin`, where `NNNNNNNN` is
/// the chunk index zero-padded to 8 digits. The padding keeps a
/// directory listing in alphabetical order matching chunk order, and
/// 8 digits is enough for any plausible snapshot size at 1 MiB chunks
/// (8-digit max ≈ 100 TiB).
pub fn export_chunk_filename(idx: u32) -> String {
    format!("chunk-{idx:08}.bin")
}

/// Write a snapshot's manifest and chunks to a directory at `out_dir`,
/// creating the directory if it does not exist.
///
/// Layout:
/// - `out_dir/manifest.bin` — postcard-encoded [`SnapshotManifest`].
/// - `out_dir/chunk-NNNNNNNN.bin` — raw bytes of chunk `NNNNNNNN`.
///
/// Returns the number of chunks written.
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

/// Read a snapshot exported by [`export_to_directory`] into a
/// `(manifest, chunks)` pair. The manifest's `version` is checked
/// against [`SNAPSHOT_FORMAT_VERSION`]; chunk hashes are NOT
/// re-verified here (callers using [`SnapshotStore::save`] get that
/// check for free).
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

/// Snapshot creation policy: how often to take snapshots, how many to
/// keep, and how big each chunk is. See module docs for defaults.
///
/// `interval_blocks == 0` disables snapshot creation entirely; the
/// store is left untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotPolicy {
    pub interval_blocks: u64,
    pub retention_count: usize,
    pub chunk_size_bytes: u32,
}

impl SnapshotPolicy {
    /// `interval_blocks=0` — snapshots disabled. The default for tests
    /// that don't opt in.
    pub fn disabled() -> Self {
        Self {
            interval_blocks: 0,
            retention_count: 0,
            chunk_size_bytes: 1,
        }
    }

    /// Reasonable production defaults: snapshot every 10_000 blocks,
    /// retain the last 3, 1 MiB chunks.
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

    /// True iff a block at `committed_height` should trigger a
    /// snapshot under this policy. False on a disabled policy and on
    /// the genesis block (height 0).
    pub fn should_snapshot_at(&self, committed_height: u64) -> bool {
        self.is_enabled() && committed_height > 0 && committed_height % self.interval_blocks == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::hotstuff::qc::quorum_size;
    use crate::replication::block::{Block, BlockHeader};
    use crate::storage::MemoryStorage;

    fn vs(n: u8) -> ValidatorSet {
        ValidatorSet::new((0..n).map(|i| [i; 32]).collect())
    }

    /// Build a `Block` whose header is structurally well-formed for a
    /// snapshot at `(height, view)` with the given state commitment.
    /// `parent_hash` defaults to genesis's hash; tests that need a
    /// specific parent can build their own Block.
    fn sample_block(height: u64, view: u64, state_commitment: [u8; 32]) -> Block {
        let parent_hash = Block::genesis([0u8; 32], [0; 32]).hash();
        let commands: Vec<Bytes> = Vec::new();
        Block {
            header: BlockHeader {
                parent_hash,
                height,
                view,
                proposer: [0u8; 32],
                state_commitment,
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
            },
            commands,
        }
    }

    /// Build a quorum-bearing QC over `block_hash` for the given
    /// validator-set length.
    fn quorum_qc_over(vs_len: usize, block_hash: BlockHash) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(0, block_hash, vs_len);
        for i in 0..quorum_size(vs_len) {
            qc.add_signature(i, [0u8; 64]);
        }
        qc
    }

    fn sample_manifest() -> (SnapshotManifest, Vec<Bytes>) {
        let validator_set = vs(4);
        let block = sample_block(42, 7, [0xAB; 32]);
        let qc = quorum_qc_over(validator_set.len(), block.hash());
        let payload = b"hello world".repeat(50_000); // 550_000 bytes
        let chunks_with_hashes = chunk_snapshot(&payload, 100_000);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let manifest = SnapshotManifest::build(
            block,
            &validator_set,
            100_000,
            chunk_hashes,
            qc,
            1_700_000_000,
        );
        (manifest, chunks)
    }

    #[test]
    fn manifest_hash_is_stable_and_postcard_round_trips() {
        let (m, _) = sample_manifest();
        let h1 = m.hash();
        let bytes = postcard::to_stdvec(&m).unwrap();
        let m2: SnapshotManifest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(m, m2);
        assert_eq!(m2.hash(), h1);
    }

    #[test]
    fn chunk_snapshot_round_trips_via_assemble() {
        let payload: Vec<u8> = (0..100_000u32).flat_map(u32::to_le_bytes).collect();
        let chunks = chunk_snapshot(&payload, 13_000);
        let chunk_bytes: Vec<Bytes> = chunks.iter().map(|(c, _)| c.clone()).collect();
        // Each chunk's hash matches sha256 of its bytes.
        for (chunk, hash) in &chunks {
            assert_eq!(*hash, sha256_of(chunk));
        }
        // Assemble back to the original payload.
        let assembled = assemble_chunks(&chunk_bytes);
        assert_eq!(&payload[..], assembled.as_ref());
    }

    #[test]
    fn empty_payload_produces_one_empty_chunk() {
        let chunks = chunk_snapshot(&[], 1024);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].0.is_empty());
        assert_eq!(chunks[0].1, sha256_of(&[]));
        let assembled = assemble_chunks(&[chunks[0].0.clone()]);
        assert!(assembled.is_empty());
    }

    #[test]
    fn store_save_then_load_round_trip() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store = SnapshotStore::new(storage);
        let (manifest, chunks) = sample_manifest();
        store.save(&manifest, &chunks).unwrap();
        let loaded = store.load_manifest(manifest.height).unwrap().unwrap();
        assert_eq!(loaded, manifest);
        for (idx, expected) in chunks.iter().enumerate() {
            let got = store
                .load_chunk(manifest.height, idx as u32)
                .unwrap()
                .unwrap();
            assert_eq!(&got, expected);
        }
        assert_eq!(store.latest_height().unwrap(), Some(manifest.height));
        assert_eq!(store.list_heights().unwrap(), vec![manifest.height]);
    }

    #[test]
    fn save_rejects_chunk_count_mismatch() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store = SnapshotStore::new(storage);
        let (manifest, mut chunks) = sample_manifest();
        chunks.pop();
        let err = store.save(&manifest, &chunks).unwrap_err().to_string();
        assert!(err.contains("chunk_count"), "got: {err}");
    }

    #[test]
    fn save_rejects_chunk_hash_mismatch() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store = SnapshotStore::new(storage);
        let (manifest, mut chunks) = sample_manifest();
        // Tamper the first byte of the first chunk after manifest was built.
        let mut first = chunks[0].to_vec();
        first[0] ^= 0xFF;
        chunks[0] = Bytes::from(first);
        let err = store.save(&manifest, &chunks).unwrap_err().to_string();
        assert!(err.contains("hash"), "got: {err}");
    }

    #[test]
    fn prune_older_than_keeps_only_n_most_recent() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store = SnapshotStore::new(storage);
        // Save 5 snapshots at heights 100, 200, ... 500.
        for height in [100, 200, 300, 400, 500] {
            let (mut m, chunks) = sample_manifest();
            m.height = height;
            store.save(&m, &chunks).unwrap();
        }
        let deleted = store.prune_older_than(3).unwrap();
        assert_eq!(deleted, vec![100, 200]);
        assert_eq!(store.list_heights().unwrap(), vec![300, 400, 500]);
        // Latest pointer survived.
        assert_eq!(store.latest_height().unwrap(), Some(500));
    }

    #[test]
    fn delete_latest_repoints_or_clears_latest() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store = SnapshotStore::new(storage);
        for height in [100, 200, 300] {
            let (mut m, chunks) = sample_manifest();
            m.height = height;
            store.save(&m, &chunks).unwrap();
        }
        store.delete(300).unwrap();
        assert_eq!(store.latest_height().unwrap(), Some(200));
        store.delete(200).unwrap();
        assert_eq!(store.latest_height().unwrap(), Some(100));
        store.delete(100).unwrap();
        assert_eq!(store.latest_height().unwrap(), None);
        assert!(store.list_heights().unwrap().is_empty());
    }

    #[test]
    fn prune_with_zero_retention_is_noop() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store = SnapshotStore::new(storage);
        for height in [100, 200] {
            let (mut m, chunks) = sample_manifest();
            m.height = height;
            store.save(&m, &chunks).unwrap();
        }
        let deleted = store.prune_older_than(0).unwrap();
        assert!(deleted.is_empty());
        assert_eq!(store.list_heights().unwrap(), vec![100, 200]);
    }

    #[test]
    fn parse_storage_keys_round_trip() {
        let mk = manifest_storage_key(0xDEAD_BEEF_u64);
        assert_eq!(parse_manifest_storage_key(&mk), Some(0xDEAD_BEEF));
        let ck = chunk_storage_key(0xCAFE_BABE, 7);
        assert_eq!(parse_chunk_storage_key(&ck), Some((0xCAFE_BABE, 7)));
        // Wrong prefix → None.
        assert_eq!(parse_manifest_storage_key(&ck), None);
        assert_eq!(parse_chunk_storage_key(&mk), None);
    }

    #[test]
    fn export_then_import_directory_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let (manifest, chunks) = sample_manifest();
        let written = export_to_directory(&manifest, &chunks, tmp.path()).unwrap();
        assert_eq!(written, manifest.chunk_count);
        // Layout matches the documented filenames.
        assert!(tmp.path().join(EXPORT_MANIFEST_FILENAME).exists());
        for idx in 0..manifest.chunk_count {
            assert!(tmp.path().join(export_chunk_filename(idx)).exists());
        }
        // Round-trip via import.
        let (m2, c2) = import_from_directory(tmp.path()).unwrap();
        assert_eq!(m2, manifest);
        assert_eq!(c2, chunks);
    }

    #[test]
    fn import_rejects_unknown_manifest_version() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut manifest, chunks) = sample_manifest();
        export_to_directory(&manifest, &chunks, tmp.path()).unwrap();
        // Tamper the on-disk manifest's version byte by re-encoding
        // with a wrong version. We can't just flip a byte because
        // postcard's framing is variable-width; round-trip-edit-write
        // is the simplest reliable route.
        manifest.version = 0xFF;
        let bytes = postcard::to_stdvec(&manifest).unwrap();
        std::fs::write(tmp.path().join(EXPORT_MANIFEST_FILENAME), bytes).unwrap();
        let err = import_from_directory(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("not supported"), "got: {err}");
    }

    #[test]
    fn store_round_trip_through_disk_storage() {
        // The on-disk backend uses different transaction semantics
        // than `MemoryStorage`; this test pins that the snapshot
        // store layout works against the real (redb) backend the
        // production binary uses. Single chunk for speed.
        use crate::storage::DiskStorage;
        let tmp = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(DiskStorage::open(tmp.path().join("kv.redb")).unwrap());
        let store = SnapshotStore::new(Arc::clone(&storage));
        let (manifest, chunks) = sample_manifest();
        store.save(&manifest, &chunks).unwrap();

        // Re-open the storage to confirm everything was committed
        // (apply_batch on DiskStorage commits in one transaction with
        // immediate durability — this catches a future regression
        // that buffers writes without flushing). Drop both the store
        // and the underlying Arc<DiskStorage> so the redb file lock
        // is released before re-opening.
        drop(store);
        drop(storage);
        let storage2: Arc<dyn Storage> =
            Arc::new(DiskStorage::open(tmp.path().join("kv.redb")).unwrap());
        let store2 = SnapshotStore::new(storage2);
        let loaded = store2.load_manifest(manifest.height).unwrap().unwrap();
        assert_eq!(loaded, manifest);
        for (idx, expected) in chunks.iter().enumerate() {
            let got = store2
                .load_chunk(manifest.height, idx as u32)
                .unwrap()
                .unwrap();
            assert_eq!(&got, expected);
        }
        assert_eq!(store2.latest_height().unwrap(), Some(manifest.height));
    }

    #[test]
    fn export_then_save_via_store_round_trip() {
        // The end-to-end "operator path": export from a populated
        // store on node A, import into a fresh store on node B, and
        // verify the new store sees the snapshot.
        let tmp = tempfile::tempdir().unwrap();
        let storage_a: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store_a = SnapshotStore::new(storage_a);
        let (manifest, chunks) = sample_manifest();
        store_a.save(&manifest, &chunks).unwrap();

        // Operator runs `snapshot export` → directory.
        export_to_directory(&manifest, &chunks, tmp.path()).unwrap();

        // Operator on node B runs `snapshot import` → fresh store sees
        // the snapshot at the same height.
        let storage_b: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let store_b = SnapshotStore::new(storage_b);
        let (m, c) = import_from_directory(tmp.path()).unwrap();
        store_b.save(&m, &c).unwrap();
        assert_eq!(store_b.list_heights().unwrap(), vec![manifest.height]);
        assert_eq!(
            store_b.load_manifest(manifest.height).unwrap().unwrap(),
            manifest,
        );
    }

    // ── Verifier (#228) ─────────────────────────────────────────────────────

    fn validator_set_len_4() -> ValidatorSet {
        // Distinct, sorted node IDs so the embedded encoding is
        // stable and we can build a "different validator set" for
        // negative tests.
        ValidatorSet::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]])
    }

    fn quorum_qc(vs: &ValidatorSet, block_hash: BlockHash) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(0, block_hash, vs.len());
        // Quorum for n=4 is 2f+1 with f=1 → 3.
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            qc.add_signature(i, [0u8; 64]);
        }
        qc
    }

    fn manifest_for_verify(vs: &ValidatorSet) -> SnapshotManifest {
        let block = sample_block(42, 7, [0xCD; 32]);
        let qc = quorum_qc(vs, block.hash());
        let payload = b"snapshot payload".repeat(4);
        let chunks = chunk_snapshot(&payload, 16);
        let chunk_hashes: Vec<[u8; 32]> = chunks.iter().map(|(_, h)| *h).collect();
        SnapshotManifest::build(block, vs, 16, chunk_hashes, qc, 1_700_000_000)
    }

    #[test]
    fn verify_accepts_well_formed_manifest() {
        let vs = validator_set_len_4();
        let m = manifest_for_verify(&vs);
        m.verify(&vs).unwrap();
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let vs = validator_set_len_4();
        let mut m = manifest_for_verify(&vs);
        m.version = 0xFE;
        assert_eq!(
            m.verify(&vs),
            Err(ManifestError::UnsupportedVersion {
                got: 0xFE,
                expected: SNAPSHOT_FORMAT_VERSION,
            }),
        );
    }

    #[test]
    fn verify_rejects_validator_set_mismatch() {
        let vs = validator_set_len_4();
        let m = manifest_for_verify(&vs);
        // Local set has different members.
        let other = ValidatorSet::new(vec![[5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32]]);
        assert_eq!(m.verify(&other), Err(ManifestError::ValidatorSetMismatch));
    }

    #[test]
    fn verify_rejects_qc_under_different_validator_set() {
        // The manifest carries a QC built against the producer's
        // validator set; if we substitute a same-shape but different
        // set in the manifest, the embedded-set check catches it
        // before the QC check. This is a distinct error variant from
        // a malformed QC: the validator-set anchoring is what changed.
        let vs = validator_set_len_4();
        let mut m = manifest_for_verify(&vs);
        // Mutate the embedded set (still len-4, still sorted), but
        // for a fresh local set that matches the *new* members, so
        // the validator-set-mismatch arm fires.
        m.validator_set = vec![[10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32]];
        let err = m.verify(&vs).unwrap_err();
        assert_eq!(err, ManifestError::ValidatorSetMismatch);
    }

    #[test]
    fn verify_rejects_qc_missing_quorum() {
        let vs = validator_set_len_4();
        let mut m = manifest_for_verify(&vs);
        // Strip down to a single signer so the QC no longer has
        // quorum (n=4, f=1 → quorum=3).
        let mut weak_qc = QuorumCertificate::new(0, m.block_hash, vs.len());
        weak_qc.add_signature(0, [0u8; 64]);
        m.commit_qc = weak_qc;
        let err = m.verify(&vs).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::QcInsufficientQuorum {
                signers: 1,
                quorum: 3
            },
        ));
    }

    #[test]
    fn verify_rejects_qc_block_hash_pointing_at_another_block() {
        let vs = validator_set_len_4();
        let mut m = manifest_for_verify(&vs);
        // Re-sign a QC over a different block hash. Bypass the
        // manifest field so the integrity check fires.
        m.commit_qc = quorum_qc(&vs, [0x99; 32]);
        assert_eq!(m.verify(&vs), Err(ManifestError::QcBlockHashMismatch));
    }

    #[test]
    fn verify_rejects_chunk_count_mismatch() {
        let vs = validator_set_len_4();
        let mut m = manifest_for_verify(&vs);
        m.chunk_count += 1; // claim one more chunk than we have hashes for
        assert!(matches!(
            m.verify(&vs),
            Err(ManifestError::ChunkCountMismatch { .. }),
        ));
    }

    #[test]
    fn verify_rejects_zero_chunk_size() {
        let vs = validator_set_len_4();
        let mut m = manifest_for_verify(&vs);
        m.chunk_size = 0;
        assert_eq!(m.verify(&vs), Err(ManifestError::InvalidChunkSize));
    }

    // ── verify_chunk ─────────────────────────────────────────────────────────

    #[test]
    fn verify_chunk_accepts_matching_payload() {
        let vs = validator_set_len_4();
        let payload = b"chunk-zero contents";
        let mut m = manifest_for_verify(&vs);
        m.chunk_count = 1;
        m.chunk_hashes = vec![sha256_of(payload)];
        verify_chunk(&m, 0, payload).unwrap();
    }

    #[test]
    fn verify_chunk_rejects_index_out_of_range() {
        let vs = validator_set_len_4();
        let m = manifest_for_verify(&vs);
        let err = verify_chunk(&m, m.chunk_count, b"anything").unwrap_err();
        assert!(matches!(
            err,
            ChunkError::IndexOutOfRange { chunk_idx, chunk_count }
                if chunk_idx == m.chunk_count && chunk_count == m.chunk_count,
        ));
    }

    #[test]
    fn verify_chunk_rejects_tampered_byte_naming_index() {
        // Acceptance: tampered chunk → clear error naming the offending index.
        let vs = validator_set_len_4();
        let payload = b"chunk-zero contents";
        let mut m = manifest_for_verify(&vs);
        m.chunk_count = 1;
        m.chunk_hashes = vec![sha256_of(payload)];

        let mut tampered = payload.to_vec();
        tampered[0] ^= 0xFF;
        let err = verify_chunk(&m, 0, &tampered).unwrap_err();
        assert!(matches!(err, ChunkError::HashMismatch { chunk_idx: 0, .. },));
        let s = err.to_string();
        assert!(
            s.contains("chunk 0"),
            "error must name the chunk index, got: {s}"
        );
    }

    #[test]
    fn policy_should_snapshot_at_respects_interval_and_zero() {
        let p = SnapshotPolicy {
            interval_blocks: 100,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        assert!(!p.should_snapshot_at(0)); // genesis never triggers
        assert!(p.should_snapshot_at(100));
        assert!(!p.should_snapshot_at(150));
        assert!(p.should_snapshot_at(200));

        let off = SnapshotPolicy::disabled();
        assert!(!off.should_snapshot_at(100));
        assert!(!off.should_snapshot_at(0));
    }
}
