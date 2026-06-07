//! The [`Block`] type consensus chains together.
//!
//! A block is a header (identity + chain-linking metadata) plus an ordered
//! `Vec<Bytes>` of opaque application commands. Commands stay opaque so the
//! block format is independent of any [`crate::replication::StateMachine`].
//!
//! # Content addressing
//!
//! A block's identity is `sha256(postcard(header))`. The header carries
//! `commands_commitment = sha256(postcard(commands))`, so the header hash
//! transitively commits to the command sequence — integrity checks never
//! rehash the commands.
//!
//! [`validate_structural`] runs the checks consensus needs (parent link,
//! height/view/timestamp monotonicity, commands commitment). Running
//! commands through the [`crate::replication::StateMachine`] is the
//! execution layer's job, not this module's.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Height, View};
use boule_core::identity::NodeId;

/// Content-address of a block, computed over its header.
pub type BlockHash = [u8; 32];

/// The chain-linking metadata at the top of a [`Block`].
///
/// Consensus signs, hashes, and stamps this into QCs. All fields are
/// deterministically `postcard`-serializable (no maps, no floats), so equal
/// headers hash equally across processes and architectures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Hash of this block's parent header. All-zero for the genesis block.
    pub parent_hash: BlockHash,

    /// Strictly increasing; genesis is `0`, children add `+1`.
    pub height: Height,

    /// HotStuff view in which this block was proposed. Must be strictly
    /// greater than the parent's view (see [`validate_structural`]).
    pub view: View,

    /// Ed25519 public key of the proposer. All-zero on genesis.
    pub proposer: NodeId,

    /// `StateMachine::state_commitment` after applying this block's commands
    /// to the parent's post-state. Lets a verifier check the execution
    /// result without replaying the full chain from genesis.
    pub state_commitment: [u8; 32],

    /// `sha256(postcard(&commands))` over the block's ordered command
    /// sequence. Binds the header to its payload so tampering with any
    /// command bytes invalidates the block.
    pub commands_commitment: [u8; 32],

    /// Commitment over the validator-history state observable when this
    /// block was built — the active `(ValidatorSetHistory,
    /// ValidatorKeyHistory, BlsKeyHistory?)` triple, hashed by
    /// [`crate::history_commitment::validator_history_commitment_v1`].
    /// Binds each block's signature to the validator-history timeline that
    /// produced it, so a replica recovering from a tampered or rolled-back
    /// history blob can detect the divergence against the latest committed
    /// block.
    pub validator_history_commitment: [u8; 32],

    /// Height of the proposer's committed frontier when this block was
    /// built — the anchor for the lagged state-root check
    /// ([`Self::committed_state_root`]).
    pub committed_height: Height,

    /// `StateMachine::state_commitment` over the proposer's committed
    /// frontier (the block at [`Self::committed_height`]) — the *lagged*
    /// root, not this block's own post-state.
    ///
    /// A voter that has committed to `committed_height` reproduces this from
    /// its own execution before voting and abstains on mismatch. Being in
    /// the header hash, a block's QC attests to it, so the lagged root is
    /// agreed rather than the leader's unverified claim. Lagging (vs. the
    /// immediate `state_commitment`) is what makes the check verifiable
    /// before the proposed block is itself executed at commit.
    pub committed_state_root: [u8; 32],

    /// Proposal time in Unix-epoch milliseconds. The leader stamps it from
    /// its wall clock, clamped to never precede the parent so chain time is
    /// non-decreasing across clock jumps; genesis is `0`.
    ///
    /// The agreed block time for the application's build context (e.g. an
    /// EVM payload derives its timestamp from this), so what a block
    /// executes against is part of what the QC attests to.
    /// [`validate_structural`] enforces only monotonicity (`child >=
    /// parent`); any tighter policy is the application's concern.
    pub timestamp: u64,
}

impl BlockHeader {
    /// Content-address of this header: `sha256(postcard(self))`.
    pub fn hash(&self) -> BlockHash {
        let bytes =
            postcard::to_stdvec(self).expect("postcard encoding of BlockHeader cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

/// A proposed or committed block: header plus the ordered command bytes
/// the block agrees on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub commands: Vec<Bytes>,
}

impl Block {
    /// Content-address of this block. Equal to `self.header.hash()` —
    /// exposed on `Block` for ergonomic use.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// The canonical genesis block: height 0, view 0, zero parent hash, no
    /// commands, all-zero `proposer`. `state_commitment` commits to the
    /// initial state machine; `validator_history_commitment` commits to the
    /// genesis validator history (production callers compute it via
    /// [`crate::history_commitment::validator_history_commitment_v1`]; tests
    /// not exercising the recovery check may pass `[0; 32]`).
    ///
    /// Consensus treats genesis as unsigned and validates it out-of-band
    /// against the configured initial commitments.
    pub fn genesis(state_commitment: [u8; 32], validator_history_commitment: [u8; 32]) -> Self {
        let commands: Vec<Bytes> = Vec::new();
        Self {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                height: Height::ZERO,
                view: View::ZERO,
                proposer: [0u8; 32],
                state_commitment,
                commands_commitment: Self::commands_commitment(&commands),
                validator_history_commitment,
                // Genesis is its own committed frontier (height 0, initial
                // state root); inert for the lagged-root check, which only
                // compares against a non-genesis block's stamped frontier.
                committed_height: Height::ZERO,
                committed_state_root: state_commitment,
                timestamp: 0,
            },
            commands,
        }
    }

    /// Compute [`BlockHeader::commands_commitment`] for a command sequence.
    /// Public so proposers fill the header consistently with what
    /// [`validate_structural`] checks.
    pub fn commands_commitment(commands: &[Bytes]) -> [u8; 32] {
        let bytes = postcard::to_stdvec(commands)
            .expect("postcard encoding of Vec<Bytes> cannot fail for owned buffers");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

/// Consensus-level ("structural") validation of a proposed block against
/// its parent. Checks, in order:
///
/// 1. `parent_hash == parent_header.hash()` — extends the claimed parent.
/// 2. `height == parent.height + 1` — contiguous chain.
/// 3. `view > parent.view` — strictly increasing (HotStuff safety).
/// 4. `commands_commitment == Block::commands_commitment(&commands)` — the
///    header binds the command sequence that appeared with it.
/// 5. `timestamp >= parent.timestamp` — block time non-decreasing. An
///    honest leader clamps to the parent so this holds; a leader stamping
///    time backward loses honest votes. Tighter policy is the
///    application's concern (see [`BlockHeader::timestamp`]).
///
/// Application validation (running commands through
/// [`crate::replication::StateMachine::apply`] and checking the resulting
/// `state_commitment`) is the execution layer's responsibility and is out
/// of scope here.
pub fn validate_structural(child: &Block, parent_header: &BlockHeader) -> anyhow::Result<()> {
    let parent_hash = parent_header.hash();
    if child.header.parent_hash != parent_hash {
        anyhow::bail!(
            "parent_hash mismatch: child claims {}, parent hashes to {}",
            hex::encode(child.header.parent_hash),
            hex::encode(parent_hash),
        );
    }
    let expected_height = parent_header
        .height
        .checked_add(Height(1))
        .ok_or_else(|| anyhow::anyhow!("parent height {} overflows u64", parent_header.height))?;
    if child.header.height != expected_height {
        anyhow::bail!(
            "height mismatch: expected {}, got {}",
            expected_height,
            child.header.height,
        );
    }
    if child.header.view <= parent_header.view {
        anyhow::bail!(
            "view must strictly increase: parent view {}, child view {}",
            parent_header.view,
            child.header.view,
        );
    }
    let recomputed = Block::commands_commitment(&child.commands);
    if child.header.commands_commitment != recomputed {
        anyhow::bail!(
            "commands_commitment mismatch: header {}, recomputed {}",
            hex::encode(child.header.commands_commitment),
            hex::encode(recomputed),
        );
    }
    if child.header.timestamp < parent_header.timestamp {
        anyhow::bail!(
            "timestamp must not decrease: parent {}, child {}",
            parent_header.timestamp,
            child.header.timestamp,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(xs: &[&[u8]]) -> Vec<Bytes> {
        xs.iter().map(|b| Bytes::copy_from_slice(b)).collect()
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            parent_hash: [0x11; 32],
            height: Height(4),
            view: View(7),
            proposer: [0x22; 32],
            state_commitment: [0x33; 32],
            commands_commitment: Block::commands_commitment(&cmds(&[b"a", b"b"])),
            validator_history_commitment: [0; 32],
            committed_height: Height(2),
            committed_state_root: [0x66; 32],
            timestamp: 0,
        }
    }

    fn child_of(parent: &BlockHeader, commands: Vec<Bytes>) -> Block {
        let header = BlockHeader {
            parent_hash: parent.hash(),
            height: parent.height + 1,
            view: parent.view + 1,
            proposer: [0x44; 32],
            state_commitment: [0x55; 32],
            commands_commitment: Block::commands_commitment(&commands),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
            timestamp: parent.timestamp,
        };
        Block { header, commands }
    }

    #[test]
    fn genesis_is_stable_and_zero_parent() {
        let g = Block::genesis([0x77; 32], [0x88; 32]);
        assert_eq!(g.header.parent_hash, [0u8; 32]);
        assert_eq!(g.header.height, Height(0));
        assert_eq!(g.header.view, View(0));
        assert_eq!(g.header.state_commitment, [0x77; 32]);
        assert_eq!(g.header.validator_history_commitment, [0x88; 32]);
        assert!(g.commands.is_empty());

        // Stable across calls.
        let h1 = g.hash();
        let h2 = Block::genesis([0x77; 32], [0x88; 32]).hash();
        assert_eq!(h1, h2);

        // Different validator_history_commitment ⇒ different genesis hash:
        // genesis identity binds to the validator history at v=0.
        let other = Block::genesis([0x77; 32], [0x99; 32]).hash();
        assert_ne!(h1, other);
    }

    #[test]
    fn hash_roundtrips_through_postcard() {
        let block = Block {
            header: sample_header(),
            commands: cmds(&[b"a", b"b"]),
        };
        let encoded = postcard::to_stdvec(&block).unwrap();
        let decoded: Block = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, block);
        assert_eq!(decoded.hash(), block.hash());
    }

    #[test]
    fn tampering_with_any_header_field_changes_hash() {
        let h = sample_header();
        let original = h.hash();

        let mut perturbed = h.clone();
        perturbed.parent_hash[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.height = Height(perturbed.height.0.wrapping_add(1));
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.view = View(perturbed.view.0.wrapping_add(1));
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.proposer[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.state_commitment[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.commands_commitment[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.validator_history_commitment[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.committed_height = Height(perturbed.committed_height.0.wrapping_add(1));
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h;
        perturbed.committed_state_root[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);
    }

    #[test]
    fn valid_child_passes_structural_validation() {
        let parent = sample_header();
        let child = child_of(&parent, cmds(&[b"x", b"y", b"z"]));
        validate_structural(&child, &parent).unwrap();
    }

    #[test]
    fn tampered_command_without_updating_commitment_fails() {
        let parent = sample_header();
        let mut child = child_of(&parent, cmds(&[b"x", b"y"]));
        // Mutate a command byte without updating `commands_commitment`.
        child.commands[0] = Bytes::copy_from_slice(b"X");
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("commands_commitment mismatch"));
    }

    #[test]
    fn wrong_parent_hash_fails() {
        let parent = sample_header();
        let mut child = child_of(&parent, cmds(&[b"a"]));
        child.header.parent_hash[0] ^= 0xFF;
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("parent_hash mismatch"));
    }

    #[test]
    fn non_contiguous_height_fails() {
        let parent = sample_header();
        let mut child = child_of(&parent, cmds(&[b"a"]));
        child.header.height = parent.height + 2;
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("height mismatch"));
    }

    #[test]
    fn non_increasing_view_fails() {
        let parent = sample_header();
        let mut child = child_of(&parent, cmds(&[b"a"]));
        child.header.view = parent.view; // not strictly greater
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("view must strictly increase"));

        // Also rejects a decreasing view.
        child.header.view = parent.view.saturating_sub(View(1));
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("view must strictly increase"));
    }

    #[test]
    fn non_decreasing_timestamp_passes() {
        let mut parent = sample_header();
        parent.timestamp = 1_000;
        // Equal to the parent is allowed (sub-second blocks may share a
        // millisecond); strictly greater is the common case.
        let mut child = child_of(&parent, cmds(&[b"a"]));
        child.header.timestamp = parent.timestamp;
        validate_structural(&child, &parent).unwrap();
        child.header.timestamp = parent.timestamp + 1;
        validate_structural(&child, &parent).unwrap();
    }

    #[test]
    fn decreasing_timestamp_fails() {
        let mut parent = sample_header();
        parent.timestamp = 1_000;
        let mut child = child_of(&parent, cmds(&[b"a"]));
        child.header.timestamp = parent.timestamp - 1;
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("timestamp must not decrease"));
    }

    #[test]
    fn empty_command_list_has_stable_commitment() {
        // Distinct hashes for empty vs. non-empty command lists keep
        // tampering detectable even for "empty block" edge cases.
        let empty = Block::commands_commitment(&[]);
        let one = Block::commands_commitment(&cmds(&[b""]));
        assert_ne!(empty, one, "empty list and list-of-empty-bytes must differ");
    }
}
