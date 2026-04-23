//! The [`Block`] type consensus chains together.
//!
//! A block carries a header (identity + chain-linking metadata) and an
//! ordered `Vec<Bytes>` of opaque application commands. Keeping commands
//! opaque decouples the block format from any particular
//! [`crate::replication::StateMachine`] — the "swap components" property
//! issue #21 is built around.
//!
//! # Content addressing
//!
//! A block's identity is `sha256(postcard(header))`. The header includes
//! `commands_commitment = sha256(postcard(Vec<Bytes>))` so the header
//! hash indirectly commits to the command sequence; consensus never needs
//! to rehash commands to check block integrity.
//!
//! # What lives here vs. the execution layer
//!
//! [`validate_structural`] performs the checks consensus itself needs:
//! parent link, height/view monotonicity, and commands-commitment
//! integrity. Application validation — running each command through the
//! [`crate::replication::StateMachine`] — is the execution layer's
//! concern and lives in milestone 8 (#24), not here.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::p2p::NodeId;

/// Content-address of a block, computed over its header.
pub type BlockHash = [u8; 32];

/// The chain-linking metadata at the top of a [`Block`].
///
/// The header is what consensus signs, hashes, and stamps into QCs. All
/// fields are deterministically serializable via `postcard` (no maps,
/// no floats), matching the convention documented in
/// `src/crypto/signed.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Hash of this block's parent header. All-zero for the genesis block.
    pub parent_hash: BlockHash,

    /// Strictly increasing; genesis is `0`, children add `+1`.
    pub height: u64,

    /// HotStuff view in which this block was proposed. Must be strictly
    /// greater than the parent's view (see [`validate_structural`]).
    pub view: u64,

    /// Ed25519 public key of the proposer, as used by `src/p2p/tls.rs`.
    pub proposer: NodeId,

    /// `StateMachine::state_commitment` after applying this block's commands
    /// to the parent's post-state. Lets a verifier check the execution
    /// result without replaying the full chain from genesis.
    pub state_commitment: [u8; 32],

    /// `sha256(postcard(&commands))` over the block's ordered command
    /// sequence. Binds the header to its payload so tampering with any
    /// command bytes invalidates the block.
    pub commands_commitment: [u8; 32],
}

impl BlockHeader {
    /// Content-address of this header: `sha256(postcard(self))`.
    pub fn hash(&self) -> BlockHash {
        // postcard is deterministic for fixed-shape structs (no maps), so
        // equal headers produce equal hashes across processes and
        // architectures.
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

    /// The canonical genesis block: height 0, view 0, all-zero parent hash,
    /// no commands. `state_commitment` is the caller-supplied commitment
    /// over the initial state machine.
    ///
    /// The `proposer` field is all-zero on genesis. Consensus treats
    /// genesis as unsigned and validates it out-of-band against the
    /// configured initial state commitment.
    pub fn genesis(state_commitment: [u8; 32]) -> Self {
        let commands: Vec<Bytes> = Vec::new();
        Self {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                height: 0,
                view: 0,
                proposer: [0u8; 32],
                state_commitment,
                commands_commitment: Self::commands_commitment(&commands),
            },
            commands,
        }
    }

    /// Compute the commitment that populates [`BlockHeader::commands_commitment`].
    ///
    /// Exposed as a public helper so proposers can fill in the header
    /// consistently with what [`validate_structural`] checks.
    pub fn commands_commitment(commands: &[Bytes]) -> [u8; 32] {
        let bytes = postcard::to_stdvec(commands)
            .expect("postcard encoding of Vec<Bytes> cannot fail for owned buffers");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

/// Consensus-level ("structural") validation of a proposed block against
/// its parent.
///
/// Checks, in order:
///
/// 1. `child.header.parent_hash == parent_header.hash()` — block extends
///    the claimed parent.
/// 2. `child.header.height == parent_header.height + 1` — heights form a
///    contiguous chain.
/// 3. `child.header.view > parent_header.view` — views are strictly
///    increasing (HotStuff safety relies on this; the pacemaker in #22
///    only advances views forward).
/// 4. `child.header.commands_commitment == Block::commands_commitment(&child.commands)`
///    — header binds the command sequence that appeared with it.
///
/// Application validation (running each command through
/// [`crate::replication::StateMachine::apply`] and checking the resulting
/// `state_commitment` against the header) is the execution layer's
/// responsibility and is intentionally out of scope here — consensus
/// only needs the structural half per the #21 non-goals.
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
        .checked_add(1)
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
            height: 4,
            view: 7,
            proposer: [0x22; 32],
            state_commitment: [0x33; 32],
            commands_commitment: Block::commands_commitment(&cmds(&[b"a", b"b"])),
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
        };
        Block { header, commands }
    }

    #[test]
    fn genesis_is_stable_and_zero_parent() {
        let g = Block::genesis([0x77; 32]);
        assert_eq!(g.header.parent_hash, [0u8; 32]);
        assert_eq!(g.header.height, 0);
        assert_eq!(g.header.view, 0);
        assert_eq!(g.header.state_commitment, [0x77; 32]);
        assert!(g.commands.is_empty());

        // Stable across calls.
        let h1 = g.hash();
        let h2 = Block::genesis([0x77; 32]).hash();
        assert_eq!(h1, h2);
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
        perturbed.height = perturbed.height.wrapping_add(1);
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.view = perturbed.view.wrapping_add(1);
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.proposer[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h.clone();
        perturbed.state_commitment[0] ^= 0xFF;
        assert_ne!(perturbed.hash(), original);

        let mut perturbed = h;
        perturbed.commands_commitment[0] ^= 0xFF;
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
        child.header.view = parent.view.saturating_sub(1);
        let err = validate_structural(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("view must strictly increase"));
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
