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

use crate::{Height, View};
use boule_core::identity::NodeId;

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
    pub height: Height,

    /// HotStuff view in which this block was proposed. Must be strictly
    /// greater than the parent's view (see [`validate_structural`]).
    pub view: View,

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

    /// Cryptographic commitment over the validator-history state at this
    /// block (#325, audit finding 7-F2 anti-rollback). The commitment
    /// covers the active `(ValidatorSetHistory, ValidatorKeyHistory,
    /// BlsKeyHistory?)` triple as observable when this block was built;
    /// see [`crate::history_commitment::validator_history_commitment_v1`]
    /// for the canonical hash. Each block's signature therefore
    /// implicitly attests to the validator-history timeline that
    /// produced it, so a replica restoring from a tampered or
    /// rolled-back persisted history blob can detect the divergence
    /// against the chain's latest committed block.
    ///
    /// PR A populates this field at the leader and stamps a deterministic
    /// value at genesis. Validation at recovery and at proposal-receive
    /// time is wired in by follow-up PRs in the #325 stack — until those
    /// land, the field is informational and never cross-checked.
    pub validator_history_commitment: [u8; 32],

    /// Height of the proposer's committed frontier at the time this block
    /// was built — the anchor for the deferred (lagged) state-root check.
    pub committed_height: Height,

    /// `StateMachine::state_commitment` over the proposer's committed
    /// frontier (the block at [`Self::committed_height`]) — the *lagged*
    /// state root, deliberately not this block's own post-state.
    ///
    /// A voter that has committed to `committed_height` reproduces this
    /// from its own execution before voting; a mismatch means the voter's
    /// state machine has diverged from the chain, and it abstains. Because
    /// the field is in the header hash, the votes that form a block's QC
    /// attest to it — so the lagged root is *agreed*, not one leader's
    /// unverified claim. The deferral (vs. this block's immediate
    /// `state_commitment`) is what makes the check verifiable at vote time
    /// without re-executing the proposed block: execution happens at
    /// commit, so only an already-committed ancestor's root can be
    /// reproduced before voting.
    pub committed_state_root: [u8; 32],

    /// Proposal time as Unix epoch **milliseconds**. The leader stamps
    /// this at build from its wall clock, clamped to never precede the
    /// parent's timestamp so the chain's time is non-decreasing
    /// regardless of clock jumps (NTP, suspend/resume). Genesis is `0`.
    ///
    /// First-class block time for the application's build context — an
    /// execution layer (e.g. a reth EVM payload) derives its block
    /// timestamp from this agreed value rather than inventing its own, so
    /// the time a block executes against is part of what the QC attests
    /// to. [`validate_structural`] enforces only monotonicity
    /// (`child >= parent`); any tighter policy (e.g. EVM's strict
    /// increase, or bounded future drift) is the application's concern.
    pub timestamp: u64,
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
    /// over the initial state machine. `validator_history_commitment` is
    /// the caller-supplied commitment over the genesis-time validator
    /// history (see #325 / [`BlockHeader::validator_history_commitment`]) —
    /// production callers compute this via
    /// [`crate::history_commitment::validator_history_commitment_v1`]
    /// over the freshly-constructed `(ValidatorSetHistory,
    /// ValidatorKeyHistory, BlsKeyHistory?)`; tests that don't exercise
    /// the recovery-time check can pass `[0; 32]`.
    ///
    /// The `proposer` field is all-zero on genesis. Consensus treats
    /// genesis as unsigned and validates it out-of-band against the
    /// configured initial state commitment.
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
                // Genesis is its own committed frontier: height 0 with the
                // initial state root. Inert for the deferred-root check,
                // which only ever compares against a non-genesis proposing
                // block's stamped frontier.
                committed_height: Height::ZERO,
                committed_state_root: state_commitment,
                // Genesis is the chain's time origin.
                timestamp: 0,
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
/// 5. `child.header.timestamp >= parent_header.timestamp` — block time is
///    non-decreasing. Only monotonicity is enforced here; an honest
///    leader clamps to the parent so this always holds, and a Byzantine
///    leader that stamps time backward loses honest votes. Any tighter
///    time policy is the application's concern (see
///    [`BlockHeader::timestamp`]).
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
