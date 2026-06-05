//! Consensus participation role: validator vs. full (follow-only) node.
//!
//! Every node in a boule chain receives, verifies, applies, and relays
//! the committed chain identically — that machinery (the dispatch
//! verify path, block/snapshot sync, the commit/apply pipeline) is
//! peer-based and role-agnostic. What distinguishes a **validator** from
//! a **full node** is purely *outbound consensus production*: only a
//! validator signs and broadcasts `Vote`, `Proposal`, `NewView`, and
//! timeout messages that carry voting weight and drive QC/TC formation.
//!
//! A [`NodeRole::Full`] node deliberately emits none of those. It has no
//! voting weight (its `self_id` is not in the validator set), so it
//! *cannot* influence safety even if it tried — but the integration
//! layer gates every weight-bearing message on this role anyway, as a
//! single explicit choke point (#802). This keeps the "a follower must
//! never affect consensus" property checkable in one place rather than
//! relying on the implicit "not in the set ⇒ votes are dropped" behaviour
//! scattered across the safety core.
//!
//! The role is fixed at boot: a validator's `self_id` is in the genesis
//! validator set; a full node's is not. Key rotation only re-keys
//! existing members, and reconfiguration that adds a new validator is a
//! separate concern (a node restarted into a set it newly belongs to
//! boots as a validator). So membership at construction is a stable
//! determinant of the role for the lifetime of the process.

/// Whether this node participates in consensus as a voting validator or
/// merely follows the chain as a full (RPC / observer) node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRole {
    /// In the validator set: proposes, votes, sends timeout messages, and
    /// participates in leader rotation — the full HotStuff replica.
    Validator,
    /// Not in the validator set: receives, verifies, applies, syncs, and
    /// relays the chain, and serves its execution-layer RPC, but emits no
    /// `Vote` / `Proposal` / `NewView` / timeout messages and is never a
    /// round-robin leader. A follow-only node (#802).
    Full,
}

impl NodeRole {
    /// `true` for [`NodeRole::Validator`]. The integration layer gates
    /// every weight-bearing outbound consensus message on this.
    pub const fn is_validator(self) -> bool {
        matches!(self, NodeRole::Validator)
    }

    /// `true` for [`NodeRole::Full`].
    pub const fn is_full(self) -> bool {
        matches!(self, NodeRole::Full)
    }

    /// Stable, human-readable tag for structured-log fields.
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeRole::Validator => "validator",
            NodeRole::Full => "full",
        }
    }
}
