//! The [`StateMachine`] trait consensus replicates over.
//!
//! Consensus orders opaque command bytes (the `Vec<Bytes>` inside a future
//! `Block`) and hands them to a `StateMachine` for execution. The trait is
//! intentionally narrow: apply a command, expose a cheap commitment over
//! current state for inclusion in the next block header, and round-trip
//! through an opaque snapshot blob.
//!
//! # Design notes
//!
//! - `apply` takes `&[u8]` rather than an associated `Command` type so the
//!   trait stays object-safe and a future `Block` can carry `Vec<Bytes>`
//!   without leaking a type parameter into consensus. Typed commands live
//!   inside each implementation.
//! - [`StateMachine::state_commitment`] is split from
//!   [`StateMachine::snapshot`]: consensus needs a fixed-size digest to
//!   stamp into a block header on every commit, while snapshots are bulkier
//!   opaque bytes used for log truncation and catch-up.
//! - Errors surface as `anyhow::Result` to match the rest of the crate
//!   (see `storage/mod.rs`).

use bytes::Bytes;

/// A deterministic state machine that consensus replicates over.
///
/// Implementations MUST be deterministic: given the same initial state and
/// the same command bytes in the same order, every honest replica must
/// arrive at byte-identical [`StateMachine::state_commitment`] and
/// [`StateMachine::snapshot`] values. This is what makes it safe for
/// consensus to stamp [`StateMachine::state_commitment`] into a block
/// header and later compare replicas' executions.
///
/// # Contract
///
/// For any sequence of commands `c0, c1, …, ck`:
///
/// ```text
/// let mut sm = Self::default();
/// for c in &[c0, c1, …, ck] {
///     sm.apply(c)?;
/// }
/// let snap = sm.snapshot();
///
/// let mut other = Self::default();
/// other.restore(&snap)?;
/// assert_eq!(other.state_commitment(), sm.state_commitment());
/// ```
///
/// Applying further commands to the restored machine must produce the same
/// state commitment as applying them to the original.
pub trait StateMachine: Send + Sync {
    /// Apply one command to the state, returning an opaque output.
    ///
    /// The caller passes raw command bytes as they appeared in a block;
    /// the implementation is responsible for deserializing (`postcard` by
    /// convention) and validating the payload. On `Err`, state MUST be
    /// unchanged — consensus relies on failed commands being effectively
    /// a no-op so replicas can agree on which commands were rejected.
    ///
    /// The returned `Bytes` are opaque to consensus; callers that care
    /// about structured output parse it themselves.
    fn apply(&mut self, cmd: &[u8]) -> anyhow::Result<Bytes>;

    /// A deterministic 32-byte commitment over the current state.
    ///
    /// Used as `state_commitment` in the next block header after applying
    /// this block's commands. MUST be cheap to compute (every commit calls
    /// it) and MUST be stable across processes, machines, and architectures
    /// for the same logical state.
    fn state_commitment(&self) -> [u8; 32];

    /// Serialize current state to opaque bytes.
    ///
    /// The returned blob is fed back into [`StateMachine::restore`] to
    /// reconstruct an equivalent state machine. Format is
    /// implementation-defined; consensus treats it as opaque.
    fn snapshot(&self) -> Bytes;

    /// Overwrite state from a snapshot previously produced by
    /// [`StateMachine::snapshot`].
    ///
    /// # Contract
    ///
    /// - **MUST** succeed on any snapshot produced by this same
    ///   `StateMachine` instance's [`Self::snapshot`] on the same
    ///   version of the state machine — the round trip is the basis
    ///   for the proposal-time fork-and-restore in
    ///   `boule_node::consensus_node::block_builder::MempoolBlockBuilder`.
    /// - **MAY** return `Err` on (a) a snapshot produced by a
    ///   *different* version of the state machine (cross-version
    ///   migration), (b) bytes corrupted on disk or in transit, or
    ///   (c) resource exhaustion. Callers treat `Err` as
    ///   recoverable: the consensus loop skips this view's proposal
    ///   rather than panicking the node, and the next-view leader
    ///   takes over (issue #326, audit finding 4-F3).
    /// - On `Err`, the receiver's state is left in an
    ///   implementation-defined but type-valid condition — callers
    ///   that need atomicity should restore into a fresh instance
    ///   and swap only on success.
    fn restore(&mut self, snap: &[u8]) -> anyhow::Result<()>;
}
