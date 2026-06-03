//! Validator-set reconfiguration command payload (#247).
//!
//! A [`ReconfigCommand`] is a typed payload the leader can embed in a
//! block's `commands` slot to propose a validator-set change effective at
//! a future view. This module defines the type, its on-the-wire codec, and
//! pre-commit validation. The commit-time application path — when a
//! committed reconfig actually rolls in — is the work of #253.
//!
//! # Wire format
//!
//! The byte stream is `RECONFIG_TAG || postcard(ReconfigCommand)`. The tag
//! prefix lets the dispatcher tell a reconfig command apart from opaque
//! application command bytes without attempt-then-rollback deserialization
//! of every `Bytes` slot in `Block.commands`.
//!
//! # Floors and delays
//!
//! [`MIN_VALIDATOR_FLOOR`] and [`MIN_V_EFF_DELAY`] are the consensus-side
//! constraints called out by #140's acceptance criteria and open
//! questions. They live here so the CLI (#251) and the commit-time
//! application path (#253) consume the same constants.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_set::{ValidatorId, ValidatorSet};
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsKeyError, BlsPop, SignatureSchemeChoice};
use boule_core::crypto::signed::ChainId;
use boule_core::identity::NodeId;

/// Magic prefix that tags a `Block.commands` entry as a reconfig payload.
pub const RECONFIG_TAG: &[u8; 6] = b"RECFG\0";

/// Minimum size the validator set may shrink to via reconfig.
///
/// Mirrors the `3f + 1 = 4` floor for the smallest `f` operators want to
/// support; #140's "Cannot reduce the validator set below `3f + 1`"
/// criterion. A reconfig whose result would drop the active set below
/// this is rejected pre-commit.
pub const MIN_VALIDATOR_FLOOR: usize = 4;

/// Minimum gap (in views) between the proposing block's view and the
/// proposed effective view.
///
/// A reconfig validated against block view `N` must target `v_eff >= N +
/// MIN_V_EFF_DELAY`. The floor must exceed the **commit depth**: a reconfig
/// rides in a block at view `N` that only commits ~`N + 3` views later (the
/// HotStuff three-chain), and the boundary is applied at commit. A `v_eff`
/// at or below the commit view lands *in the past* — retroactively
/// reassigning the validator set for views where QCs were already formed
/// under the old set, which then fail verification and stall the chain
/// (#667). At `MIN_V_EFF_DELAY = 4`, `v_eff >= N + 4` clears the three-chain
/// commit (~`N + 3`), so the boundary is still in the future when applied.
/// This also gives a newly-added validator a window to finish state sync
/// (#139) before it must vote. Operators may target a larger delay via the
/// CLI but cannot undercut this floor.
///
/// Note: this is a happy-path floor. Under sustained timeouts a reconfig
/// block can commit much later than `N + 3`, so even `N + 4` can be
/// overtaken — a fully timeout-robust bound is tracked in #667.
pub const MIN_V_EFF_DELAY: View = View::new(4);

/// A pubkey + network address pair describing a validator to admit.
///
/// `node_id` is the Ed25519 pubkey used by `boule_transport_tcp::tls`; `addr` is
/// the routable socket peers should use to reach this validator. On BLS
/// chains (#143 / #289) `bls_pop` carries the new validator's BLS
/// pubkey paired with a proof-of-possession signature over that pubkey;
/// on Ed25519 chains the field is `None`. The reconfig validator (this
/// module) verifies the PoP whenever it is present, regardless of the
/// chain's scheme — scheme-driven enforcement (PoP *required* on BLS
/// chains) lands together with the rest of the BLS integration in #293.
///
/// `weight` is the validator's voting weight when seated (#462). Must
/// be `>= 1`; weight 0 is rejected at validation time, mirroring the
/// `ValidatorSet::with_weights` invariant from #460.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    /// Optional BLS proof-of-possession bundle (pubkey + sig over the
    /// pubkey under the IETF `_POP_` ciphersuite). `None` on Ed25519
    /// chains; required and verified on BLS chains (#293 enforces the
    /// "required" half).
    ///
    /// Always serialized (postcard is schema-bound and does not
    /// tolerate `skip_serializing_if`) — `None` adds a single Option
    /// discriminant byte to the wire payload.
    pub bls_pop: Option<BlsPop>,
    /// Voting weight to assign this validator at and after `v_eff`
    /// (#462). The weighted-quorum predicate
    /// ([`crate::hotstuff::qc::QuorumCertificate::has_quorum`])
    /// reads this via the boundary's [`crate::validator_set::ValidatorSet`].
    /// Validation rejects `weight == 0` — the reconfig "remove" path
    /// is the canonical way to spell removal.
    pub weight: u64,
    /// Optional operator key (#549) for the validator being admitted: the
    /// cold-storage administrative key that can later rotate this validator's
    /// signing key without the old key (recovery) or rotate itself. `None`
    /// seats the validator with no operator key (no recovery path) — e.g. a
    /// staking-driven add whose source carries no operator pubkey. Registered
    /// in the operator-key history at `v_eff`, the same way `node_id` is
    /// mirrored into the signing-key history. Ed25519 like the validator's own
    /// NodeId; multi-sig is an operator-side choice (the protocol just verifies
    /// whatever Ed25519 signature the operator later presents).
    ///
    /// Always serialized (postcard is schema-bound) — `None` adds one Option
    /// discriminant byte, like `bls_pop`.
    pub operator_pubkey: Option<NodeId>,
}

/// A weight-only adjustment for a currently-seated validator. Equivalent
/// to "the existing member's voting weight changes from its current
/// value to `weight` at and after `v_eff`" without altering membership
/// (#462). Composes with `adds` / `removes` in the same
/// [`ReconfigCommand`] under the disjointness rules in
/// [`ReconfigCommand::validate_against_with_delay_and_scheme`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightChange {
    pub node_id: NodeId,
    pub weight: u64,
}

/// A typed reconfiguration payload.
///
/// `adds`, `removes`, and `changes` describe the diff against the
/// active set. `v_eff` is the view at which the resulting set becomes
/// authoritative. See [`crate::reconfig::ReconfigCommand::validate_against_with_delay_and_scheme`] for the exact
/// pre-commit checks.
///
/// **Wire-format note (#462):** `ValidatorEntry` gains a `weight`
/// field and `ReconfigCommand` gains a `changes` field — both bump the
/// postcard layout. Pre-#462 reconfig payloads in mempools or on disk
/// will not decode under the new layout and are silently ignored
/// (see `is_reconfig_payload` + `decode`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconfigCommand {
    pub adds: Vec<ValidatorEntry>,
    pub removes: Vec<NodeId>,
    /// Weight-only adjustments for currently-seated validators (#462).
    /// Each entry must reference a current member and carry a non-
    /// zero weight; conflicts with `adds`/`removes` are rejected.
    pub changes: Vec<WeightChange>,
    pub v_eff: View,
}

impl ReconfigCommand {
    /// Encode as a tagged byte sequence suitable for `Block.commands`.
    pub fn encode(&self) -> Bytes {
        let body =
            postcard::to_stdvec(self).expect("postcard encoding of ReconfigCommand cannot fail");
        let mut out = Vec::with_capacity(RECONFIG_TAG.len() + body.len());
        out.extend_from_slice(RECONFIG_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    /// True iff `bytes` carries the reconfig tag prefix.
    pub fn is_reconfig_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(RECONFIG_TAG)
    }

    /// Decode a tagged reconfig command. Errors if the tag is absent or
    /// the body is malformed.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(RECONFIG_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing reconfig tag prefix"))?;
        postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed ReconfigCommand: {e}"))
    }

    /// Construct a tagged "add a single validator" payload at the
    /// supplied voting weight. Convenience wrapper used by the CLI
    /// (#251 / #462).
    pub fn build_add_validator_payload(
        node_id: NodeId,
        addr: SocketAddr,
        weight: u64,
        v_eff: View,
    ) -> Bytes {
        Self {
            adds: vec![ValidatorEntry {
                node_id,
                addr,
                bls_pop: None,
                weight,
                operator_pubkey: None,
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        }
        .encode()
    }

    /// Construct a tagged "remove a single validator" payload.
    /// Convenience wrapper used by the CLI (#251).
    pub fn build_remove_validator_payload(node_id: NodeId, v_eff: View) -> Bytes {
        Self {
            adds: vec![],
            removes: vec![node_id],
            changes: vec![],
            v_eff,
        }
        .encode()
    }

    /// Construct a tagged "change a validator's weight" payload (#462).
    /// The validator must be a current member at `v_eff`; the weight
    /// must be non-zero. Validation rules apply at commit time.
    pub fn build_change_weight_payload(node_id: NodeId, weight: u64, v_eff: View) -> Bytes {
        Self {
            adds: vec![],
            removes: vec![],
            changes: vec![WeightChange { node_id, weight }],
            v_eff,
        }
        .encode()
    }

    /// Validate this command against the active state at validation time.
    /// Returns the resulting weighted member list (sorted by `NodeId`,
    /// deduplicated) on success.
    ///
    /// Checks:
    /// - `v_eff >= current_view + MIN_V_EFF_DELAY`.
    /// - No duplicates within `adds` / `removes` / `changes`, and no
    ///   `NodeId` appearing in more than one of those lists.
    /// - Each `removes` entry is currently a member.
    /// - Each `changes` entry is currently a member.
    /// - No `adds` entry is currently a member.
    /// - Every weight (in `adds` and `changes`) is `>= 1`.
    /// - Resulting set size `>= MIN_VALIDATOR_FLOOR`.
    ///
    /// Test-only shim around [`Self::validate_against_with_delay_and_scheme`]
    /// — production callers thread in the chain's real scheme and
    /// chain_id rather than relying on the Ed25519 + [`ChainId::TEST`]
    /// defaults this wrapper hardcodes.
    #[cfg(test)]
    pub fn validate_against(
        &self,
        current_set: &ValidatorSet,
        current_view: impl Into<View>,
    ) -> anyhow::Result<Vec<(NodeId, u64)>> {
        self.validate_against_with_delay(current_set, current_view.into(), MIN_V_EFF_DELAY)
    }

    /// Same as [`crate::reconfig::ReconfigCommand::validate_against_with_delay_and_scheme`] but uses an operator-supplied
    /// minimum delay floor, which must be at least [`MIN_V_EFF_DELAY`].
    /// Wired through [`crate::wire::NodeConfigForConsensus::min_v_eff_delay`]
    /// (#272) so deployments can require a longer "give the new
    /// validator time to state-sync" window than the consensus floor.
    ///
    /// This shim is `cfg(test)` because it assumes
    /// [`SignatureSchemeChoice::Ed25519Collected`] and uses
    /// [`ChainId::TEST`], both of which are inappropriate for
    /// production. Production callers go through
    /// [`Self::validate_against_with_delay_and_scheme`] with the
    /// chain's real scheme + chain_id.
    #[cfg(test)]
    pub fn validate_against_with_delay(
        &self,
        current_set: &ValidatorSet,
        current_view: impl Into<View>,
        min_v_eff_delay: View,
    ) -> anyhow::Result<Vec<(NodeId, u64)>> {
        // Ed25519 chains never read the chain_id arg (PoPs are absent),
        // so the test sentinel is safe here.
        self.validate_against_with_delay_and_scheme(
            current_set,
            current_view.into(),
            min_v_eff_delay,
            SignatureSchemeChoice::Ed25519Collected,
            &ChainId::TEST,
        )
    }

    /// Scheme-aware variant of [`crate::reconfig::ReconfigCommand::validate_against_with_delay_and_scheme`].
    /// Adds two checks driven by the chain's signature scheme (#334):
    ///
    /// - BLS chain: every `adds` entry must carry a `bls_pop` whose
    ///   pre-image binds to `chain_id` (#410). Without the PoP, a
    ///   Byzantine proposer could seat a validator with no verifiable
    ///   BLS pubkey and stall every QC the new committee tries to
    ///   form; without the chain_id binding, an attacker could
    ///   cross-replay a PoP minted on another deployment.
    /// - Ed25519 chain: no `adds` entry may carry a `bls_pop`. A BLS
    ///   PoP on an Ed25519 chain has no semantic meaning; accepting it
    ///   would mask a misconfigured operator who copied a BLS-chain
    ///   payload onto an Ed25519 chain.
    pub fn validate_against_with_delay_and_scheme(
        &self,
        current_set: &ValidatorSet,
        current_view: impl Into<View>,
        min_v_eff_delay: View,
        scheme: SignatureSchemeChoice,
        chain_id: &ChainId,
    ) -> anyhow::Result<Vec<(NodeId, u64)>> {
        let current_view = current_view.into();
        let effective_delay = std::cmp::max(min_v_eff_delay, MIN_V_EFF_DELAY);
        let min_v_eff = current_view.checked_add(effective_delay).ok_or_else(|| {
            anyhow::anyhow!("current_view {current_view} + delay {effective_delay} overflows",)
        })?;
        if self.v_eff < min_v_eff {
            anyhow::bail!(
                "v_eff {} must be >= current_view {} + delay {}",
                self.v_eff,
                current_view,
                effective_delay
            );
        }

        // Weight gating: weight 0 is reserved (matches
        // ValidatorSet::with_weights's #460 invariant). Reject in
        // adds and changes alike, before any membership lookups —
        // catches the misuse with a clear error.
        for entry in &self.adds {
            if entry.weight == 0 {
                anyhow::bail!(
                    "validator {} has weight 0; weight 0 is reserved — \
                     remove the validator via `removes` instead.",
                    hex::encode(entry.node_id),
                );
            }
        }
        for change in &self.changes {
            if change.weight == 0 {
                anyhow::bail!(
                    "weight change for {} carries weight 0; weight 0 is reserved — \
                     remove the validator via `removes` instead.",
                    hex::encode(change.node_id),
                );
            }
        }

        let mut adds_seen: BTreeSet<NodeId> = BTreeSet::new();
        for entry in &self.adds {
            if !adds_seen.insert(entry.node_id) {
                anyhow::bail!("duplicate node_id in adds: {}", hex::encode(entry.node_id));
            }
        }

        let mut removes_seen: BTreeSet<NodeId> = BTreeSet::new();
        for n in &self.removes {
            if !removes_seen.insert(*n) {
                anyhow::bail!("duplicate node_id in removes: {}", hex::encode(n));
            }
        }

        let mut changes_seen: BTreeSet<NodeId> = BTreeSet::new();
        for change in &self.changes {
            if !changes_seen.insert(change.node_id) {
                anyhow::bail!(
                    "duplicate node_id in changes: {}",
                    hex::encode(change.node_id)
                );
            }
        }

        if let Some(n) = adds_seen.intersection(&removes_seen).next() {
            anyhow::bail!(
                "node_id appears in both adds and removes: {}",
                hex::encode(n)
            );
        }
        if let Some(n) = adds_seen.intersection(&changes_seen).next() {
            anyhow::bail!(
                "node_id appears in both adds and changes: {}",
                hex::encode(n)
            );
        }
        if let Some(n) = removes_seen.intersection(&changes_seen).next() {
            anyhow::bail!(
                "node_id appears in both removes and changes: {}",
                hex::encode(n)
            );
        }

        // Reconfig payloads come in over the wire as `NodeId` bytes;
        // bridge to the typed `ValidatorId` for membership checks
        // (#328). At reconfig-validation time the bytes haven't been
        // promoted to a stable id yet, but the membership check is
        // semantically "is this *node id* a current member" — and a
        // current member's stable id has the same bytes by genesis
        // construction, so the lookup is correct via
        // `from_genesis_pubkey`.
        for n in &removes_seen {
            let vid = ValidatorId::from_genesis_pubkey(*n);
            if !current_set.contains(&vid) {
                anyhow::bail!("remove targets non-member: {}", hex::encode(n));
            }
        }

        for n in &adds_seen {
            let vid = ValidatorId::from_genesis_pubkey(*n);
            if current_set.contains(&vid) {
                anyhow::bail!("add targets existing member: {}", hex::encode(n));
            }
        }

        for n in &changes_seen {
            let vid = ValidatorId::from_genesis_pubkey(*n);
            if !current_set.contains(&vid) {
                anyhow::bail!("change targets non-member: {}", hex::encode(n));
            }
        }

        // Verify any embedded BLS proof-of-possession AND enforce the
        // scheme-driven presence rule.
        //
        // Cryptographic check: every entry that carries a `bls_pop` is
        // verified here so a malformed PoP is rejected pre-commit
        // regardless of scheme.
        //
        // Presence check: on BLS chains, every `adds` entry MUST carry
        // a PoP — otherwise the new validator would be seated with no
        // verifiable BLS pubkey and the next QC would stall. On
        // Ed25519 chains, no `adds` entry may carry one — a BLS PoP
        // has no semantic meaning there, and silently accepting it
        // would mask a misconfigured operator.
        for entry in &self.adds {
            match (&entry.bls_pop, scheme) {
                (Some(pop), _) => {
                    BlsAggregated::verify_pop(pop, &pop.pubkey, chain_id).map_err(|e| match e {
                        BlsKeyError::PopPubkeyMismatch => anyhow::anyhow!(
                            "BLS PoP for validator {} has mismatched embedded pubkey",
                            hex::encode(entry.node_id),
                        ),
                        BlsKeyError::Blst(err) => anyhow::anyhow!(
                            "BLS PoP for validator {} failed to verify: {err:?}",
                            hex::encode(entry.node_id),
                        ),
                    })?;
                    if matches!(scheme, SignatureSchemeChoice::Ed25519Collected) {
                        anyhow::bail!(
                            "validator {} carries a BLS PoP but the chain's signature_scheme = \
                             \"ed25519_collected\" — Ed25519 chains have no use for BLS keys.",
                            hex::encode(entry.node_id),
                        );
                    }
                }
                (None, SignatureSchemeChoice::BlsAggregated) => {
                    anyhow::bail!(
                        "validator {} has no bls_pop but the chain's signature_scheme = \
                         \"bls_aggregated\" — every BLS-chain `adds` entry must declare a \
                         proof-of-possession.",
                        hex::encode(entry.node_id),
                    );
                }
                (None, SignatureSchemeChoice::Ed25519Collected) => {}
            }
        }

        // Build the (NodeId, weight) map. Start from the current set's
        // weights, drop removes, apply changes, append adds; sort by
        // NodeId for deterministic output.
        let mut next: Vec<(NodeId, u64)> = current_set
            .iter_weighted()
            .map(|(v, w)| (v.into_node_id(), w))
            .filter(|(n, _)| !removes_seen.contains(n))
            .collect();
        // Apply weight changes in-place.
        for change in &self.changes {
            if let Some((_, w)) = next.iter_mut().find(|(n, _)| *n == change.node_id) {
                *w = change.weight;
            }
            // Membership for changes was confirmed above; the lookup
            // here can fail only if a `removes` already filtered the
            // entry, which the disjointness check above also rules
            // out. Skip silently — defensive idempotency.
        }
        // Append adds with their declared weights.
        for entry in &self.adds {
            next.push((entry.node_id, entry.weight));
        }
        next.sort_by_key(|(n, _)| *n);
        next.dedup_by_key(|(n, _)| *n);

        if next.len() < MIN_VALIDATOR_FLOOR {
            anyhow::bail!(
                "resulting set size {} below floor {}",
                next.len(),
                MIN_VALIDATOR_FLOOR
            );
        }

        Ok(next)
    }
}

/// Read a `<pubkey_hex>:<pop_hex>` file (48-byte BLS pubkey + 96-byte
/// PoP signature). Whitespace at either end is ignored. Backs the
/// `--bls-pop-file` flag of `reconfig add-validator`.
pub fn read_bls_pop_file(path: &Path) -> anyhow::Result<BlsPop> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading --bls-pop-file {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    let (pk_hex, sig_hex) = trimmed.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not in the expected `<pubkey_hex>:<pop_hex>` format",
            path.display(),
        )
    })?;
    let pk_bytes = hex::decode(pk_hex.trim())
        .map_err(|e| anyhow::anyhow!("--bls-pop-file pubkey is not valid hex: {e}"))?;
    let sig_bytes = hex::decode(sig_hex.trim())
        .map_err(|e| anyhow::anyhow!("--bls-pop-file pop signature is not valid hex: {e}"))?;
    if pk_bytes.len() != 48 {
        anyhow::bail!(
            "--bls-pop-file pubkey is {} bytes, expected 48",
            pk_bytes.len(),
        );
    }
    if sig_bytes.len() != 96 {
        anyhow::bail!(
            "--bls-pop-file pop signature is {} bytes, expected 96",
            sig_bytes.len(),
        );
    }
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&pk_bytes);
    let mut sig = [0u8; 96];
    sig.copy_from_slice(&sig_bytes);
    Ok(BlsPop { pubkey, sig })
}

/// Load a [`boule_core::crypto::bls_key::BlsKeyFile`] and derive a
/// chain-id-bound PoP (#410) on the fly, letting an operator generate an
/// add-validator payload from a freshly-provisioned BLS key file in one
/// step. The PoP pre-image binds to `chain_id` so the same key produces a
/// different PoP per deployment, blocking cross-chain replay.
pub fn derive_bls_pop_from_key_file(path: &Path, chain_id: &ChainId) -> anyhow::Result<BlsPop> {
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    let provider = BlsKeyFile::new(path.to_path_buf());
    let id = provider
        .load_or_init()
        .map_err(|e| anyhow::anyhow!("loading BLS key from {}: {e}", path.display()))?;
    BlsAggregated::sign_pop(&id.secret, chain_id)
        .map_err(|e| anyhow::anyhow!("signing BLS PoP for {}: {e:?}", path.display()))
}

/// Build the encoded `add-validator` reconfig payload. When `config` is
/// supplied, cross-checks the chain's `signature_scheme` against BLS-flag
/// presence (#334), derives the chain_id for PoP binding (#410), and
/// locally verifies any resolved PoP. `bls_pop_file` and `bls_key_file`
/// are mutually exclusive. Backs `reconfig add-validator`.
#[allow(clippy::too_many_arguments)]
pub fn build_add_validator_payload(
    config: Option<&boule_core::config::Config>,
    node_id: NodeId,
    addr: SocketAddr,
    v_eff: View,
    weight: u64,
    bls_pop_file: Option<&Path>,
    bls_key_file: Option<&Path>,
    operator_pubkey: Option<NodeId>,
) -> anyhow::Result<Bytes> {
    if bls_pop_file.is_some() && bls_key_file.is_some() {
        anyhow::bail!(
            "--bls-pop-file and --bls-key-file are mutually exclusive — pass one or the other.",
        );
    }
    if (bls_pop_file.is_some() || bls_key_file.is_some()) && config.is_none() {
        anyhow::bail!(
            "--bls-pop-file / --bls-key-file requires --config so the chain_id can be derived \
             from the genesis. BLS proof-of-possession pre-images bind to chain_id (#410); \
             without --config the CLI cannot mint or verify the PoP.",
        );
    }

    // Resolve the chain_id (when --config is supplied) once, up front —
    // used by the local PoP verify and threaded into the fresh-mint path.
    let cfg_chain_id: Option<ChainId> = if let Some(cfg) = config {
        let cons = cfg.consensus.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--config has no [consensus] section — cannot infer scheme or chain_id")
        })?;
        // Scheme cross-check (#334): refuse to build a payload that would
        // be rejected at commit time by scheme-driven enforcement.
        match (cons.signature_scheme, bls_pop_file, bls_key_file) {
            (SignatureSchemeChoice::BlsAggregated, None, None) => {
                anyhow::bail!(
                    "--config declares signature_scheme = \"bls_aggregated\" but no \
                     --bls-pop-file or --bls-key-file was supplied. Every BLS-chain `adds` \
                     entry must carry a proof-of-possession.",
                );
            }
            (SignatureSchemeChoice::Ed25519Collected, Some(_), _)
            | (SignatureSchemeChoice::Ed25519Collected, _, Some(_)) => {
                anyhow::bail!(
                    "--config declares signature_scheme = \"ed25519_collected\" but a \
                     --bls-pop-file or --bls-key-file was supplied. Ed25519 chains have no \
                     use for BLS keys; remove the BLS flag.",
                );
            }
            _ => {}
        }
        Some(crate::genesis::derive_chain_id(cons)?)
    } else {
        None
    };

    // Resolve the BLS proof-of-possession from whichever flag was passed
    // (or none, for an Ed25519 chain).
    let bls_pop = if let Some(path) = bls_pop_file {
        Some(read_bls_pop_file(path)?)
    } else if let Some(path) = bls_key_file {
        let chain_id = cfg_chain_id
            .as_ref()
            .expect("--config presence enforced above when --bls-key-file is set");
        Some(derive_bls_pop_from_key_file(path, chain_id)?)
    } else {
        None
    };

    // Local cryptographic fast-fail before distributing the payload.
    // Scoped to the deployment's chain_id (#410).
    if let Some(pop) = &bls_pop {
        let chain_id = cfg_chain_id
            .as_ref()
            .expect("--config presence enforced above when bls_pop is built");
        BlsAggregated::verify_pop(pop, &pop.pubkey, chain_id).map_err(|e| {
            anyhow::anyhow!(
                "BLS PoP failed verification under its embedded pubkey + the chain's chain_id: \
                 {e:?}. Re-mint the PoP for this deployment via --bls-key-file (PoP pre-images \
                 are now chain-bound, #410).",
            )
        })?;
    }

    let cmd = ReconfigCommand {
        adds: vec![ValidatorEntry {
            node_id,
            addr,
            bls_pop,
            weight,
            operator_pubkey,
        }],
        removes: vec![],
        changes: vec![],
        v_eff,
    };
    Ok(cmd.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use tempfile::TempDir;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn addr(p: u16) -> SocketAddr {
        format!("127.0.0.1:{p}").parse().unwrap()
    }

    #[test]
    fn read_bls_pop_file_round_trips_with_valid_pop() {
        // Write a valid `<pubkey_hex>:<pop_hex>` file and confirm the
        // helper reads back a structurally-identical PoP that verifies.
        let mut ikm = [0u8; 32];
        ikm[0] = 0x42;
        let (sk, pk) = BlsAggregated::keygen(&ikm).unwrap();
        let pop = BlsAggregated::sign_pop(&sk, &ChainId([0u8; 32])).unwrap();

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pop.txt");
        std::fs::write(
            &path,
            format!("{}:{}\n", hex::encode(pk), hex::encode(pop.sig)),
        )
        .unwrap();

        let parsed = read_bls_pop_file(&path).expect("must parse");
        assert_eq!(parsed.pubkey, pop.pubkey);
        assert_eq!(parsed.sig, pop.sig);
        BlsAggregated::verify_pop(&parsed, &pk, &ChainId([0u8; 32]))
            .expect("must still verify after round-trip");
    }

    #[test]
    fn read_bls_pop_file_rejects_wrong_lengths() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.txt");
        // Pubkey of wrong length (only 32 bytes).
        std::fs::write(
            &path,
            format!("{}:{}", hex::encode([0u8; 32]), hex::encode([0u8; 96])),
        )
        .unwrap();
        let err = read_bls_pop_file(&path).unwrap_err();
        assert!(err.to_string().contains("48"), "{err}");

        // Sig of wrong length (only 32 bytes).
        std::fs::write(
            &path,
            format!("{}:{}", hex::encode([0u8; 48]), hex::encode([0u8; 32])),
        )
        .unwrap();
        let err = read_bls_pop_file(&path).unwrap_err();
        assert!(err.to_string().contains("96"), "{err}");
    }

    #[test]
    fn read_bls_pop_file_rejects_missing_separator() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nosep.txt");
        std::fs::write(&path, "deadbeef").unwrap();
        let err = read_bls_pop_file(&path).unwrap_err();
        assert!(err.to_string().contains("expected"), "{err}");
    }

    #[test]
    fn derive_bls_pop_from_key_file_produces_verifiable_pop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        // Provision the key file via the standard provider.
        let provider = BlsKeyFile::new(path.clone());
        let id = provider.load_or_init().unwrap();

        let chain_id = ChainId([0x55; 32]);
        let derived = derive_bls_pop_from_key_file(&path, &chain_id).expect("must succeed");
        assert_eq!(derived.pubkey, id.public);
        BlsAggregated::verify_pop(&derived, &id.public, &chain_id)
            .expect("derived PoP must verify under the same chain_id");
        // #410: the same key derives a different (and incompatible)
        // PoP under a different chain_id.
        let other = ChainId([0xCC; 32]);
        assert!(BlsAggregated::verify_pop(&derived, &id.public, &other).is_err());
    }

    fn entry(b: u8, port: u16) -> ValidatorEntry {
        entry_with_weight(b, port, 1)
    }

    fn entry_with_weight(b: u8, port: u16, weight: u64) -> ValidatorEntry {
        ValidatorEntry {
            node_id: nid(b),
            addr: addr(port),
            bls_pop: None,
            weight,
            operator_pubkey: None,
        }
    }

    fn floor_set() -> ValidatorSet {
        // Smallest set the floor allows.
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)])
    }

    fn five_set() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5)])
    }

    // ---------- codec ----------

    #[test]
    fn roundtrips_through_codec() {
        let cmd = ReconfigCommand {
            adds: vec![entry(10, 7010), entry(11, 7011)],
            removes: vec![nid(1)],
            changes: vec![],
            v_eff: View(100),
        };
        let bytes = cmd.encode();
        assert!(ReconfigCommand::is_reconfig_payload(&bytes));
        let decoded = ReconfigCommand::decode(&bytes).unwrap();
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn is_reconfig_payload_false_for_untagged_bytes() {
        assert!(!ReconfigCommand::is_reconfig_payload(b""));
        assert!(!ReconfigCommand::is_reconfig_payload(b"hello"));
        // A near-miss tag (5 of 6 bytes) does not match.
        assert!(!ReconfigCommand::is_reconfig_payload(b"RECFG"));
    }

    #[test]
    fn decode_errors_without_tag() {
        let err = ReconfigCommand::decode(b"not a reconfig").unwrap_err();
        assert!(err.to_string().contains("missing reconfig tag prefix"));
    }

    #[test]
    fn decode_errors_on_truncated_body() {
        let cmd = ReconfigCommand {
            adds: vec![entry(10, 7010)],
            removes: vec![],
            changes: vec![],
            v_eff: View(100),
        };
        let bytes = cmd.encode();
        // Lop off the body's tail. The tag remains intact.
        let truncated = &bytes[..bytes.len() - 1];
        assert!(ReconfigCommand::is_reconfig_payload(truncated));
        let err = ReconfigCommand::decode(truncated).unwrap_err();
        assert!(err.to_string().contains("malformed ReconfigCommand"));
    }

    // ---------- validation: happy paths ----------

    #[test]
    fn add_only_validates() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(
            next,
            vec![
                (nid(1), 1),
                (nid(2), 1),
                (nid(3), 1),
                (nid(4), 1),
                (nid(5), 1),
            ]
        );
    }

    #[test]
    fn remove_only_validates_and_holds_floor() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(5)],
            changes: vec![],
            v_eff: View(10),
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(
            next,
            vec![(nid(1), 1), (nid(2), 1), (nid(3), 1), (nid(4), 1)]
        );
    }

    #[test]
    fn mixed_add_and_remove_validates() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(6, 7006)],
            removes: vec![nid(2)],
            changes: vec![],
            v_eff: View(10),
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(
            next,
            vec![
                (nid(1), 1),
                (nid(3), 1),
                (nid(4), 1),
                (nid(5), 1),
                (nid(6), 1),
            ]
        );
    }

    #[test]
    fn v_eff_at_exact_minimum_is_accepted() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            changes: vec![],
            v_eff: MIN_V_EFF_DELAY, // current_view = 0, min = 0 + 2.
        };
        cmd.validate_against(&cur, 0).unwrap();
    }

    // ---------- validation: rejection paths ----------

    #[test]
    fn v_eff_below_minimum_is_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            changes: vec![],
            v_eff: View(5), // current_view = 4, min v_eff = 4 + 2 = 6.
        };
        let err = cmd.validate_against(&cur, 4).unwrap_err();
        assert!(err.to_string().contains("v_eff 5"), "{err}");
    }

    #[test]
    fn duplicate_in_adds_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005), entry(5, 7006)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("duplicate node_id in adds"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_in_removes_rejected() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(5), nid(5)],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("duplicate node_id in removes"),
            "{err}"
        );
    }

    #[test]
    fn overlap_between_adds_and_removes_rejected() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![nid(5)],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("appears in both adds and removes"),
            "{err}"
        );
    }

    #[test]
    fn add_targeting_existing_member_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(1, 7001)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("add targets existing member"),
            "{err}"
        );
    }

    #[test]
    fn remove_targeting_non_member_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(99)],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("remove targets non-member"),
            "{err}"
        );
    }

    #[test]
    fn floor_violation_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(4)],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("below floor"),
            "expected floor error, got: {err}"
        );
    }

    // ── #251: CLI builder helpers ───────────────────────────────────

    #[test]
    fn build_add_validator_payload_round_trips() {
        let node_id = nid(7);
        let addr: SocketAddr = "127.0.0.1:7007".parse().unwrap();
        let v_eff = View(42);
        let bytes = ReconfigCommand::build_add_validator_payload(node_id, addr, 1, v_eff);
        assert!(ReconfigCommand::is_reconfig_payload(&bytes));
        let decoded = ReconfigCommand::decode(&bytes).unwrap();
        assert_eq!(decoded.adds.len(), 1);
        assert_eq!(decoded.adds[0].node_id, node_id);
        assert_eq!(decoded.adds[0].addr, addr);
        assert_eq!(decoded.adds[0].weight, 1);
        assert!(decoded.removes.is_empty());
        assert!(decoded.changes.is_empty());
        assert_eq!(decoded.v_eff, v_eff);
    }

    #[test]
    fn build_remove_validator_payload_round_trips() {
        let node_id = nid(3);
        let v_eff = View(99);
        let bytes = ReconfigCommand::build_remove_validator_payload(node_id, v_eff);
        assert!(ReconfigCommand::is_reconfig_payload(&bytes));
        let decoded = ReconfigCommand::decode(&bytes).unwrap();
        assert!(decoded.adds.is_empty());
        assert_eq!(decoded.removes, vec![node_id]);
        assert!(decoded.changes.is_empty());
        assert_eq!(decoded.v_eff, v_eff);
    }

    #[test]
    fn build_change_weight_payload_round_trips() {
        let node_id = nid(2);
        let v_eff = View(100);
        let bytes = ReconfigCommand::build_change_weight_payload(node_id, 7, v_eff);
        assert!(ReconfigCommand::is_reconfig_payload(&bytes));
        let decoded = ReconfigCommand::decode(&bytes).unwrap();
        assert!(decoded.adds.is_empty());
        assert!(decoded.removes.is_empty());
        assert_eq!(decoded.changes.len(), 1);
        assert_eq!(decoded.changes[0].node_id, node_id);
        assert_eq!(decoded.changes[0].weight, 7);
        assert_eq!(decoded.v_eff, v_eff);
    }

    #[test]
    fn current_view_overflow_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            changes: vec![],
            v_eff: View::MAX,
        };
        let err = cmd.validate_against(&cur, u64::MAX).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }

    // ---------- BLS proof-of-possession on adds (#291) ----------

    /// Generate a BLS keypair and a valid PoP (bound to `chain_id`) for
    /// embedding in a `ValidatorEntry`. Seed the keygen with the
    /// bottom byte of the validator's NodeId so different fixtures get
    /// different keys.
    fn entry_with_valid_pop(b: u8, port: u16, chain_id: &ChainId) -> ValidatorEntry {
        let mut ikm = [0u8; 32];
        ikm.fill(b);
        let (sk, _pk) = BlsAggregated::keygen(&ikm).unwrap();
        let pop = BlsAggregated::sign_pop(&sk, chain_id).unwrap();
        ValidatorEntry {
            node_id: nid(b),
            addr: addr(port),
            bls_pop: Some(pop),
            weight: 1,
            operator_pubkey: None,
        }
    }

    /// Validate `cmd` on a BLS chain. Helper for the PoP-cryptography
    /// tests below — they all assume the BLS scheme (PoP-on-Ed25519 is
    /// rejected by #334's presence check before the crypto runs).
    fn validate_bls(
        cmd: &ReconfigCommand,
        cur: &ValidatorSet,
    ) -> anyhow::Result<Vec<(NodeId, u64)>> {
        cmd.validate_against_with_delay_and_scheme(
            cur,
            View::ZERO,
            MIN_V_EFF_DELAY,
            SignatureSchemeChoice::BlsAggregated,
            &ChainId::TEST,
        )
    }

    #[test]
    fn add_with_valid_bls_pop_passes_validation() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_valid_pop(5, 7005, &ChainId::TEST)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let next = validate_bls(&cmd, &cur).unwrap();
        assert!(next.iter().any(|(n, _)| *n == nid(5)));
    }

    #[test]
    fn add_with_invalid_bls_pop_signature_is_rejected() {
        let mut entry = entry_with_valid_pop(5, 7005, &ChainId::TEST);
        // Tamper the signature byte 0.
        if let Some(p) = entry.bls_pop.as_mut() {
            p.sig[0] ^= 0xFF;
        }
        let cmd = ReconfigCommand {
            adds: vec![entry],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = validate_bls(&cmd, &floor_set()).unwrap_err();
        assert!(err.to_string().contains("PoP"), "{err}");
    }

    #[test]
    fn add_with_pop_pubkey_swapped_to_other_key_is_rejected() {
        // Forge: take sk_a's PoP but rewrite the embedded pubkey to
        // someone else's. The signature is over pk_a's bytes but the
        // payload now claims pk_b — verification fails at the BLS step.
        let mut a = entry_with_valid_pop(5, 7005, &ChainId::TEST);
        let b = entry_with_valid_pop(6, 7006, &ChainId::TEST);
        if let (Some(pop_a), Some(pop_b)) = (a.bls_pop.as_mut(), b.bls_pop.as_ref()) {
            pop_a.pubkey = pop_b.pubkey;
        }
        let cmd = ReconfigCommand {
            adds: vec![a],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = validate_bls(&cmd, &floor_set()).unwrap_err();
        assert!(err.to_string().contains("PoP"), "{err}");
    }

    /// #410: a PoP minted on chain A must not be accepted as an add
    /// entry on chain B. Cross-chain PoP replay is the dual of the
    /// envelope-level cross-chain replay defense (#324).
    #[test]
    fn add_with_pop_minted_under_different_chain_id_is_rejected() {
        let chain_a = ChainId([0xAA; 32]);
        let chain_b = ChainId([0xBB; 32]);
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_valid_pop(5, 7005, &chain_a)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        // Sanity: under the originating chain, the add is accepted.
        cmd.validate_against_with_delay_and_scheme(
            &cur,
            0,
            MIN_V_EFF_DELAY,
            SignatureSchemeChoice::BlsAggregated,
            &chain_a,
        )
        .expect("PoP minted on chain A must validate on chain A");
        // Cross-chain replay: rejected.
        let err = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::BlsAggregated,
                &chain_b,
            )
            .unwrap_err();
        assert!(err.to_string().contains("PoP"), "{err}");
    }

    #[test]
    fn add_without_pop_passes_validation_on_ed25519_chain() {
        // Default validate_against uses Ed25519Collected. An add with
        // `bls_pop: None` on an Ed25519 chain is the normal case.
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        cmd.validate_against(&cur, 0)
            .expect("entries without PoP must validate on Ed25519 chains");
    }

    // ---------- Scheme-driven PoP enforcement (#334) ----------

    #[test]
    fn bls_chain_rejects_add_without_pop() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::BlsAggregated,
                &ChainId::TEST,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("bls_aggregated") && err.to_string().contains("no bls_pop"),
            "{err}",
        );
    }

    #[test]
    fn bls_chain_accepts_add_with_pop() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_valid_pop(5, 7005, &ChainId::TEST)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let next = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::BlsAggregated,
                &ChainId::TEST,
            )
            .unwrap();
        assert!(next.iter().any(|(n, _)| *n == nid(5)));
    }

    #[test]
    fn ed25519_chain_rejects_add_with_pop() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_valid_pop(5, 7005, &ChainId::TEST)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::Ed25519Collected,
                &ChainId::TEST,
            )
            .unwrap_err();
        assert!(err.to_string().contains("ed25519_collected"), "{err}",);
    }

    // ── #462: weighted reconfig payload ─────────────────────────────────

    #[test]
    fn add_with_explicit_weight_validates_and_returns_weighted_entries() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_weight(5, 7005, 7)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        // Existing 1..=4 keep weight 1, new validator 5 gets weight 7.
        assert_eq!(
            next,
            vec![
                (nid(1), 1),
                (nid(2), 1),
                (nid(3), 1),
                (nid(4), 1),
                (nid(5), 7),
            ]
        );
    }

    #[test]
    fn change_weight_returns_updated_weight() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![],
            changes: vec![WeightChange {
                node_id: nid(2),
                weight: 5,
            }],
            v_eff: View(10),
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(
            next,
            vec![(nid(1), 1), (nid(2), 5), (nid(3), 1), (nid(4), 1)]
        );
    }

    #[test]
    fn add_with_zero_weight_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_weight(5, 7005, 0)],
            removes: vec![],
            changes: vec![],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(err.to_string().contains("weight 0"), "{err}");
    }

    #[test]
    fn change_with_zero_weight_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![],
            changes: vec![WeightChange {
                node_id: nid(1),
                weight: 0,
            }],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(err.to_string().contains("weight 0"), "{err}");
    }

    #[test]
    fn change_targeting_non_member_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![],
            changes: vec![WeightChange {
                node_id: nid(99),
                weight: 3,
            }],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("change targets non-member"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_in_changes_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![],
            changes: vec![
                WeightChange {
                    node_id: nid(1),
                    weight: 2,
                },
                WeightChange {
                    node_id: nid(1),
                    weight: 3,
                },
            ],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("duplicate node_id in changes"),
            "{err}"
        );
    }

    #[test]
    fn change_overlapping_with_removes_rejected() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(5)],
            changes: vec![WeightChange {
                node_id: nid(5),
                weight: 3,
            }],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string()
                .contains("appears in both removes and changes"),
            "{err}"
        );
    }

    #[test]
    fn change_overlapping_with_adds_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_weight(5, 7005, 2)],
            removes: vec![],
            changes: vec![WeightChange {
                node_id: nid(5),
                weight: 7,
            }],
            v_eff: View(10),
        };
        let err = cmd.validate_against(&cur, 0).unwrap_err();
        assert!(
            err.to_string().contains("appears in both adds and changes"),
            "{err}"
        );
    }

    #[test]
    fn mixed_add_remove_change_composes_correctly() {
        // Exercise the disjointness rules with one of each operation
        // in a single command: add nid(6) at weight 3, remove nid(2),
        // bump nid(1)'s weight from 1 to 5.
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_weight(6, 7006, 3)],
            removes: vec![nid(2)],
            changes: vec![WeightChange {
                node_id: nid(1),
                weight: 5,
            }],
            v_eff: View(10),
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(
            next,
            vec![
                (nid(1), 5), // weight bumped via change
                (nid(3), 1),
                (nid(4), 1),
                (nid(5), 1),
                (nid(6), 3), // added at weight 3
            ]
        );
    }
}
