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

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::sig_scheme::{BlsAggregated, BlsKeyError, BlsPop, SignatureSchemeChoice};
use crate::p2p::NodeId;

/// Magic prefix that tags a `Block.commands` entry as a reconfig payload.
pub const RECONFIG_TAG: &[u8; 6] = b"RECFG\0";

/// Minimum size the validator set may shrink to via reconfig.
///
/// Mirrors the `3f + 1 = 4` floor for the smallest `f` operators want to
/// support; #140's "Cannot reduce the validator set below `3f + 1`"
/// criterion. A reconfig whose result would drop the active set below
/// this is rejected pre-commit.
pub const MIN_VALIDATOR_FLOOR: usize = 4;

/// Minimum gap (in views) between the current view at validation time and
/// the proposed effective view.
///
/// With `MIN_V_EFF_DELAY = 2`, a reconfig validated at view `N` must
/// target `v_eff >= N + 2`, giving a newly-added validator a window to
/// finish state sync (#139) before it must vote. #140 open question
/// "Effective-view delay" — value is settled here as the consensus-side
/// minimum; operators may target a larger delay via the CLI but cannot
/// undercut this floor.
pub const MIN_V_EFF_DELAY: u64 = 2;

/// A pubkey + network address pair describing a validator to admit.
///
/// `node_id` is the Ed25519 pubkey used by [`crate::p2p::tls`]; `addr` is
/// the routable socket peers should use to reach this validator. On BLS
/// chains (#143 / #289) `bls_pop` carries the new validator's BLS
/// pubkey paired with a proof-of-possession signature over that pubkey;
/// on Ed25519 chains the field is `None`. The reconfig validator (this
/// module) verifies the PoP whenever it is present, regardless of the
/// chain's scheme — scheme-driven enforcement (PoP *required* on BLS
/// chains) lands together with the rest of the BLS integration in #293.
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
}

/// A typed reconfiguration payload.
///
/// `adds` and `removes` describe the diff against the active set. `v_eff`
/// is the view at which the resulting set becomes authoritative. See
/// [`Self::validate_against`] for the exact pre-commit checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconfigCommand {
    pub adds: Vec<ValidatorEntry>,
    pub removes: Vec<NodeId>,
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

    /// Construct a tagged "add a single validator" payload, suitable
    /// for injection into a mempool. Convenience wrapper used by the
    /// CLI (#251).
    pub fn build_add_validator_payload(node_id: NodeId, addr: SocketAddr, v_eff: View) -> Bytes {
        Self {
            adds: vec![ValidatorEntry {
                node_id,
                addr,
                bls_pop: None,
            }],
            removes: vec![],
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
            v_eff,
        }
        .encode()
    }

    /// Validate this command against the active state at validation time.
    /// Returns the resulting member list (sorted, deduplicated) on
    /// success.
    ///
    /// Checks:
    /// - `v_eff >= current_view + MIN_V_EFF_DELAY`.
    /// - No duplicates within `adds` or within `removes`, and no
    ///   `NodeId` appearing in both.
    /// - Each `removes` entry is currently a member.
    /// - No `adds` entry is currently a member.
    /// - Resulting set size `>= MIN_VALIDATOR_FLOOR`.
    pub fn validate_against(
        &self,
        current_set: &ValidatorSet,
        current_view: View,
    ) -> anyhow::Result<Vec<NodeId>> {
        self.validate_against_with_delay(current_set, current_view, MIN_V_EFF_DELAY)
    }

    /// Same as [`Self::validate_against`] but uses an operator-supplied
    /// minimum delay floor, which must be at least [`MIN_V_EFF_DELAY`].
    /// Wired through [`crate::consensus::node::NodeConfigForConsensus::min_v_eff_delay`]
    /// (#272) so deployments can require a longer "give the new
    /// validator time to state-sync" window than the consensus floor.
    ///
    /// This shim assumes [`SignatureSchemeChoice::Ed25519Collected`].
    /// Use [`Self::validate_against_with_delay_and_scheme`] from any
    /// call site that has the chain's scheme in hand to enforce the
    /// "BLS chain → every `adds` entry needs a PoP" rule.
    pub fn validate_against_with_delay(
        &self,
        current_set: &ValidatorSet,
        current_view: View,
        min_v_eff_delay: View,
    ) -> anyhow::Result<Vec<NodeId>> {
        self.validate_against_with_delay_and_scheme(
            current_set,
            current_view,
            min_v_eff_delay,
            SignatureSchemeChoice::Ed25519Collected,
        )
    }

    /// Scheme-aware variant of [`Self::validate_against_with_delay`].
    /// Adds two checks driven by the chain's signature scheme (#334):
    ///
    /// - BLS chain: every `adds` entry must carry a `bls_pop`. Without
    ///   one, a Byzantine proposer could seat a validator with no
    ///   verifiable BLS pubkey and stall every QC the new committee
    ///   tries to form.
    /// - Ed25519 chain: no `adds` entry may carry a `bls_pop`. A BLS
    ///   PoP on an Ed25519 chain has no semantic meaning; accepting it
    ///   would mask a misconfigured operator who copied a BLS-chain
    ///   payload onto an Ed25519 chain.
    pub fn validate_against_with_delay_and_scheme(
        &self,
        current_set: &ValidatorSet,
        current_view: View,
        min_v_eff_delay: View,
        scheme: SignatureSchemeChoice,
    ) -> anyhow::Result<Vec<NodeId>> {
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

        if let Some(n) = adds_seen.intersection(&removes_seen).next() {
            anyhow::bail!(
                "node_id appears in both adds and removes: {}",
                hex::encode(n)
            );
        }

        for n in &removes_seen {
            if !current_set.contains(n) {
                anyhow::bail!("remove targets non-member: {}", hex::encode(n));
            }
        }

        for n in &adds_seen {
            if current_set.contains(n) {
                anyhow::bail!("add targets existing member: {}", hex::encode(n));
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
                    BlsAggregated::verify_pop(pop, &pop.pubkey).map_err(|e| match e {
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

        let mut next: Vec<NodeId> = current_set.iter().copied().collect();
        next.retain(|n| !removes_seen.contains(n));
        next.extend(adds_seen.iter().copied());
        next.sort_unstable();
        next.dedup();

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

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn addr(p: u16) -> SocketAddr {
        format!("127.0.0.1:{p}").parse().unwrap()
    }

    fn entry(b: u8, port: u16) -> ValidatorEntry {
        ValidatorEntry {
            node_id: nid(b),
            addr: addr(port),
            bls_pop: None,
        }
    }

    fn floor_set() -> ValidatorSet {
        // Smallest set the floor allows.
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
    }

    fn five_set() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4), nid(5)])
    }

    // ---------- codec ----------

    #[test]
    fn roundtrips_through_codec() {
        let cmd = ReconfigCommand {
            adds: vec![entry(10, 7010), entry(11, 7011)],
            removes: vec![nid(1)],
            v_eff: 100,
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
            v_eff: 100,
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
            v_eff: 10,
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(next, vec![nid(1), nid(2), nid(3), nid(4), nid(5)]);
    }

    #[test]
    fn remove_only_validates_and_holds_floor() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(5)],
            v_eff: 10,
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(next, vec![nid(1), nid(2), nid(3), nid(4)]);
    }

    #[test]
    fn mixed_add_and_remove_validates() {
        let cur = five_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(6, 7006)],
            removes: vec![nid(2)],
            v_eff: 10,
        };
        let next = cmd.validate_against(&cur, 0).unwrap();
        assert_eq!(next, vec![nid(1), nid(3), nid(4), nid(5), nid(6)]);
    }

    #[test]
    fn v_eff_at_exact_minimum_is_accepted() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
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
            v_eff: 5, // current_view = 4, min v_eff = 4 + 2 = 6.
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
            v_eff: 10,
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
            v_eff: 10,
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
            v_eff: 10,
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
            v_eff: 10,
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
            v_eff: 10,
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
            v_eff: 10,
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
        let v_eff = 42;
        let bytes = ReconfigCommand::build_add_validator_payload(node_id, addr, v_eff);
        assert!(ReconfigCommand::is_reconfig_payload(&bytes));
        let decoded = ReconfigCommand::decode(&bytes).unwrap();
        assert_eq!(decoded.adds.len(), 1);
        assert_eq!(decoded.adds[0].node_id, node_id);
        assert_eq!(decoded.adds[0].addr, addr);
        assert!(decoded.removes.is_empty());
        assert_eq!(decoded.v_eff, v_eff);
    }

    #[test]
    fn build_remove_validator_payload_round_trips() {
        let node_id = nid(3);
        let v_eff = 99;
        let bytes = ReconfigCommand::build_remove_validator_payload(node_id, v_eff);
        assert!(ReconfigCommand::is_reconfig_payload(&bytes));
        let decoded = ReconfigCommand::decode(&bytes).unwrap();
        assert!(decoded.adds.is_empty());
        assert_eq!(decoded.removes, vec![node_id]);
        assert_eq!(decoded.v_eff, v_eff);
    }

    #[test]
    fn current_view_overflow_rejected() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry(5, 7005)],
            removes: vec![],
            v_eff: u64::MAX,
        };
        let err = cmd.validate_against(&cur, u64::MAX).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }

    // ---------- BLS proof-of-possession on adds (#291) ----------

    /// Generate a BLS keypair and a valid PoP for embedding in a
    /// `ValidatorEntry`. Seed the keygen with the bottom byte of the
    /// validator's NodeId so different fixtures get different keys.
    fn entry_with_valid_pop(b: u8, port: u16) -> ValidatorEntry {
        let mut ikm = [0u8; 32];
        ikm.fill(b);
        let (sk, _pk) = BlsAggregated::keygen(&ikm).unwrap();
        let pop = BlsAggregated::sign_pop(&sk).unwrap();
        ValidatorEntry {
            node_id: nid(b),
            addr: addr(port),
            bls_pop: Some(pop),
        }
    }

    /// Validate `cmd` on a BLS chain. Helper for the PoP-cryptography
    /// tests below — they all assume the BLS scheme (PoP-on-Ed25519 is
    /// rejected by #334's presence check before the crypto runs).
    fn validate_bls(cmd: &ReconfigCommand, cur: &ValidatorSet) -> anyhow::Result<Vec<NodeId>> {
        cmd.validate_against_with_delay_and_scheme(
            cur,
            0,
            MIN_V_EFF_DELAY,
            SignatureSchemeChoice::BlsAggregated,
        )
    }

    #[test]
    fn add_with_valid_bls_pop_passes_validation() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_valid_pop(5, 7005)],
            removes: vec![],
            v_eff: 10,
        };
        let next = validate_bls(&cmd, &cur).unwrap();
        assert!(next.contains(&nid(5)));
    }

    #[test]
    fn add_with_invalid_bls_pop_signature_is_rejected() {
        let mut entry = entry_with_valid_pop(5, 7005);
        // Tamper the signature byte 0.
        if let Some(p) = entry.bls_pop.as_mut() {
            p.sig[0] ^= 0xFF;
        }
        let cmd = ReconfigCommand {
            adds: vec![entry],
            removes: vec![],
            v_eff: 10,
        };
        let err = validate_bls(&cmd, &floor_set()).unwrap_err();
        assert!(err.to_string().contains("PoP"), "{err}");
    }

    #[test]
    fn add_with_pop_pubkey_swapped_to_other_key_is_rejected() {
        // Forge: take sk_a's PoP but rewrite the embedded pubkey to
        // someone else's. The signature is over pk_a's bytes but the
        // payload now claims pk_b — verification fails at the BLS step.
        let mut a = entry_with_valid_pop(5, 7005);
        let b = entry_with_valid_pop(6, 7006);
        if let (Some(pop_a), Some(pop_b)) = (a.bls_pop.as_mut(), b.bls_pop.as_ref()) {
            pop_a.pubkey = pop_b.pubkey;
        }
        let cmd = ReconfigCommand {
            adds: vec![a],
            removes: vec![],
            v_eff: 10,
        };
        let err = validate_bls(&cmd, &floor_set()).unwrap_err();
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
            v_eff: 10,
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
            v_eff: 10,
        };
        let err = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::BlsAggregated,
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
            adds: vec![entry_with_valid_pop(5, 7005)],
            removes: vec![],
            v_eff: 10,
        };
        let next = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::BlsAggregated,
            )
            .unwrap();
        assert!(next.contains(&nid(5)));
    }

    #[test]
    fn ed25519_chain_rejects_add_with_pop() {
        let cur = floor_set();
        let cmd = ReconfigCommand {
            adds: vec![entry_with_valid_pop(5, 7005)],
            removes: vec![],
            v_eff: 10,
        };
        let err = cmd
            .validate_against_with_delay_and_scheme(
                &cur,
                0,
                MIN_V_EFF_DELAY,
                SignatureSchemeChoice::Ed25519Collected,
            )
            .unwrap_err();
        assert!(err.to_string().contains("ed25519_collected"), "{err}",);
    }
}
