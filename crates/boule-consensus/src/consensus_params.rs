//! Live-updateable consensus parameters (#542) and the committed-transaction
//! that changes them at a view boundary.
//!
//! Some cluster-wide configuration is fixed at genesis or per-node; some should
//! change without a chain restart, the way Ethereum updates protocol params at
//! a hard-fork boundary. This module carries the **live-updateable** subset
//! ([`ConsensusParams`]) and the system command that updates it
//! ([`ConsensusParamUpdate`]), applied at a `v_eff` view boundary so every
//! replica adopts the new value at the same view — exactly the convergence
//! discipline [`ReconfigCommand`](crate::reconfig::ReconfigCommand) uses for
//! membership.
//!
//! Genesis-immutable params (the signature scheme, #288 — changing it
//! cluster-wide is a hard fork) and purely per-node operational knobs (cache
//! caps) are deliberately **not** here: the former cannot change without a
//! restart, the latter need no cluster-wide agreement.
//!
//! This is the milestone-#4 apply path behind
//! [`ValidatorEffect::ParamUpdate`](crate::replication::application::ValidatorEffect::ParamUpdate):
//! an execution layer that drives a parameter change emits the effect, and the
//! integration layer materialises it into a [`ConsensusParamUpdate`] command.

use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::View;

/// Tag prefix identifying a [`ConsensusParamUpdate`] in `Block.commands`.
pub const PARAM_UPDATE_TAG: &[u8; 6] = b"CPARM\0";

/// Minimum views between the block committing a [`ConsensusParamUpdate`] and
/// its `v_eff`, so the change lands a few views in the future and every replica
/// adopts it at the same boundary (mirrors
/// [`MIN_V_EFF_DELAY`](crate::reconfig::MIN_V_EFF_DELAY) for reconfigs).
pub const MIN_PARAM_V_EFF_DELAY: View = View::new(2);

/// The cluster-wide consensus parameters that may change at runtime via a
/// committed [`ConsensusParamUpdate`]. Each field is "live-updateable" in the
/// taxonomy of #542 (live vs. genesis-immutable vs. per-node-only).
///
/// New live params are added as fields here (and as an `Option` field on
/// [`ConsensusParamUpdate`]); the postcard layout bump is handled the same way
/// reconfig handles its own — an old payload that does not decode under the new
/// layout is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Minimum wall-clock spacing (milliseconds) between proposals a leader
    /// produces (#614). `0` disables pacing. This is the first parameter wired
    /// through the live-update mechanism: it is leader-local, so a transient
    /// disagreement during the activation window is harmless.
    pub min_block_interval_ms: u64,
}

impl ConsensusParams {
    /// The leader-pacing interval as a [`Duration`].
    pub fn min_block_interval(&self) -> Duration {
        Duration::from_millis(self.min_block_interval_ms)
    }
}

/// A typed live-parameter-update payload. Each field is `Some(new value)` to
/// change that parameter and `None` to leave it unchanged; `v_eff` is the view
/// at which the change becomes authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParamUpdate {
    /// New leader-pacing interval (ms), or `None` to leave it unchanged.
    pub min_block_interval_ms: Option<u64>,
    /// The view at and after which the updated params are authoritative.
    pub v_eff: View,
}

impl ConsensusParamUpdate {
    /// Encode as a tagged byte sequence suitable for `Block.commands`.
    pub fn encode(&self) -> Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of ConsensusParamUpdate cannot fail");
        let mut out = Vec::with_capacity(PARAM_UPDATE_TAG.len() + body.len());
        out.extend_from_slice(PARAM_UPDATE_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    /// True iff `bytes` carries the param-update tag prefix.
    pub fn is_param_update_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(PARAM_UPDATE_TAG)
    }

    /// Decode a tagged param-update command. Errors if the tag is absent or the
    /// body is malformed.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(PARAM_UPDATE_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing param-update tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed ConsensusParamUpdate: {e}"))
    }

    /// True iff this update changes nothing (every field is `None`). Such an
    /// update is rejected at validation — it would mint a boundary that is a
    /// no-op yet still consumes the one-pending-at-a-time slot.
    pub fn is_empty(&self) -> bool {
        self.min_block_interval_ms.is_none()
    }

    /// Apply the set fields onto `base`, returning the resulting params.
    pub fn apply_to(&self, base: ConsensusParams) -> ConsensusParams {
        ConsensusParams {
            min_block_interval_ms: self
                .min_block_interval_ms
                .unwrap_or(base.min_block_interval_ms),
        }
    }

    /// Validate the update against the view of the block that carries it: it
    /// must change something and its `v_eff` must sit at least
    /// [`MIN_PARAM_V_EFF_DELAY`] views beyond `block_view`, so all replicas have
    /// committed it before the boundary activates.
    pub fn validate_against(&self, block_view: View) -> anyhow::Result<()> {
        if self.is_empty() {
            anyhow::bail!("param update changes nothing");
        }
        let floor = block_view
            .checked_add(MIN_PARAM_V_EFF_DELAY)
            .ok_or_else(|| anyhow::anyhow!("v_eff floor overflow"))?;
        if self.v_eff < floor {
            anyhow::bail!(
                "v_eff {} is sooner than the floor {} (block view {} + delay {})",
                self.v_eff.0,
                floor.0,
                block_view.0,
                MIN_PARAM_V_EFF_DELAY.0,
            );
        }
        Ok(())
    }
}

/// The schedule of live consensus parameters over views: the genesis params and
/// the committed `v_eff` boundaries that change them. [`Self::at`] resolves the
/// authoritative params for any view, exactly as
/// [`ValidatorSetHistory`](crate::validator_history::ValidatorSetHistory)
/// resolves the active set — the params active at `view` are those of the
/// latest boundary whose `v_eff <= view`, or the genesis params if none has
/// activated.
///
/// Boundaries are inserted in strictly increasing `v_eff` order
/// ([`Self::insert_boundary`]); a committed update whose `v_eff` does not exceed
/// the last boundary is rejected, the one-pending-at-a-time discipline reconfig
/// also enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusParamHistory {
    genesis: ConsensusParams,
    /// `(v_eff, params)` boundaries, sorted by ascending `v_eff`.
    boundaries: Vec<(View, ConsensusParams)>,
}

impl ConsensusParamHistory {
    /// A history with only the genesis params and no boundaries yet.
    pub fn new(genesis: ConsensusParams) -> Self {
        Self {
            genesis,
            boundaries: Vec::new(),
        }
    }

    /// The params authoritative at `view`: the latest boundary with
    /// `v_eff <= view`, or the genesis params if none has activated.
    pub fn at(&self, view: View) -> ConsensusParams {
        self.boundaries
            .iter()
            .rev()
            .find(|(v_eff, _)| view >= *v_eff)
            .map(|(_, p)| *p)
            .unwrap_or(self.genesis)
    }

    /// The params of the most recently scheduled boundary, or genesis if none —
    /// the base a new update applies its changes onto.
    pub fn latest(&self) -> ConsensusParams {
        self.boundaries
            .last()
            .map(|(_, p)| *p)
            .unwrap_or(self.genesis)
    }

    /// Insert a new boundary at `v_eff`. `v_eff` must strictly exceed the last
    /// boundary's (and so cannot be `View::ZERO`); otherwise the boundary is
    /// rejected, preventing two contradictory boundaries from landing.
    pub fn insert_boundary(&mut self, v_eff: View, params: ConsensusParams) -> anyhow::Result<()> {
        if let Some((last, _)) = self.boundaries.last() {
            if v_eff <= *last {
                anyhow::bail!(
                    "param boundary v_eff {} does not exceed the last boundary {}",
                    v_eff.0,
                    last.0,
                );
            }
        } else if v_eff == View::ZERO {
            anyhow::bail!("param boundary v_eff must be greater than genesis (view 0)");
        }
        self.boundaries.push((v_eff, params));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(ms: u64) -> ConsensusParams {
        ConsensusParams {
            min_block_interval_ms: ms,
        }
    }

    #[test]
    fn encode_roundtrips_and_is_tagged() {
        let cmd = ConsensusParamUpdate {
            min_block_interval_ms: Some(250),
            v_eff: View::new(10),
        };
        let bytes = cmd.encode();
        assert!(ConsensusParamUpdate::is_param_update_payload(&bytes));
        assert_eq!(ConsensusParamUpdate::decode(&bytes).unwrap(), cmd);
    }

    #[test]
    fn decode_rejects_untagged_and_truncated() {
        assert!(!ConsensusParamUpdate::is_param_update_payload(b"CPARM"));
        assert!(ConsensusParamUpdate::decode(b"nope").is_err());
        assert!(ConsensusParamUpdate::decode(PARAM_UPDATE_TAG).is_err());
    }

    #[test]
    fn apply_to_overlays_only_set_fields() {
        let base = params(100);
        let unchanged = ConsensusParamUpdate {
            min_block_interval_ms: None,
            v_eff: View::new(5),
        };
        assert_eq!(unchanged.apply_to(base), base);
        let changed = ConsensusParamUpdate {
            min_block_interval_ms: Some(500),
            v_eff: View::new(5),
        };
        assert_eq!(changed.apply_to(base).min_block_interval_ms, 500);
    }

    #[test]
    fn validate_rejects_empty_and_too_soon() {
        let empty = ConsensusParamUpdate {
            min_block_interval_ms: None,
            v_eff: View::new(100),
        };
        assert!(empty.validate_against(View::new(1)).is_err());

        // v_eff must clear block_view + MIN_PARAM_V_EFF_DELAY.
        let too_soon = ConsensusParamUpdate {
            min_block_interval_ms: Some(1),
            v_eff: View::new(2),
        };
        assert!(too_soon.validate_against(View::new(1)).is_err());

        let ok = ConsensusParamUpdate {
            min_block_interval_ms: Some(1),
            v_eff: View::new(3),
        };
        assert!(ok.validate_against(View::new(1)).is_ok());
    }

    #[test]
    fn history_resolves_active_params_per_view() {
        let mut h = ConsensusParamHistory::new(params(100));
        assert_eq!(h.at(View::new(0)), params(100));
        h.insert_boundary(View::new(10), params(200)).unwrap();
        h.insert_boundary(View::new(20), params(300)).unwrap();
        assert_eq!(h.at(View::new(9)), params(100), "before first boundary");
        assert_eq!(h.at(View::new(10)), params(200), "at first boundary");
        assert_eq!(h.at(View::new(19)), params(200), "between boundaries");
        assert_eq!(h.at(View::new(25)), params(300), "after second boundary");
        assert_eq!(h.latest(), params(300));
    }

    #[test]
    fn history_rejects_non_increasing_v_eff() {
        let mut h = ConsensusParamHistory::new(params(100));
        h.insert_boundary(View::new(10), params(200)).unwrap();
        assert!(
            h.insert_boundary(View::new(10), params(300)).is_err(),
            "equal v_eff is rejected",
        );
        assert!(
            h.insert_boundary(View::new(5), params(300)).is_err(),
            "earlier v_eff is rejected",
        );
        assert!(h.insert_boundary(View::new(0), params(0)).is_err());
    }
}
