//! Pluggable leader selection for the HotStuff pacemaker.
//!
//! A [`LeaderSelector`] maps a [`View`] to the [`NodeId`] that is
//! responsible for proposing in that view. Two implementations live
//! here:
//!
//! - [`RoundRobinSelector`] — rotates through the [`ValidatorSet`] in
//!   sort order. Used by tests and any deployment that explicitly opts
//!   out of stake-weighting.
//! - [`WeightedAccumulatorSelector`] — Tendermint-style stake-weighted
//!   accumulator (#475 / parent #145). Long-run leader frequency
//!   exactly tracks `weight[i] / total_weight`. The production default.
//!
//! VRF-based unpredictable selection (option 3 of #145) lands as a
//! third impl behind the same trait when DoS resistance becomes a
//! concern (open-network deployment).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::consensus::View;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_set::ValidatorSet;
use crate::p2p::NodeId;

/// Maps a [`View`] to the proposer for that view.
///
/// Implementations hold their own reference to the validator history; the
/// trait intentionally does not take it as a parameter, so callers
/// (notably the `Pacemaker` state machine) don't have to thread it
/// through every event.
///
/// # Contract
///
/// - Determinism: `leader_for_view(v)` returns the same [`NodeId`] on
///   every call and every replica. Anything else breaks HotStuff.
/// - Totality: every view yields a leader. A selector that can't decide
///   for some view must either define a fallback or panic at construction.
pub trait LeaderSelector: Send + Sync {
    fn leader_for_view(&self, view: View) -> NodeId;
}

/// Rotates through the [`ValidatorSet`] authoritative at `view`,
/// looked up via [`ValidatorSetHistory::set_at`]:
/// `set_at(view)[view % set_at(view).len()]`.
///
/// On either side of a reconfiguration boundary the rotation runs over
/// the corresponding committee — leaders before `v_eff` come from the
/// pre-boundary set, leaders at or after `v_eff` come from the post-
/// boundary set. Until #272 lands the commit-time application path the
/// history holds only the genesis boundary, so this matches the prior
/// single-set rotation exactly.
#[derive(Debug, Clone)]
pub struct RoundRobinSelector {
    history: Arc<ValidatorSetHistory>,
}

impl RoundRobinSelector {
    /// Build a selector backed by `history`. Panics if any boundary's
    /// set is empty — a pacemaker with no validators cannot make
    /// progress, and silently returning a zero [`NodeId`] would be a
    /// subtle footgun.
    pub fn new(history: Arc<ValidatorSetHistory>) -> Self {
        for (v_eff, set) in history.iter() {
            assert!(
                !set.is_empty(),
                "RoundRobinSelector: boundary at view {v_eff} has no validators"
            );
        }
        Self { history }
    }

    /// Convenience constructor for callers that still hold a single
    /// `Arc<ValidatorSet>` (no reconfiguration history). Equivalent to
    /// `Self::new(Arc::new(ValidatorSetHistory::from_genesis((*set).clone())))`.
    pub fn from_genesis_set(set: Arc<ValidatorSet>) -> Self {
        let history = Arc::new(ValidatorSetHistory::from_genesis((*set).clone()));
        Self::new(history)
    }

    /// Inherent shadow of [`LeaderSelector::leader_for_view`] that
    /// accepts any `Into<View>`. Test code commonly passes a `u64`
    /// literal; this avoids wrapping every call site in `View(..)`.
    /// Inherent impls take precedence over trait impls, so callers
    /// holding a concrete `RoundRobinSelector` get this overload.
    pub fn leader_for_view(&self, view: impl Into<View>) -> NodeId {
        <Self as LeaderSelector>::leader_for_view(self, view.into())
    }
}

impl LeaderSelector for RoundRobinSelector {
    fn leader_for_view(&self, view: View) -> NodeId {
        let vs_at = self.history.set_at(view);
        let vs = vs_at.for_view(view);
        // `view.0 % len as u64` before narrowing to usize so the
        // rotation is identical on 32- and 64-bit platforms.
        let idx = (view.0 % vs.len() as u64) as usize;
        // Round-robin returns the wire-form `NodeId` for the leader;
        // the bytes are the validator's stable id (#328 keeps the
        // bytes reusable across the typestate boundary).
        vs.get(idx)
            .expect("modulo of non-zero length is always in bounds")
            .into_node_id()
    }
}

/// Tendermint-style deterministic stake-weighted accumulator
/// (#475 / parent #145).
///
/// Each validator carries a `priority: i128` that grows by its `weight`
/// each view. The leader is whoever has the highest priority (ties:
/// lowest [`ValidatorSet`] index — i.e. lowest `NodeId`); the chosen
/// validator's priority is then decremented by `total_weight`. Long-run
/// leader frequency is *exactly* `weight[i] / total_weight` (within ±1
/// in any window), with no statistical drift.
///
/// # Reconfiguration boundaries
///
/// Each regime — a span between consecutive boundaries in the
/// [`ValidatorSetHistory`] — runs an independent accumulator starting
/// from priorities = `[0; n]`. Crossing a boundary at `v_eff` does not
/// carry priorities forward: the post-boundary committee starts fresh.
/// This mirrors how [`RoundRobinSelector`] already scopes its rotation
/// to `set_at(view).for_view(view)`. Carrying priorities across
/// committee changes would require a re-mapping that has no clean
/// answer (validator joins/leaves don't preserve indices), so each
/// regime gets its own clock.
///
/// # Caching
///
/// The pacemaker calls `leader_for_view` forward-monotonically in
/// production (view 0, 1, 2, …), so an interior per-regime frontier
/// (`last_view`, `priorities`) keeps the typical cost O(1) per view.
/// Out-of-order or backward queries within a regime recompute from the
/// regime's start at O((view - regime_start) * n) — acceptable for
/// tests, snapshot replay, and the rare catch-up path.
///
/// # Determinism contract
///
/// Calling `leader_for_view(v)` repeatedly in any order yields the same
/// answer: forward advance and backward recompute both run the same
/// algorithm on the same inputs. Two selectors built from the same
/// history are observationally equivalent; the cache is purely a
/// performance optimization.
#[derive(Debug)]
pub struct WeightedAccumulatorSelector {
    history: Arc<ValidatorSetHistory>,
    /// Per-regime forward frontier, keyed by the regime's start view
    /// (`v_eff` of the boundary that opens it). Entries are inserted
    /// lazily on the first lookup that touches a regime.
    state: Mutex<HashMap<View, RegimeFrontier>>,
}

/// Forward-advance state for one regime in [`WeightedAccumulatorSelector`].
#[derive(Debug, Clone)]
struct RegimeFrontier {
    /// The most recent view whose leader has been computed in this
    /// regime. `None` before any computation — the next call advances
    /// from `regime_start`.
    last_view: Option<View>,
    /// Priorities post-decrement at `last_view`, indexed identically to
    /// the regime's [`ValidatorSet`].
    priorities: Vec<i128>,
}

impl WeightedAccumulatorSelector {
    /// Build a selector backed by `history`. Panics if any boundary's
    /// set is empty — same reasoning as [`RoundRobinSelector::new`]:
    /// a pacemaker with no validators cannot make progress, and
    /// silently returning a zero [`NodeId`] would be a subtle footgun.
    pub fn new(history: Arc<ValidatorSetHistory>) -> Self {
        for (v_eff, set) in history.iter() {
            assert!(
                !set.is_empty(),
                "WeightedAccumulatorSelector: boundary at view {v_eff} has no validators"
            );
        }
        Self {
            history,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Convenience constructor mirroring
    /// [`RoundRobinSelector::from_genesis_set`].
    pub fn from_genesis_set(set: Arc<ValidatorSet>) -> Self {
        let history = Arc::new(ValidatorSetHistory::from_genesis((*set).clone()));
        Self::new(history)
    }

    /// Inherent shadow of [`LeaderSelector::leader_for_view`] — same
    /// pattern as [`RoundRobinSelector::leader_for_view`].
    pub fn leader_for_view(&self, view: impl Into<View>) -> NodeId {
        <Self as LeaderSelector>::leader_for_view(self, view.into())
    }

    /// Find the start view of the regime containing `view` — the
    /// `v_eff` of the rightmost boundary at-or-before `view`.
    fn regime_start_for(&self, view: View) -> View {
        let mut start = View::ZERO;
        for (v_eff, _) in self.history.iter() {
            if v_eff <= view {
                start = v_eff;
            } else {
                break;
            }
        }
        start
    }
}

impl LeaderSelector for WeightedAccumulatorSelector {
    fn leader_for_view(&self, view: View) -> NodeId {
        let vs_at = self.history.set_at(view);
        let vs = vs_at.for_view(view);
        let regime_start = self.regime_start_for(view);

        // The fast path: extend the cached frontier forward through
        // `view` and return the leader at `view`. The slow path
        // (backward query) recomputes from regime_start without
        // touching the cached frontier — it would otherwise lose the
        // already-amortized work for future forward queries.
        let mut state = self.state.lock();
        let frontier = state.entry(regime_start).or_insert_with(|| RegimeFrontier {
            last_view: None,
            priorities: vec![0i128; vs.len()],
        });

        let needs_recompute = match frontier.last_view {
            Some(last) => view <= last,
            None => false,
        };

        if needs_recompute {
            let mut tmp = vec![0i128; vs.len()];
            let mut leader_idx = 0usize;
            for v in regime_start.0..=view.0 {
                leader_idx = accumulator_step(&mut tmp, vs);
                let _ = v;
            }
            return vs
                .get(leader_idx)
                .expect("leader index in range")
                .into_node_id();
        }

        let start_view = match frontier.last_view {
            Some(last) => View(last.0 + 1),
            None => regime_start,
        };
        let mut leader_idx = 0usize;
        for _v in start_view.0..=view.0 {
            leader_idx = accumulator_step(&mut frontier.priorities, vs);
        }
        frontier.last_view = Some(view);

        vs.get(leader_idx)
            .expect("leader index in range")
            .into_node_id()
    }
}

/// One step of the Tendermint accumulator over `vs.weights()`. Mutates
/// `priorities` in place: increments each by its weight, picks the
/// highest (ties → lowest index), decrements that priority by
/// `total_weight`. Returns the chosen leader's index.
///
/// `priorities.len()` must equal `vs.len()`.
fn accumulator_step(priorities: &mut [i128], vs: &ValidatorSet) -> usize {
    debug_assert_eq!(priorities.len(), vs.len());
    let weights = vs.weights();
    let total_weight: i128 = vs.total_weight() as i128;

    for (p, &w) in priorities.iter_mut().zip(weights.iter()) {
        *p = p.saturating_add(w as i128);
    }

    // Strict `>` so the *lowest* index wins ties — matches the existing
    // ValidatorSet sort-order convention used everywhere else
    // (RoundRobinSelector, validator-set indexing in QC verification).
    let mut best_idx = 0usize;
    let mut best_priority = priorities[0];
    for (i, &p) in priorities.iter().enumerate().skip(1) {
        if p > best_priority {
            best_idx = i;
            best_priority = p;
        }
    }

    priorities[best_idx] = priorities[best_idx].saturating_sub(total_weight);
    best_idx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> crate::consensus::validator_set::ValidatorId {
        crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn sel(ids: Vec<NodeId>) -> RoundRobinSelector {
        let vids: Vec<_> = ids
            .into_iter()
            .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
            .collect();
        RoundRobinSelector::from_genesis_set(Arc::new(ValidatorSet::new(vids)))
    }

    #[test]
    fn rotation_covers_every_validator_in_sort_order() {
        let s = sel(vec![nid(4), nid(1), nid(3), nid(2)]);
        let leaders: Vec<_> = (0..4).map(|v| s.leader_for_view(v)).collect();
        assert_eq!(leaders, vec![nid(1), nid(2), nid(3), nid(4)]);
    }

    #[test]
    fn deterministic() {
        let s = sel(vec![nid(1), nid(2), nid(3)]);
        assert_eq!(s.leader_for_view(42), s.leader_for_view(42));
        assert_eq!(s.leader_for_view(1_000_000), s.leader_for_view(1_000_000));
    }

    #[test]
    fn wraps_around() {
        let s = sel(vec![nid(1), nid(2), nid(3)]);
        for v in 0..9 {
            assert_eq!(s.leader_for_view(v), s.leader_for_view(v + 3));
        }
    }

    #[test]
    fn large_view_matches_modular_arithmetic() {
        // Past `u32::MAX`, make sure the result still tracks `v % len`.
        // `u32::MAX = 4_294_967_295` is divisible by 3, so
        // `(u32::MAX + 7) % 3 == 1` — the selector should return index 1.
        let s = sel(vec![nid(1), nid(2), nid(3)]);
        let v = (u32::MAX as u64) + 7;
        assert_eq!(s.leader_for_view(v), nid(2));
    }

    #[test]
    #[should_panic(expected = "no validators")]
    fn empty_validator_set_panics() {
        let _ = RoundRobinSelector::from_genesis_set(Arc::new(ValidatorSet::new(vec![])));
    }

    // ── #271: leader rotation across a reconfiguration boundary ──────

    /// With a synthetic boundary at view `v_eff`, the round-robin index
    /// is computed against the set authoritative at each view: leaders
    /// before `v_eff` come from the old set, leaders at or after `v_eff`
    /// come from the new set.
    #[test]
    fn rotation_picks_pre_boundary_set_before_v_eff_and_post_at_or_after() {
        let old_set = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)]);
        let new_set = ValidatorSet::new(vec![vid(10), vid(20), vid(30)]);
        let v_eff: View = View(7);

        let mut history = ValidatorSetHistory::from_genesis(old_set.clone());
        history.insert_boundary(v_eff, new_set.clone()).unwrap();
        let s = RoundRobinSelector::new(Arc::new(history));

        // Pre-boundary leaders are the old set: idx = view % 4.
        for v in [0u64, 1, 2, 3, 4, 5, 6] {
            let expected = old_set.get((v % 4) as usize).unwrap().into_node_id();
            assert_eq!(s.leader_for_view(v), expected, "pre-boundary leader at {v}");
        }
        // At and beyond v_eff the new set rotates: idx = view % 3.
        for v in [7u64, 8, 9, 10, 11] {
            let expected = new_set.get((v % 3) as usize).unwrap().into_node_id();
            assert_eq!(
                s.leader_for_view(v),
                expected,
                "post-boundary leader at {v}",
            );
        }
    }

    /// A boundary that arrives at view 0 (i.e. the genesis "boundary")
    /// continues to drive the rotation even as later boundaries are
    /// stacked on top. Two consecutive boundaries: leaders advance
    /// through three regimes in order.
    #[test]
    fn multiple_boundaries_drive_rotation_through_each_regime() {
        let g = ValidatorSet::new(vec![vid(1), vid(2)]);
        let mid = ValidatorSet::new(vec![vid(3), vid(4), vid(5)]);
        let post = ValidatorSet::new(vec![vid(6), vid(7), vid(8), vid(9)]);

        let mut history = ValidatorSetHistory::from_genesis(g.clone());
        history.insert_boundary(5, mid.clone()).unwrap();
        history.insert_boundary(11, post.clone()).unwrap();
        let s = RoundRobinSelector::new(Arc::new(history));

        // Regime 1: views 0..=4 over the genesis set (size 2).
        assert_eq!(s.leader_for_view(0), g.get(0).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(1), g.get(1).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(4), g.get(0).unwrap().into_node_id());

        // Regime 2: views 5..=10 over the mid set (size 3).
        assert_eq!(s.leader_for_view(5), mid.get(2).unwrap().into_node_id()); // 5 % 3 = 2
        assert_eq!(s.leader_for_view(6), mid.get(0).unwrap().into_node_id()); // 6 % 3 = 0
        assert_eq!(s.leader_for_view(10), mid.get(1).unwrap().into_node_id()); // 10 % 3 = 1

        // Regime 3: views 11.. over the post set (size 4).
        assert_eq!(s.leader_for_view(11), post.get(3).unwrap().into_node_id()); // 11 % 4 = 3
        assert_eq!(s.leader_for_view(12), post.get(0).unwrap().into_node_id()); // 12 % 4 = 0
    }

    // ── #475: WeightedAccumulatorSelector ───────────────────────────

    fn weighted_sel(entries: Vec<(NodeId, u64)>) -> WeightedAccumulatorSelector {
        let weighted: Vec<_> = entries
            .into_iter()
            .map(|(n, w)| {
                (
                    crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(n),
                    w,
                )
            })
            .collect();
        let vs = ValidatorSet::with_weights(weighted).expect("weights nonzero");
        WeightedAccumulatorSelector::from_genesis_set(Arc::new(vs))
    }

    /// With every weight equal to 1, the accumulator's leader sequence
    /// over a fresh regime is exactly `0, 1, 2, …, n-1, 0, 1, …` —
    /// i.e. it collapses byte-for-byte to round-robin starting at the
    /// lowest index. This is the property #475 promises in its
    /// "uniform → round-robin" reduction.
    #[test]
    fn weighted_accumulator_uniform_weights_match_round_robin() {
        let ids = vec![nid(1), nid(2), nid(3), nid(4)];
        let weighted = weighted_sel(ids.iter().map(|n| (*n, 1)).collect());
        let rr = sel(ids.clone());

        // Compare for one full cycle plus wraparound.
        for v in 0..(ids.len() as u64 * 3) {
            assert_eq!(
                weighted.leader_for_view(v),
                rr.leader_for_view(v),
                "uniform weighted should equal round-robin at view {v}",
            );
        }
    }

    /// Hand-checked sequence for weights `[3, 1, 1]` over the first
    /// five views.
    ///
    /// nid(1)/nid(2)/nid(3) sort to indices 0/1/2 with weights 3/1/1
    /// and total_weight = 5. Step-by-step:
    ///
    /// |view|priorities pre-pick| pick   | priorities post-pick |
    /// |----|-------------------|--------|---------------------|
    /// |  0 |  [3, 1, 1]        | idx 0  | [-2, 1, 1]          |
    /// |  1 |  [1, 2, 2]        | idx 1  | [1, -3, 2]          |
    /// |  2 |  [4, -2, 3]       | idx 0  | [-1, -2, 3]         |
    /// |  3 |  [2, -1, 4]       | idx 2  | [2, -1, -1]         |
    /// |  4 |  [5, 0, 0]        | idx 0  | [0, 0, 0]           |
    ///
    /// → leaders = [nid(1), nid(2), nid(1), nid(3), nid(1)] — exactly
    /// 3/5, 1/5, 1/5 of leadership over a 5-view window. After view
    /// 4 priorities reset to [0, 0, 0], so the sequence repeats with
    /// period 5.
    #[test]
    fn weighted_accumulator_three_one_one_hand_checked() {
        let s = weighted_sel(vec![(nid(1), 3), (nid(2), 1), (nid(3), 1)]);
        let leaders: Vec<_> = (0..5).map(|v| s.leader_for_view(v)).collect();
        assert_eq!(
            leaders,
            vec![nid(1), nid(2), nid(1), nid(3), nid(1)],
            "hand-checked Tendermint accumulator sequence for [3, 1, 1]",
        );
        // Period 5 — priorities returned to zero.
        for v in 0..5u64 {
            assert_eq!(s.leader_for_view(v), s.leader_for_view(v + 5));
            assert_eq!(s.leader_for_view(v), s.leader_for_view(v + 10));
        }
    }

    /// Out-of-order queries return the same answer as forward queries —
    /// the selector recomputes from the regime start when asked about
    /// a view earlier than the cached frontier, and that recompute
    /// must be byte-identical to the original forward computation.
    #[test]
    fn weighted_accumulator_out_of_order_queries_are_consistent() {
        let s = weighted_sel(vec![(nid(1), 3), (nid(2), 1), (nid(3), 1)]);

        // Forward sequence (also primes the cache).
        let forward: Vec<_> = (0..10).map(|v| s.leader_for_view(v)).collect();

        // Now ask out of order: earlier views first, then jump
        // forward, then back. Every query must match the forward
        // sequence.
        let s2 = weighted_sel(vec![(nid(1), 3), (nid(2), 1), (nid(3), 1)]);
        let scrambled: Vec<u64> = vec![7, 0, 9, 3, 1, 5, 2, 8, 4, 6];
        for v in scrambled {
            assert_eq!(
                s2.leader_for_view(v),
                forward[v as usize],
                "out-of-order query at view {v} disagrees with forward sequence",
            );
        }
    }

    /// Two selectors built from the same history produce identical
    /// leader sequences regardless of query order — the cache is
    /// purely a perf optimization, not part of the semantics.
    #[test]
    fn weighted_accumulator_two_selectors_agree_under_different_query_orders() {
        let entries = vec![(nid(1), 5), (nid(2), 3), (nid(3), 1), (nid(4), 1)];
        let s_forward = weighted_sel(entries.clone());
        let s_backward = weighted_sel(entries);

        for v in 0..30u64 {
            // s_forward queried in ascending order; s_backward in descending.
            let _ = s_forward.leader_for_view(v);
        }
        for v in (0..30u64).rev() {
            let _ = s_backward.leader_for_view(v);
        }
        for v in 0..30u64 {
            assert_eq!(
                s_forward.leader_for_view(v),
                s_backward.leader_for_view(v),
                "selectors disagree at view {v}",
            );
        }
    }

    /// Crossing a reconfig boundary at `v_eff` resets the accumulator
    /// — the post-boundary regime starts from priorities = `[0; n]`.
    /// The pre-boundary leader sequence is independent of the
    /// post-boundary committee composition.
    #[test]
    fn weighted_accumulator_resets_priorities_at_each_boundary() {
        let pre = ValidatorSet::with_weights(vec![(vid(1), 3), (vid(2), 1), (vid(3), 1)]).unwrap();
        let post =
            ValidatorSet::with_weights(vec![(vid(10), 1), (vid(20), 1), (vid(30), 1)]).unwrap();
        let v_eff: View = View(3);

        let mut history = ValidatorSetHistory::from_genesis(pre.clone());
        history.insert_boundary(v_eff, post.clone()).unwrap();
        let s = WeightedAccumulatorSelector::new(Arc::new(history));

        // Pre-boundary: same as the [3,1,1] hand-checked sequence at
        // views 0..3 — [nid(1), nid(2), nid(1)].
        assert_eq!(s.leader_for_view(0), pre.get(0).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(1), pre.get(1).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(2), pre.get(0).unwrap().into_node_id());

        // Post-boundary: uniform weights → round-robin from index 0.
        // Even though the pre-regime ended mid-cycle (with priorities
        // not at zero), the post regime starts fresh.
        assert_eq!(s.leader_for_view(3), post.get(0).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(4), post.get(1).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(5), post.get(2).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(6), post.get(0).unwrap().into_node_id());
    }

    /// Ties (equal priorities) break in favor of the lowest
    /// [`ValidatorSet`] index — which, since the set is sorted by
    /// `NodeId`, means the lowest `NodeId` wins. Construct a tie
    /// explicitly: at view 0 with uniform weights, priorities are
    /// `[1, 1, …, 1]` and the leader is index 0.
    #[test]
    fn weighted_accumulator_ties_break_to_lowest_index() {
        let s = weighted_sel(vec![(nid(7), 1), (nid(3), 1), (nid(5), 1)]);
        // sorted ids: nid(3), nid(5), nid(7) at indices 0, 1, 2.
        assert_eq!(s.leader_for_view(0), nid(3));
        assert_eq!(s.leader_for_view(1), nid(5));
        assert_eq!(s.leader_for_view(2), nid(7));
    }

    /// Empty validator set rejected at construction — same panic
    /// shape as `RoundRobinSelector` for parity at the call site.
    #[test]
    #[should_panic(expected = "no validators")]
    fn weighted_accumulator_empty_validator_set_panics() {
        let _ = WeightedAccumulatorSelector::from_genesis_set(Arc::new(ValidatorSet::new(vec![])));
    }

    /// Property test: over `N = 1000` views in a regime, validator
    /// `i`'s leadership count is *exactly* `floor(N * w_i / total) ±
    /// 1`. The Tendermint accumulator gives no statistical drift —
    /// this is a hard bound, not a confidence interval.
    ///
    /// 1000 views × 7 validators is ~7k accumulator steps per case;
    /// at 64 cases the test stays well under the 15s budget.
    #[test]
    fn weighted_accumulator_long_run_frequency_tracks_weights_exactly() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(64), |(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=20, 7),
        )| {
            let weights = &weights7[..n];
            let entries: Vec<(NodeId, u64)> = (0..n as u8)
                .zip(weights.iter().copied())
                .map(|(i, w)| (nid(i + 1), w))
                .collect();
            let s = weighted_sel(entries);

            let view_count: u64 = 1000;
            let total_weight: u128 = weights.iter().map(|w| u128::from(*w)).sum();
            let mut counts = vec![0u64; n];
            for v in 0..view_count {
                let leader = s.leader_for_view(v);
                let idx = (leader[0] - 1) as usize;
                counts[idx] += 1;
            }

            for (i, &count) in counts.iter().enumerate() {
                let expected = (u128::from(view_count) * u128::from(weights[i]) / total_weight) as u64;
                let drift = count.abs_diff(expected);
                prop_assert!(
                    drift <= 1,
                    "validator {i} (weight {w}) led {count} times but expected {expected} ± 1 (drift {drift})",
                    w = weights[i],
                );
            }
            // The total leader count must be exactly view_count.
            let sum: u64 = counts.iter().sum();
            prop_assert_eq!(sum, view_count);
        });
    }

    /// Property test: two selectors with the same history return
    /// the same `NodeId` at every view, even when one is queried
    /// strictly forward and the other in random order.
    #[test]
    fn weighted_accumulator_determinism_under_arbitrary_query_orders() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(32), |(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=20, 7),
            mut order in proptest::collection::vec(0u64..200, 200),
        )| {
            let weights = &weights7[..n];
            let entries: Vec<(NodeId, u64)> = (0..n as u8)
                .zip(weights.iter().copied())
                .map(|(i, w)| (nid(i + 1), w))
                .collect();
            let s_forward = weighted_sel(entries.clone());
            let s_random = weighted_sel(entries);

            // Forward sequence — also serves as the reference.
            let reference: Vec<NodeId> = (0..200u64)
                .map(|v| s_forward.leader_for_view(v))
                .collect();
            // Dedup `order` so we still cover every view from 0..200
            // but in scrambled sequence.
            order.sort();
            order.dedup();
            for v in &order {
                let actual = s_random.leader_for_view(*v);
                prop_assert_eq!(actual, reference[*v as usize]);
            }
        });
    }
}
