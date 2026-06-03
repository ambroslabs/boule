//! Liveness-fault detection (#540) — a rolling, per-validator participation
//! tracker that flags validators which have effectively stopped voting.
//!
//! # What "participation" means here
//!
//! A leader seals the next view's QC as soon as it has enough vote weight,
//! so a slow-but-honest validator's vote can arrive *after* the QC is
//! formed and never get folded in. "Credited" therefore means: the
//! validator's signature is present in the QC that committed a view. This
//! tracker observes, per committed view, the set of validators that were
//! members and the subset whose votes were credited, and maintains each
//! validator's `credited / member` ratio over a rolling window.
//!
//! # The Byzantine-censorship floor (why the threshold is low)
//!
//! With `n = 3f + 1`, up to `f` Byzantine leaders can censor an honest
//! validator — sealing the QC before its vote lands, or simply not folding
//! it — on as much as `f/n ≈ 1/3` of views. So an honest validator targeted
//! by the Byzantine quorum can have its *credited* participation dip to
//! ≈ `1 − f/n ≈ 66%` through no fault of its own. The delinquency floor
//! ([`LIVENESS_FLOOR_PERMILLE`]) sits **well below** that 66% so a
//! censored-but-honest validator is never flagged; only near-total silence
//! trips it. Sustained *cluster-wide* participation below ~66% is itself a
//! meta-signal that the censorship fraction has grown past the Byzantine
//! bound (> f bad actors or a coordinated network fault) — surfaced via
//! [`LivenessTracker::cluster_participation_permille`].
//!
//! # Scope (#540)
//!
//! This is the **detection + threshold-calibration** half. It does not
//! slash or ban — enforcement (via the #457 tokenless membership ban /
//! `StakeSource`) is a follow-up that consumes [`LivenessTracker::delinquents`].
//! All arithmetic is integer permille so the verdict is deterministic
//! across replicas.

use std::collections::{BTreeMap, VecDeque};

use crate::validator_set::ValidatorId;

/// Number of most-recent committed views the tracker scores over.
pub const LIVENESS_WINDOW_VIEWS: usize = 128;

/// Credited-participation floor, in permille (parts per thousand). A
/// validator whose in-window ratio falls below this — having been a member
/// long enough to judge ([`LIVENESS_MIN_SAMPLE_VIEWS`]) — is delinquent.
///
/// 500 ‰ = 50%, deliberately well under the ≈66% honest floor a validator
/// can be pushed to by maximal Byzantine-leader censorship (see the module
/// docs), so honest-but-censored validators are never flagged.
pub const LIVENESS_FLOOR_PERMILLE: u64 = 500;

/// The honest-participation floor under maximal Byzantine censorship, in
/// permille — `(1 − f/n)` for `n = 3f + 1` approaches `666‰`. Sustained
/// cluster-wide participation below this means censorship has exceeded the
/// Byzantine bound; surfaced as a meta-signal, never used to flag an
/// individual.
pub const BYZANTINE_PARTICIPATION_FLOOR_PERMILLE: u64 = 666;

/// Minimum in-window member-views before a validator's ratio is judged —
/// avoids flagging a freshly-added validator on a handful of samples.
pub const LIVENESS_MIN_SAMPLE_VIEWS: u32 = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Counts {
    /// Views in the window where the validator was a member.
    member_views: u32,
    /// Views in the window where the validator's vote was credited.
    credited_views: u32,
}

/// One committed view's participation snapshot.
#[derive(Debug, Clone)]
struct Observation {
    members: Vec<ValidatorId>,
    credited: Vec<ValidatorId>,
}

/// Rolling per-validator participation tracker (#540). Maintains exact
/// in-window counts incrementally as observations are pushed and the oldest
/// evicted, so queries are O(1)–O(set) rather than O(window).
#[derive(Debug, Clone)]
pub struct LivenessTracker {
    window: usize,
    observations: VecDeque<Observation>,
    counts: BTreeMap<ValidatorId, Counts>,
}

impl Default for LivenessTracker {
    fn default() -> Self {
        Self::with_window(LIVENESS_WINDOW_VIEWS)
    }
}

impl LivenessTracker {
    /// A tracker scoring over the most-recent `window` committed views.
    pub fn with_window(window: usize) -> Self {
        Self {
            window: window.max(1),
            observations: VecDeque::new(),
            counts: BTreeMap::new(),
        }
    }

    /// Record one committed view: `members` were in the validator set, and
    /// `credited` (a subset of `members`) had their votes folded into the
    /// committing QC. Evicts the oldest observation once the window is full.
    ///
    /// `credited` entries that are not in `members` are ignored (defensive:
    /// a QC signer always indexes the set it was formed under).
    pub fn observe(&mut self, members: &[ValidatorId], credited: &[ValidatorId]) {
        // Apply the new observation to the running counts.
        for m in members {
            self.counts.entry(*m).or_default().member_views += 1;
        }
        let credited: Vec<ValidatorId> = credited
            .iter()
            .filter(|c| members.contains(c))
            .copied()
            .collect();
        for c in &credited {
            // Members were just inserted above, so the entry exists.
            self.counts.entry(*c).or_default().credited_views += 1;
        }
        self.observations.push_back(Observation {
            members: members.to_vec(),
            credited,
        });

        while self.observations.len() > self.window {
            let old = self
                .observations
                .pop_front()
                .expect("len > window > 0 implies a front");
            for m in &old.members {
                if let Some(c) = self.counts.get_mut(m) {
                    c.member_views = c.member_views.saturating_sub(1);
                }
            }
            for cr in &old.credited {
                if let Some(c) = self.counts.get_mut(cr) {
                    c.credited_views = c.credited_views.saturating_sub(1);
                }
            }
            // Drop validators that have aged entirely out of the window.
            self.counts
                .retain(|_, c| c.member_views > 0 || c.credited_views > 0);
        }
    }

    /// The validator's in-window credited-participation ratio in permille,
    /// or `None` if it has no member-views in the window.
    pub fn participation_permille(&self, validator: &ValidatorId) -> Option<u64> {
        let c = self.counts.get(validator)?;
        if c.member_views == 0 {
            return None;
        }
        Some(u64::from(c.credited_views) * 1000 / u64::from(c.member_views))
    }

    /// Whether `validator` is delinquent: a member for at least
    /// [`LIVENESS_MIN_SAMPLE_VIEWS`] in-window views, with participation
    /// below [`LIVENESS_FLOOR_PERMILLE`]. Below the sample floor (e.g. a
    /// freshly-added validator) it is never delinquent.
    pub fn is_delinquent(&self, validator: &ValidatorId) -> bool {
        match self.counts.get(validator) {
            Some(c) if c.member_views >= LIVENESS_MIN_SAMPLE_VIEWS => {
                u64::from(c.credited_views) * 1000 / u64::from(c.member_views)
                    < LIVENESS_FLOOR_PERMILLE
            }
            _ => false,
        }
    }

    /// Every currently-delinquent validator (sorted, the `BTreeMap` order).
    pub fn delinquents(&self) -> Vec<ValidatorId> {
        self.counts
            .keys()
            .filter(|v| self.is_delinquent(v))
            .copied()
            .collect()
    }

    /// Cluster-wide mean credited participation over the window, in
    /// permille: total credited-views / total member-views across all
    /// validators. `None` until any member-views exist.
    ///
    /// Below [`BYZANTINE_PARTICIPATION_FLOOR_PERMILLE`] this is a meta-signal
    /// that censorship has exceeded the Byzantine bound (a node should
    /// surface it, not act on individuals).
    pub fn cluster_participation_permille(&self) -> Option<u64> {
        let (credited, member): (u64, u64) = self.counts.values().fold((0, 0), |(cr, mv), c| {
            (
                cr + u64::from(c.credited_views),
                mv + u64::from(c.member_views),
            )
        });
        (member > 0).then(|| credited * 1000 / member)
    }

    /// Whether the cluster-wide mean participation has fallen below the
    /// Byzantine-censorship floor — evidence of more than `f` faulty/censoring
    /// actors or a coordinated network fault. Requires at least one full
    /// window of observations so it isn't tripped during warm-up.
    pub fn cluster_below_byzantine_floor(&self) -> bool {
        self.observations.len() >= self.window
            && self
                .cluster_participation_permille()
                .is_some_and(|p| p < BYZANTINE_PARTICIPATION_FLOOR_PERMILLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey([b; 32])
    }

    /// Observe `view_count` views where `members` are all present and
    /// `credited` (resolved each view) is supplied by `credited_fn(view)`.
    fn run(
        tracker: &mut LivenessTracker,
        members: &[ValidatorId],
        view_count: usize,
        mut credited_fn: impl FnMut(usize) -> Vec<ValidatorId>,
    ) {
        for v in 0..view_count {
            let credited = credited_fn(v);
            tracker.observe(members, &credited);
        }
    }

    #[test]
    fn full_participation_is_not_delinquent() {
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let mut t = LivenessTracker::with_window(128);
        run(&mut t, &members, 100, |_| members.to_vec());
        for m in &members {
            assert_eq!(t.participation_permille(m), Some(1000));
            assert!(!t.is_delinquent(m));
        }
        assert!(t.delinquents().is_empty());
    }

    #[test]
    fn a_silent_validator_is_delinquent() {
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let silent = vid(4);
        let mut t = LivenessTracker::with_window(128);
        // vid(4) never appears in the credited set.
        run(&mut t, &members, 100, |_| {
            members.iter().copied().filter(|m| *m != silent).collect()
        });
        assert_eq!(t.participation_permille(&silent), Some(0));
        assert!(t.is_delinquent(&silent));
        assert_eq!(t.delinquents(), vec![silent]);
        // The others are at 100%.
        for m in members.iter().filter(|m| **m != silent) {
            assert!(!t.is_delinquent(m));
        }
    }

    #[test]
    fn an_honest_but_censored_validator_above_the_floor_is_not_flagged() {
        // A validator censored on ~30% of views (credited 70%) sits above
        // the 50% floor — it must never be flagged, even though it is below
        // 100%. This is the load-bearing anti-weaponization property.
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let censored = vid(2);
        let mut t = LivenessTracker::with_window(100);
        run(&mut t, &members, 100, |v| {
            if v % 10 < 3 {
                // 30% of views: censored validator's vote not credited.
                members.iter().copied().filter(|m| *m != censored).collect()
            } else {
                members.to_vec()
            }
        });
        assert_eq!(t.participation_permille(&censored), Some(700));
        assert!(!t.is_delinquent(&censored), "70% must clear the 50% floor");
    }

    #[test]
    fn below_min_sample_is_never_delinquent() {
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let silent = vid(4);
        let mut t = LivenessTracker::with_window(128);
        // Fewer than LIVENESS_MIN_SAMPLE_VIEWS observations, silent throughout.
        run(
            &mut t,
            &members,
            (LIVENESS_MIN_SAMPLE_VIEWS - 1) as usize,
            |_| members.iter().copied().filter(|m| *m != silent).collect(),
        );
        assert_eq!(t.participation_permille(&silent), Some(0));
        assert!(
            !t.is_delinquent(&silent),
            "insufficient sample must not flag"
        );
    }

    #[test]
    fn window_slides_so_recovery_clears_delinquency() {
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let recovered = vid(3);
        let mut t = LivenessTracker::with_window(64);
        // First fill the window with the validator silent → delinquent.
        run(&mut t, &members, 64, |_| {
            members
                .iter()
                .copied()
                .filter(|m| *m != recovered)
                .collect()
        });
        assert!(t.is_delinquent(&recovered));
        // Then a full window of full participation evicts the silence.
        run(&mut t, &members, 64, |_| members.to_vec());
        assert_eq!(t.participation_permille(&recovered), Some(1000));
        assert!(!t.is_delinquent(&recovered));
    }

    #[test]
    fn a_freshly_added_validator_only_counts_from_when_it_joins() {
        let base = [vid(1), vid(2), vid(3), vid(4)];
        let joiner = vid(5);
        let mut t = LivenessTracker::with_window(256);
        // 100 views without the joiner.
        run(&mut t, &base, 100, |_| base.to_vec());
        assert_eq!(t.participation_permille(&joiner), None);
        // Then 40 views with the joiner present + voting.
        let with_joiner: Vec<ValidatorId> = base.iter().copied().chain([joiner]).collect();
        run(&mut t, &with_joiner, 40, |_| with_joiner.clone());
        assert_eq!(t.participation_permille(&joiner), Some(1000));
        assert!(!t.is_delinquent(&joiner));
    }

    #[test]
    fn cluster_floor_signal_trips_only_under_widespread_censorship() {
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let mut healthy = LivenessTracker::with_window(64);
        run(&mut healthy, &members, 64, |_| members.to_vec());
        assert_eq!(healthy.cluster_participation_permille(), Some(1000));
        assert!(!healthy.cluster_below_byzantine_floor());

        // Half the votes cluster-wide are dropped each view → 500‰ < 666‰.
        let mut sick = LivenessTracker::with_window(64);
        run(&mut sick, &members, 64, |_| vec![members[0], members[1]]);
        assert_eq!(sick.cluster_participation_permille(), Some(500));
        assert!(sick.cluster_below_byzantine_floor());
    }

    #[test]
    fn cluster_floor_signal_waits_for_a_full_window() {
        let members = [vid(1), vid(2), vid(3), vid(4)];
        let mut t = LivenessTracker::with_window(64);
        // Only 10 views, all silent-ish — but below a full window, no signal.
        run(&mut t, &members, 10, |_| vec![members[0]]);
        assert!(!t.cluster_below_byzantine_floor());
    }
}
