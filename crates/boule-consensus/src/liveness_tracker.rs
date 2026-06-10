use std::collections::{BTreeMap, VecDeque};

use crate::validator_set::ValidatorId;

pub const LIVENESS_WINDOW_VIEWS: usize = 128;

pub const LIVENESS_FLOOR_PERMILLE: u64 = 500;

pub const BYZANTINE_PARTICIPATION_FLOOR_PERMILLE: u64 = 666;

pub const LIVENESS_MIN_SAMPLE_VIEWS: u32 = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Counts {
    member_views: u32,

    credited_views: u32,
}

#[derive(Debug, Clone)]
struct Observation {
    members: Vec<ValidatorId>,
    credited: Vec<ValidatorId>,
}

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
    pub fn with_window(window: usize) -> Self {
        Self {
            window: window.max(1),
            observations: VecDeque::new(),
            counts: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, members: &[ValidatorId], credited: &[ValidatorId]) {
        for m in members {
            self.counts.entry(*m).or_default().member_views += 1;
        }
        let credited: Vec<ValidatorId> = credited
            .iter()
            .filter(|c| members.contains(c))
            .copied()
            .collect();
        for c in &credited {
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

            self.counts
                .retain(|_, c| c.member_views > 0 || c.credited_views > 0);
        }
    }

    pub fn participation_permille(&self, validator: &ValidatorId) -> Option<u64> {
        let c = self.counts.get(validator)?;
        if c.member_views == 0 {
            return None;
        }
        Some(u64::from(c.credited_views) * 1000 / u64::from(c.member_views))
    }

    pub fn is_delinquent(&self, validator: &ValidatorId) -> bool {
        match self.counts.get(validator) {
            Some(c) if c.member_views >= LIVENESS_MIN_SAMPLE_VIEWS => {
                u64::from(c.credited_views) * 1000 / u64::from(c.member_views)
                    < LIVENESS_FLOOR_PERMILLE
            }
            _ => false,
        }
    }

    pub fn delinquents(&self) -> Vec<ValidatorId> {
        self.counts
            .keys()
            .filter(|v| self.is_delinquent(v))
            .copied()
            .collect()
    }

    pub fn cluster_participation_permille(&self) -> Option<u64> {
        let (credited, member): (u64, u64) = self.counts.values().fold((0, 0), |(cr, mv), c| {
            (
                cr + u64::from(c.credited_views),
                mv + u64::from(c.member_views),
            )
        });
        (member > 0).then(|| credited * 1000 / member)
    }

    pub fn cluster_below_byzantine_floor(&self) -> bool {
        self.observations.len() >= self.window
            && self
                .cluster_participation_permille()
                .is_some_and(|p| p < BYZANTINE_PARTICIPATION_FLOOR_PERMILLE)
    }
}
