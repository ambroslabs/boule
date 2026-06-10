use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::View;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_set::ValidatorSet;
use boule_core::identity::NodeId;

pub trait LeaderSelector: Send + Sync {
    fn leader_for_view(&self, view: View) -> NodeId;
}

#[derive(Debug, Clone)]
pub struct RoundRobinSelector {
    history: Arc<ValidatorSetHistory>,
}

impl RoundRobinSelector {
    pub fn new(history: Arc<ValidatorSetHistory>) -> Self {
        for (v_eff, set) in history.iter() {
            assert!(
                !set.is_empty(),
                "RoundRobinSelector: boundary at view {v_eff} has no validators"
            );
        }
        Self { history }
    }

    pub fn from_genesis_set(set: Arc<ValidatorSet>) -> Self {
        let history = Arc::new(ValidatorSetHistory::from_genesis((*set).clone()));
        Self::new(history)
    }

    pub fn leader_for_view(&self, view: impl Into<View>) -> NodeId {
        <Self as LeaderSelector>::leader_for_view(self, view.into())
    }
}

impl LeaderSelector for RoundRobinSelector {
    fn leader_for_view(&self, view: View) -> NodeId {
        let vs_at = self.history.set_at(view);
        let vs = vs_at.for_view(view);

        let idx = (view.0 % vs.len() as u64) as usize;

        vs.get(idx)
            .expect("modulo of non-zero length is always in bounds")
            .into_node_id()
    }
}

#[derive(Debug)]
pub struct WeightedAccumulatorSelector {
    history: Arc<ValidatorSetHistory>,

    state: Mutex<HashMap<View, RegimeFrontier>>,
}

#[derive(Debug, Clone)]
struct RegimeFrontier {
    last_view: Option<View>,

    priorities: Vec<i128>,
}

impl WeightedAccumulatorSelector {
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

    pub fn from_genesis_set(set: Arc<ValidatorSet>) -> Self {
        let history = Arc::new(ValidatorSetHistory::from_genesis((*set).clone()));
        Self::new(history)
    }

    pub fn leader_for_view(&self, view: impl Into<View>) -> NodeId {
        <Self as LeaderSelector>::leader_for_view(self, view.into())
    }

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

fn accumulator_step(priorities: &mut [i128], vs: &ValidatorSet) -> usize {
    debug_assert_eq!(priorities.len(), vs.len());
    let weights = vs.weights();
    let total_weight: i128 = vs.total_weight() as i128;

    for (p, &w) in priorities.iter_mut().zip(weights.iter()) {
        *p = p.saturating_add(w as i128);
    }

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
