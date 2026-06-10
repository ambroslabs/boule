use std::sync::Arc;
use std::time::Duration;

use crate::View;
use boule_core::identity::NodeId;

use self::leader::LeaderSelector;
use self::timeout::TimeoutPolicy;

pub mod leader;
pub mod timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonestyThresholdEvidence(());

impl HonestyThresholdEvidence {
    pub fn from_bucket(bucket_size: usize, honesty_threshold: usize) -> Option<Self> {
        (bucket_size >= honesty_threshold).then_some(Self(()))
    }

    pub fn from_bucket_weight(bucket_weight: u128, honesty_threshold: u128) -> Option<Self> {
        (bucket_weight >= honesty_threshold).then_some(Self(()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    OnQc(View),

    OnTimeoutCert(View),

    OnTimeout(View),

    OnProposalReceived(View),

    OnRoundSync {
        view: View,
        evidence: HonestyThresholdEvidence,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceCause {
    Qc,

    Tc,

    RoundSync,
}

impl AdvanceCause {
    pub fn as_str(self) -> &'static str {
        match self {
            AdvanceCause::Qc => "qc",
            AdvanceCause::Tc => "tc",
            AdvanceCause::RoundSync => "round_sync",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    AdvanceToView { view: View, cause: AdvanceCause },

    BecomeLeader(View),

    SendTimeout(View),

    ResetTimer(Duration),
}

pub struct Pacemaker {
    self_id: NodeId,
    current_view: View,
    high_qc_view: View,
    consecutive_failures: u32,
    selector: Arc<dyn LeaderSelector>,
    policy: Arc<dyn TimeoutPolicy>,
}

impl Pacemaker {
    pub fn new(
        self_id: NodeId,
        selector: Arc<dyn LeaderSelector>,
        policy: Arc<dyn TimeoutPolicy>,
    ) -> Self {
        Self {
            self_id,
            current_view: View::ZERO,
            high_qc_view: View::ZERO,
            consecutive_failures: 0,
            selector,
            policy,
        }
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    pub fn set_selector(&mut self, selector: Arc<dyn LeaderSelector>) {
        self.selector = selector;
    }

    pub fn leader_for_view(&self, view: View) -> NodeId {
        self.selector.leader_for_view(view)
    }

    pub fn current_view(&self) -> View {
        self.current_view
    }

    pub fn high_qc_view(&self) -> View {
        self.high_qc_view
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn step(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::OnQc(v) => {
                if v < self.current_view {
                    return Vec::new();
                }
                if v > self.high_qc_view {
                    self.high_qc_view = v;
                }
                self.advance_to(v + 1, AdvanceCause::Qc)
            }
            Event::OnTimeoutCert(v) => {
                if v < self.current_view {
                    return Vec::new();
                }
                self.advance_to(v + 1, AdvanceCause::Tc)
            }
            Event::OnTimeout(v) => {
                if v != self.current_view {
                    return Vec::new();
                }
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                vec![
                    Action::SendTimeout(v),
                    Action::ResetTimer(self.policy.timeout(self.consecutive_failures)),
                ]
            }
            Event::OnProposalReceived(v) => {
                if v != self.current_view {
                    return Vec::new();
                }

                vec![Action::ResetTimer(
                    self.policy.timeout(self.consecutive_failures),
                )]
            }
            Event::OnRoundSync { view: v, evidence } => {
                let _ = evidence;

                if v <= self.current_view {
                    return Vec::new();
                }
                self.advance_to(v, AdvanceCause::RoundSync)
            }
        }
    }

    fn advance_to(&mut self, new_view: View, cause: AdvanceCause) -> Vec<Action> {
        self.current_view = new_view;
        self.consecutive_failures = 0;
        let mut actions = Vec::with_capacity(3);
        actions.push(Action::AdvanceToView {
            view: new_view,
            cause,
        });
        if self.selector.leader_for_view(new_view) == self.self_id {
            actions.push(Action::BecomeLeader(new_view));
        }
        actions.push(Action::ResetTimer(self.policy.timeout(0)));
        actions
    }
}
