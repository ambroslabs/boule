//! HotStuff pacemaker: view synchronization and leader rotation.
//!
//! The pacemaker is the liveness half of HotStuff — it drives view
//! changes, timeouts, and leader rotation. Safety (never committing
//! conflicting blocks) lives in the milestone 7 safety core (#23).
//! Keeping the two modules separate makes each one small enough to test
//! against a mock of the other, which is the central modularity
//! discipline of issue #22.
//!
//! # Purity
//!
//! Everything here is deliberately I/O-free: no `tokio`, no
//! [`crate::clock::Clock`], no network. Inputs are [`Event`]s; outputs
//! are [`Action`]s. The milestone 8 integration layer (#24) translates
//! the returned actions into real effects (arming timers, sending
//! messages). This is what lets the pacemaker run unmodified in the
//! deterministic simulator and in production.
//!
//! # Driving the state machine
//!
//! ```text
//!  ┌───────────────┐  Event  ┌────────────┐  Vec<Action>  ┌───────────────┐
//!  │ safety core + │────────▶│ Pacemaker  │──────────────▶│ integration   │
//!  │   network     │         │ ::step(ev) │               │ layer (#24)   │
//!  └───────────────┘         └────────────┘               └───────────────┘
//! ```
//!
//! # Module layout
//!
//! - [`leader`] (6.A / #86): [`leader::LeaderSelector`] trait + default
//!   [`leader::RoundRobinSelector`].
//! - [`timeout`] (6.B / #87): [`timeout::TimeoutPolicy`] trait +
//!   [`timeout::ExponentialBackoff`].
//! - This module (6.C / #88): the [`Pacemaker`] state machine.

use std::sync::Arc;
use std::time::Duration;

use crate::consensus::View;
use crate::p2p::NodeId;

use self::leader::LeaderSelector;
use self::timeout::TimeoutPolicy;

pub mod leader;
pub mod timeout;

#[cfg(test)]
mod tests;

/// Inputs the pacemaker reacts to.
///
/// All variants carry only the [`View`] the event pertains to — the
/// sender's [`NodeId`] is not relevant to view management (accounting
/// for who sent what is the integration layer's job). This keeps the
/// interface narrow, as issue #22 requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A quorum certificate was observed for `View` — the cluster has
    /// made progress at that view. Advances the pacemaker to `v + 1` and
    /// resets the timeout backoff.
    OnQc(View),
    /// A timeout certificate was observed for `View` — a quorum of
    /// replicas gave up on that view. Same effect as `OnQc`: advance to
    /// `v + 1`, reset backoff.
    OnTimeoutCert(View),
    /// The local view-timer expired for `View` before a QC or proposal
    /// arrived. The pacemaker responds by broadcasting its own timeout
    /// (so a TC can form) and arming a longer timer.
    OnTimeout(View),
    /// A well-formed proposal was observed for `View` — proof the leader
    /// of this view is alive. Re-arms the timer so a slow-but-progressing
    /// leader doesn't get timed out mid-proposal.
    OnProposalReceived(View),
}

/// Why the pacemaker advanced to a new view. Plumbed through on
/// [`Action::AdvanceToView`] so the integration layer can emit a single
/// structured trace per view change distinguishing happy-path (QC)
/// progress from view-change (TC) recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceCause {
    /// A quorum certificate for the prior view was observed; the cluster
    /// made happy-path progress.
    Qc,
    /// A timeout certificate for the prior view was observed; the
    /// cluster abandoned that view via view-change recovery.
    Tc,
}

impl AdvanceCause {
    /// Short, stable tag suitable for use as a structured log value.
    pub fn as_str(self) -> &'static str {
        match self {
            AdvanceCause::Qc => "qc",
            AdvanceCause::Tc => "tc",
        }
    }
}

/// Effects the pacemaker asks the outer driver to perform.
///
/// The state machine never executes these itself; it returns them from
/// [`Pacemaker::step`] and the integration layer is responsible for
/// translating each variant into real side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Record that the local pacemaker has moved to `view`. `cause`
    /// distinguishes happy-path QC progress from TC-driven view-change
    /// recovery — both have the same state-machine effect but look very
    /// different in traces.
    AdvanceToView { view: View, cause: AdvanceCause },
    /// This replica is the leader for `View`; the outer driver should
    /// start building and broadcasting a proposal. Emitted immediately
    /// after [`Action::AdvanceToView`] when applicable.
    BecomeLeader(View),
    /// Broadcast a signed timeout message for `View` so a timeout
    /// certificate can form on the network.
    SendTimeout(View),
    /// Arm (or re-arm) the view-timer to fire after [`Duration`].
    ResetTimer(Duration),
}

/// View-management state machine. Pure — no I/O, no timers, no clock.
///
/// Construct with the local node's [`NodeId`], a [`LeaderSelector`], and
/// a [`TimeoutPolicy`]. Drive it by feeding [`Event`]s to [`step`]; apply
/// the returned [`Action`]s in order.
///
/// [`step`]: Pacemaker::step
pub struct Pacemaker {
    self_id: NodeId,
    current_view: View,
    high_qc_view: View,
    consecutive_failures: u32,
    selector: Arc<dyn LeaderSelector>,
    policy: Arc<dyn TimeoutPolicy>,
}

impl Pacemaker {
    /// Start at view 0 with no failures. The outer driver is responsible
    /// for arming the initial timer (using `policy.timeout(0)`).
    pub fn new(
        self_id: NodeId,
        selector: Arc<dyn LeaderSelector>,
        policy: Arc<dyn TimeoutPolicy>,
    ) -> Self {
        Self {
            self_id,
            current_view: 0,
            high_qc_view: 0,
            consecutive_failures: 0,
            selector,
            policy,
        }
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
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

    /// React to `event` and return the [`Action`]s the outer driver must
    /// perform, in order.
    ///
    /// Stale events (`v < current_view`) are ignored and return an empty
    /// vector — safe by default even when the network replays old
    /// messages. Future-view events are only honored for [`Event::OnQc`]
    /// and [`Event::OnTimeoutCert`] (proof of cluster progress);
    /// future-view [`Event::OnTimeout`] and [`Event::OnProposalReceived`]
    /// are ignored so a malicious replica can't force view jumps with
    /// fabricated local events.
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
                // Proof the leader is alive — keep the current backoff
                // level (a stalled-then-revived view shouldn't pretend
                // the network is fully healthy yet).
                vec![Action::ResetTimer(
                    self.policy.timeout(self.consecutive_failures),
                )]
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
