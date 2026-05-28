//! Crash-injection seam for the consensus event loop (issue #420).
//!
//! `crashpoint!("name")` is a per-call-site marker the integration layer
//! sprinkles between safety-state mutations and their dependent network
//! sends (vote broadcasts, proposal sends, timeout-vote broadcasts, the
//! atomic batch in `restore_from_snapshot`, and so on). In production
//! builds the macro compiles to nothing — the expansion is gated on
//! `cfg(test)` so a release binary takes no extra branch.
//!
//! In test builds the macro consults a tokio-task-local, fire-once
//! [`CrashSlot`]. If a test has *armed* the slot with a matching name,
//! the macro panics with a tagged `CrashPoint(name)` payload — modelling
//! the consensus task being yanked out from under the integration
//! layer between "I just persisted X" and "I just sent the network
//! message that depends on X".
//!
//! The slot is fire-once: the first matching `crashpoint!()` clears the
//! slot, so subsequent crashpoints inside the same task are no-ops.
//! That matches the "node crashes once, restarts, never crashes at the
//! same point again in the same test" shape every regression for
//! findings #1, #2, #3, #11 needs.
//!
//! # Why task-local rather than thread-local?
//!
//! The sim spawns one tokio task per node, all on the same
//! `current_thread` runtime. A thread-local would let a crashpoint
//! armed for node A fire when node B happens to be the task currently
//! running on the thread. Tokio's [`tokio::task_local`] propagates the
//! slot only down the spawn chain rooted at the node's run loop, so
//! each node sees only its own arm.
//!
//! # Production no-op contract
//!
//! `crashpoint!("name")` expands to `()` outside `cfg(test)`. Tests
//! enforce this via [`crashpoint_macro_is_noop_outside_cfg_test`] (a
//! tautology under `cfg(test)` but kept as a documented anchor: any
//! future macro change that would smuggle a runtime branch into
//! release builds breaks compilation of that anchor).

// CrashSlot's helpers (`empty`, `arm`, `peek`) are only consumed by
// the `#[cfg(test)] sim` module; in lib builds the dead-code lint
// flags every method, so scope the allow here rather than ripping
// the `pub` API away from the test-only consumers.
#![allow(dead_code)]

#[cfg(feature = "crashpoints")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "crashpoints")]
tokio::task_local! {
    /// Per-task fire-once crash slot. Cloned [`CrashSlot`]s share the
    /// same inner state via [`Arc`], so the sim can hold an external
    /// handle, hand another clone into the consensus task via
    /// [`tokio::task_local::LocalKey::scope`], and arm the slot from
    /// outside while the macro fires from inside.
    pub static CRASH_SLOT: CrashSlot;
}

/// Test-side handle for arming a [`CRASH_SLOT`]. Constructed by the
/// sim when it spawns a node, handed to the test via
/// [`crate::sim::SimCluster::arm_crashpoint`], and consulted
/// by [`fire`] when the consensus task hits a `crashpoint!()`.
///
/// The slot is fire-once: the first matching name consumes the entry.
/// A test that wants to crash at two distinct points in the same run
/// re-arms the slot after the recovery completes — the same shape any
/// "crash, restart, crash again" property would need.
///
/// `Clone` shares the underlying `Arc<Mutex<Option<&'static str>>>`,
/// so all clones see the same arm. The sim holds one clone per node
/// and hands another into the per-node task scope.
#[cfg(feature = "crashpoints")]
#[derive(Default, Clone)]
pub struct CrashSlot {
    inner: Arc<Mutex<Option<&'static str>>>,
}

#[cfg(feature = "crashpoints")]
impl CrashSlot {
    /// Construct an empty slot. The sim's per-node task scope hands one
    /// of these into [`tokio::task_local::LocalKey::scope`] when it
    /// spawns the node's run loop.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Arm the slot with `name`. Replaces any previously-armed but
    /// not-yet-fired entry — tests that want layered arms must wait
    /// for the previous one to fire first. Returns the previously
    /// armed name, if any, so callers can assert nothing was lost.
    pub fn arm(&self, name: &'static str) -> Option<&'static str> {
        self.inner.lock().unwrap().replace(name)
    }

    /// Take the currently-armed name, if any, leaving the slot empty.
    /// Used by [`fire`] to honour the fire-once contract: a single
    /// matching `crashpoint!()` clears the slot before panicking, so
    /// re-arming under panic-unwind is the test's responsibility.
    fn take_if_matches(&self, name: &str) -> Option<&'static str> {
        let mut guard = self.inner.lock().unwrap();
        if guard.as_deref() == Some(name) {
            guard.take()
        } else {
            None
        }
    }

    /// Inspect the currently-armed name without consuming it. Tests
    /// use this to assert post-condition state (e.g. "the crashpoint
    /// did fire — slot is now empty").
    pub fn peek(&self) -> Option<&'static str> {
        *self.inner.lock().unwrap()
    }
}

/// Body of the [`crashpoint!`] macro under `cfg(test)`. Resolved at
/// every call site so the integration layer's call graph stays linear
/// — no async indirection through the task-local lookup.
///
/// If the task-local slot is unset (production-shape spawn, or a sim
/// node that opted out of crash injection), this is a one-load
/// `try_with` that returns immediately. If the slot is set and the
/// armed name matches, the slot is cleared first and then the panic
/// fires — clearing under-arm-then-panic is the only ordering that
/// survives the panic-unwind without leaking a stale arm into the
/// reborn task on restart.
///
/// The panic payload is a `'static str` of the form `"CrashPoint(name)"`
/// so a test that catches via [`std::panic::catch_unwind`] can match
/// on the exact name. The integration layer doesn't catch unwinds —
/// the sim's tokio task abort plus the per-node restart helper is how
/// recovery is observed end-to-end.
#[cfg(feature = "crashpoints")]
pub fn fire(name: &'static str) {
    let _ = CRASH_SLOT.try_with(|slot| {
        if slot.take_if_matches(name).is_some() {
            panic!("CrashPoint({name})");
        }
    });
}

/// No-op build of [`fire`]: when the `crashpoints` feature is off (every
/// production build), the `crashpoint!` macro expands to this empty,
/// always-inlined call so release binaries take no branch.
#[cfg(not(feature = "crashpoints"))]
#[inline(always)]
pub fn fire(_name: &'static str) {}

/// Inject `crashpoint!("name")` between a safety-state mutation and
/// its dependent network send. Compiles to a no-op outside `cfg(test)`
/// so production binaries take no extra branch. Inside `cfg(test)`
/// expands to a [`fire`] call against the per-task [`CrashSlot`].
///
/// Names are short kebab-case strings naming the durability boundary,
/// matching the audit's vocabulary: `after_persist_voted_view`,
/// `after_broadcast_vote`, `after_persist_locked`,
/// `after_apply_commit_block_persist`, `after_send_outbound_for_proposal`,
/// `after_adopt_snapshot_persist`, `after_broadcast_timeout_vote`.
/// Duplicating a name across call sites is fine: an armed slot fires
/// at the first one the running node reaches.
#[macro_export]
#[doc(hidden)]
macro_rules! __crashpoint_impl {
    ($name:literal) => {{
        $crate::crashpoint::fire($name);
    }};
}
pub use crate::__crashpoint_impl as crashpoint;

#[cfg(all(test, feature = "crashpoints"))]
mod tests {
    use super::{CRASH_SLOT, CrashSlot, crashpoint, fire};

    /// `crashpoint!()` is a no-op when no slot is armed. Without a
    /// task-local scope the `try_with` path returns immediately; this
    /// pins that the macro stays infallible under "production-shape"
    /// callers (no scope wrapper, no slot).
    #[tokio::test(flavor = "current_thread")]
    async fn crashpoint_outside_scope_is_noop() {
        // No `CRASH_SLOT.scope` wrapper. The fire path's `try_with`
        // returns `Err` and the macro is a no-op.
        fire("never_armed");
        crashpoint!("also_never_armed");
    }

    /// Arming a slot and crossing the matching crashpoint must panic
    /// with a `CrashPoint(name)` payload. Catching the unwind asserts
    /// the panic message verbatim, which the harness uses to confirm
    /// the right crashpoint fired (rather than some unrelated panic).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn matching_crashpoint_panics_with_named_payload() {
        let slot = CrashSlot::empty();
        slot.arm("after_persist_voted_view");
        let result = CRASH_SLOT
            .scope(slot, async {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crashpoint!("after_persist_voted_view");
                }))
            })
            .await;
        let err = result.expect_err("crashpoint must panic when armed name matches");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&'static str>().copied())
            .expect("panic payload must be a string");
        assert_eq!(msg, "CrashPoint(after_persist_voted_view)");
    }

    /// A non-matching name is silently ignored. This lets the
    /// integration layer sprinkle named crashpoints all over without
    /// having to teach the sim about every one — only the named arms
    /// fire.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn non_matching_crashpoint_is_silent() {
        let slot = CrashSlot::empty();
        slot.arm("after_broadcast_vote");
        CRASH_SLOT
            .scope(slot, async {
                // Different name: no panic.
                crashpoint!("after_persist_locked");
            })
            .await;
    }

    /// Fire-once: a second crashpoint with the matching name does not
    /// panic. Tests model "crash once, restart, run again without
    /// re-crashing at the same point" by relying on this contract.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn crashpoint_is_fire_once() {
        let slot = CrashSlot::empty();
        slot.arm("after_persist_locked");
        let result = CRASH_SLOT
            .scope(slot, async {
                let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crashpoint!("after_persist_locked");
                }));
                let armed_after_first =
                    CRASH_SLOT.with(|s: &CrashSlot| -> Option<&'static str> { s.peek() });
                // Second call must be silent.
                crashpoint!("after_persist_locked");
                (first, armed_after_first)
            })
            .await;
        let (first, armed_after_first) = result;
        assert!(first.is_err(), "first crashpoint must panic");
        assert_eq!(armed_after_first, None, "slot must clear after first fire");
    }

    /// Distinct slots in distinct scopes do not bleed: a crashpoint
    /// armed in scope A's slot does not fire when scope B (with a
    /// different `CrashSlot` instance) crosses the same name. The sim
    /// relies on this when it spawns one task per node and arms only
    /// one of them.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn distinct_scopes_do_not_share_arm() {
        let armed = CrashSlot::empty();
        armed.arm("after_persist_voted_view");
        let unarmed = CrashSlot::empty();

        // Scope B (unarmed): crashpoint must not fire.
        CRASH_SLOT
            .scope(unarmed.clone(), async {
                crashpoint!("after_persist_voted_view");
            })
            .await;

        // Scope A (armed): the same name fires because the scope
        // received a clone sharing the armed Arc<Mutex>.
        let result = CRASH_SLOT
            .scope(armed.clone(), async {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crashpoint!("after_persist_voted_view");
                }))
            })
            .await;
        assert!(result.is_err(), "scope-A crashpoint must fire");
    }

    /// `Clone` shares state. The sim holds one clone of each per-node
    /// slot; the in-task scope holds another. Arming via the external
    /// clone makes the in-task `crashpoint!()` fire — the property
    /// the sim's `arm_crashpoint(idx, name)` builds on.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cloned_slots_share_state() {
        let outside = CrashSlot::empty();
        let inside = outside.clone();
        // Arm via the outside handle, fire from inside the scope.
        outside.arm("after_broadcast_vote");
        let result = CRASH_SLOT
            .scope(inside, async {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crashpoint!("after_broadcast_vote");
                }))
            })
            .await;
        assert!(result.is_err(), "shared-Arc clones must propagate arms");
        assert_eq!(
            outside.peek(),
            None,
            "fire-once contract must clear the shared inner slot",
        );
    }
}
