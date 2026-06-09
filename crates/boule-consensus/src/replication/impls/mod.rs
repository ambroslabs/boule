//! Reference implementations of the traits in [`super`].
//!
//! These exist to unit-test consensus against something concrete without
//! committing to a real application. They are deliberately minimal.

// The counter state machine is test/sim-only infrastructure (#894): it is the
// reference [`StateMachine`] consensus is unit-tested against and the
// lightweight backend the simulation suite and the bundle's fast
// consensus-liveness tests run, but it is NOT a production execution backend
// (reth is — #883). Gate it behind `cfg(test)` for this crate's own tests and
// the `testing` feature for downstream test builds so it never ships in a
// production binary.
#[cfg(any(test, feature = "testing"))]
pub mod counter_sm;
pub mod mem_mempool;

#[cfg(any(test, feature = "testing"))]
#[allow(unused_imports)]
pub use counter_sm::CounterStateMachine;
#[allow(unused_imports)]
pub use mem_mempool::InMemoryMempool;
