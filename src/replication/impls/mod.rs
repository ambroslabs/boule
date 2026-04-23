//! Reference implementations of the traits in [`super`].
//!
//! These exist to unit-test consensus against something concrete without
//! committing to a real application. They are deliberately minimal.

pub mod counter_sm;

#[allow(unused_imports)]
pub use counter_sm::CounterStateMachine;
