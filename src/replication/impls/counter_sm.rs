//! A trivial [`StateMachine`] over a single `u64` counter.
//!
//! Commands are a two-variant enum (`Increment` / `Decrement`) encoded with
//! `postcard`. Underflow on `Decrement` past zero surfaces as `Err` and
//! leaves the counter unchanged — matching the `apply` error contract on
//! [`StateMachine`].
//!
//! This impl is sufficient for unit-testing consensus and for the synthetic
//! cross-trait integration test planned with the last milestone-5 subissue.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::replication::state_machine::StateMachine;

/// Commands accepted by [`CounterStateMachine`].
///
/// Serialized with `postcard` for wire and storage representation; the
/// encoding is deterministic for this fixed-shape enum and matches the
/// convention used elsewhere in the crate (see `src/crypto/signed.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterCommand {
    Increment,
    Decrement,
}

impl CounterCommand {
    /// Encode this command with `postcard`.
    pub fn encode(&self) -> Bytes {
        // `postcard::to_stdvec` on a fixed-shape enum cannot fail.
        Bytes::from(postcard::to_stdvec(self).expect("postcard encoding of CounterCommand"))
    }
}

/// A single-`u64` counter driven by [`CounterCommand`]s.
#[derive(Debug, Default, Clone)]
pub struct CounterStateMachine {
    value: u64,
}

impl CounterStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current counter value. Exposed for tests; consensus observes state
    /// only through [`StateMachine::state_commitment`] and
    /// [`StateMachine::snapshot`].
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl StateMachine for CounterStateMachine {
    fn apply(&mut self, cmd: &[u8]) -> anyhow::Result<Bytes> {
        let decoded: CounterCommand = postcard::from_bytes(cmd)
            .map_err(|e| anyhow::anyhow!("decoding CounterCommand: {e}"))?;
        match decoded {
            CounterCommand::Increment => {
                // Per the `apply` contract, on error state is unchanged.
                self.value = self
                    .value
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("counter overflow"))?;
            }
            CounterCommand::Decrement => {
                self.value = self
                    .value
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("counter underflow"))?;
            }
        }
        // Opaque output: the new counter value as big-endian bytes.
        Ok(Bytes::copy_from_slice(&self.value.to_be_bytes()))
    }

    fn state_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.value.to_be_bytes());
        hasher.finalize().into()
    }

    fn snapshot(&self) -> Bytes {
        Bytes::from(postcard::to_stdvec(&self.value).expect("postcard encoding of counter value"))
    }

    fn restore(&mut self, snap: &[u8]) -> anyhow::Result<()> {
        let value: u64 =
            postcard::from_bytes(snap).map_err(|e| anyhow::anyhow!("decoding snapshot: {e}"))?;
        self.value = value;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd_bytes(c: CounterCommand) -> Bytes {
        c.encode()
    }

    fn expected_commitment(value: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(value.to_be_bytes());
        hasher.finalize().into()
    }

    #[test]
    fn known_sequence_matches_expected_commitment() {
        // +, +, +, -  →  value = 2
        let mut sm = CounterStateMachine::new();
        for c in [
            CounterCommand::Increment,
            CounterCommand::Increment,
            CounterCommand::Increment,
            CounterCommand::Decrement,
        ] {
            sm.apply(&cmd_bytes(c)).unwrap();
        }
        assert_eq!(sm.value(), 2);
        assert_eq!(sm.state_commitment(), expected_commitment(2));
    }

    #[test]
    fn apply_returns_be_encoded_new_value() {
        let mut sm = CounterStateMachine::new();
        let out = sm.apply(&cmd_bytes(CounterCommand::Increment)).unwrap();
        assert_eq!(out.as_ref(), &1u64.to_be_bytes());
    }

    #[test]
    fn decrement_below_zero_errors_and_leaves_state_unchanged() {
        let mut sm = CounterStateMachine::new();
        let before = sm.state_commitment();
        let err = sm.apply(&cmd_bytes(CounterCommand::Decrement)).unwrap_err();
        assert!(err.to_string().contains("underflow"));
        assert_eq!(sm.value(), 0);
        assert_eq!(sm.state_commitment(), before);
    }

    #[test]
    fn malformed_command_errors_and_leaves_state_unchanged() {
        let mut sm = CounterStateMachine::new();
        sm.apply(&cmd_bytes(CounterCommand::Increment)).unwrap();
        let before = sm.state_commitment();

        // A plainly invalid postcard encoding for `CounterCommand`.
        let err = sm.apply(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert!(err.to_string().contains("decoding CounterCommand"));
        assert_eq!(sm.value(), 1);
        assert_eq!(sm.state_commitment(), before);
    }

    #[test]
    fn snapshot_restore_round_trip() {
        let mut a = CounterStateMachine::new();
        for _ in 0..5 {
            a.apply(&cmd_bytes(CounterCommand::Increment)).unwrap();
        }
        let snap = a.snapshot();

        let mut b = CounterStateMachine::new();
        b.restore(&snap).unwrap();
        assert_eq!(b.value(), a.value());
        assert_eq!(b.state_commitment(), a.state_commitment());
    }

    #[test]
    fn determinism_across_instances() {
        // Two independent machines applying the same sequence must agree
        // on the commitment. Guards against accidental nondeterminism
        // creeping into `apply` or `state_commitment`.
        let seq = [
            CounterCommand::Increment,
            CounterCommand::Increment,
            CounterCommand::Decrement,
            CounterCommand::Increment,
        ];
        let mut a = CounterStateMachine::new();
        let mut b = CounterStateMachine::new();
        for c in seq {
            a.apply(&cmd_bytes(c)).unwrap();
            b.apply(&cmd_bytes(c)).unwrap();
        }
        assert_eq!(a.state_commitment(), b.state_commitment());
    }

    // ── Property tests ──────────────────────────────────────────────────

    use proptest::prelude::*;

    fn command_strategy() -> impl Strategy<Value = CounterCommand> {
        prop_oneof![
            Just(CounterCommand::Increment),
            Just(CounterCommand::Decrement),
        ]
    }

    // A "safe" sequence: never dips below zero, so every `apply` succeeds
    // and the final value is the signed sum. Drawn as `Vec<CounterCommand>`
    // filtered for non-negative running sum.
    fn safe_sequence_strategy() -> impl Strategy<Value = Vec<CounterCommand>> {
        prop::collection::vec(command_strategy(), 0..64).prop_filter(
            "never decrement below zero",
            |seq| {
                let mut v: i64 = 0;
                for c in seq {
                    v += match c {
                        CounterCommand::Increment => 1,
                        CounterCommand::Decrement => -1,
                    };
                    if v < 0 {
                        return false;
                    }
                }
                true
            },
        )
    }

    fn apply_all(sm: &mut CounterStateMachine, cmds: &[CounterCommand]) {
        for c in cmds {
            sm.apply(&cmd_bytes(*c)).unwrap();
        }
    }

    proptest! {
        // The core verification criterion from issue #21:
        // `snapshot → restore → apply(suffix)` equals `apply(full sequence)`.
        #[test]
        fn prop_snapshot_restore_apply_suffix_matches_full(
            seq in safe_sequence_strategy(),
            split in any::<u8>(),
        ) {
            let split = (split as usize) % (seq.len() + 1);
            let (prefix, suffix) = seq.split_at(split);

            // Full: apply everything from scratch.
            let mut full = CounterStateMachine::new();
            apply_all(&mut full, &seq);

            // Split: apply prefix, snapshot, restore into a fresh machine,
            // then apply the suffix.
            let mut first = CounterStateMachine::new();
            apply_all(&mut first, prefix);
            let snap = first.snapshot();

            let mut second = CounterStateMachine::new();
            second.restore(&snap).unwrap();
            apply_all(&mut second, suffix);

            prop_assert_eq!(second.state_commitment(), full.state_commitment());
            prop_assert_eq!(second.value(), full.value());
        }

        // Determinism: same sequence, two fresh machines, identical commitments.
        #[test]
        fn prop_same_sequence_same_commitment(seq in safe_sequence_strategy()) {
            let mut a = CounterStateMachine::new();
            let mut b = CounterStateMachine::new();
            apply_all(&mut a, &seq);
            apply_all(&mut b, &seq);
            prop_assert_eq!(a.state_commitment(), b.state_commitment());
        }

        // Snapshot round-trip preserves state for arbitrary u64 values.
        #[test]
        fn prop_snapshot_round_trip(value in any::<u64>()) {
            let mut a = CounterStateMachine { value };
            let snap = a.snapshot();
            let mut b = CounterStateMachine::new();
            b.restore(&snap).unwrap();
            prop_assert_eq!(b.value(), value);
            prop_assert_eq!(b.state_commitment(), a.state_commitment());
            // And applying an Increment on either now matches.
            a.apply(&cmd_bytes(CounterCommand::Increment)).ok();
            b.apply(&cmd_bytes(CounterCommand::Increment)).ok();
            prop_assert_eq!(a.state_commitment(), b.state_commitment());
        }
    }
}
