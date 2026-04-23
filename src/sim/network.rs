//! Per-link network state and scheduling primitives for the simulator.
//!
//! For step 2 (issue #19, sub-task #29) this is intentionally minimal: it
//! holds the seeded RNG and a placeholder for per-link fault state. Step 3
//! grows this to own a `BinaryHeap<Event>` keyed on
//! `(virtual_time, tiebreak_seq)` plus per-link latency / drop / bandwidth /
//! reorder / partition state.

use std::sync::{Arc, Mutex};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng as _;

pub struct SimNetwork {
    inner: Mutex<Inner>,
}

struct Inner {
    #[allow(dead_code)] // Unused until fault injection (sub-task #30) consumes it.
    rng: ChaCha20Rng,
}

impl SimNetwork {
    pub fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                rng: ChaCha20Rng::seed_from_u64(seed),
            }),
        })
    }
}
