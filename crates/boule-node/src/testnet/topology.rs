//! Seeded topology generation for the testnet driver.
//!
//! The driver lays out an `n`-node cluster as a ring (each node lists
//! `i-1` and `i+1 mod n` as neighbours) plus `seed_extra` random extra
//! peers per node, drawn with a seeded RNG from `{0..n} \ {i, i-1, i+1}`.
//! The realized peer set seeds each node's `[overlay].bootstrap_addrs`,
//! which the libp2p overlay dials to join the cluster.

use rand::SeedableRng;
use rand::seq::IndexedRandom;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// Topology specification — the inputs to `generate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologySpec {
    pub nodes: usize,
    pub seed_extra: usize,
    pub target_degree: usize,
    pub seed: u64,
}

impl TopologySpec {
    /// Validate the inputs. Errors are surfaced verbatim to the CLI.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.nodes < 4 {
            anyhow::bail!("--nodes must be at least 4 (HotStuff needs 3f+1, f>=1)");
        }
        // Available off-ring candidates per node = n - 3 (exclude self
        // + two ring neighbours). When n == 3 there are zero candidates,
        // so we already require n >= 4 above.
        let candidates = self.nodes.saturating_sub(3);
        if self.seed_extra > candidates {
            anyhow::bail!(
                "--seed-extra={} exceeds the {} off-ring candidates available with --nodes={}",
                self.seed_extra,
                candidates,
                self.nodes
            );
        }
        if self.target_degree <= self.seed_extra + 2 {
            anyhow::bail!(
                "--target-degree must exceed seed_extra+2 ({} + 2 = {}); got {}",
                self.seed_extra,
                self.seed_extra + 2,
                self.target_degree
            );
        }
        Ok(())
    }
}

/// Per-node bootstrap peer list, expressed as zero-based indices into
/// the topology's node array. The driver maps these to the actual
/// `[[peers]]` block once node IDs and bound P2P addresses are known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTopology {
    pub index: usize,
    /// Zero-based indices of the ring neighbours and the random extras,
    /// sorted ascending. Self is never included.
    pub bootstrap_peers: Vec<usize>,
}

/// Generate the per-node bootstrap peer index lists for `spec`.
///
/// Determinism: a `(spec.nodes, spec.seed_extra, spec.seed)` tuple
/// always produces the same output. The seed is mixed with the node
/// index so re-seeding for higher node counts doesn't collapse to a
/// single shared draw.
pub fn generate(spec: &TopologySpec) -> anyhow::Result<Vec<NodeTopology>> {
    spec.validate()?;
    let n = spec.nodes;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let prev = (i + n - 1) % n;
        let next = (i + 1) % n;
        let mut peers: Vec<usize> = vec![prev, next];

        if spec.seed_extra > 0 {
            // Per-node sub-seed so adding nodes later doesn't reshuffle
            // earlier nodes' draws.
            let mut rng = ChaCha20Rng::seed_from_u64(spec.seed.wrapping_add(i as u64));
            let candidates: Vec<usize> = (0..n)
                .filter(|j| *j != i && *j != prev && *j != next)
                .collect();
            let extra: Vec<usize> = candidates
                .choose_multiple(&mut rng, spec.seed_extra)
                .copied()
                .collect();
            peers.extend(extra);
        }
        peers.sort_unstable();
        peers.dedup();
        out.push(NodeTopology {
            index: i,
            bootstrap_peers: peers,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(n: usize, k: usize, target: usize, seed: u64) -> TopologySpec {
        TopologySpec {
            nodes: n,
            seed_extra: k,
            target_degree: target,
            seed,
        }
    }

    #[test]
    fn ring_only_when_seed_extra_is_zero() {
        let topo = generate(&spec(7, 0, 3, 1)).unwrap();
        for (i, t) in topo.iter().enumerate() {
            let n = 7;
            let prev = (i + n - 1) % n;
            let next = (i + 1) % n;
            let mut want = vec![prev, next];
            want.sort_unstable();
            assert_eq!(t.bootstrap_peers, want);
        }
    }

    #[test]
    fn extras_are_off_ring_only() {
        let topo = generate(&spec(10, 2, 5, 42)).unwrap();
        for (i, t) in topo.iter().enumerate() {
            let n = 10;
            let prev = (i + n - 1) % n;
            let next = (i + 1) % n;
            assert!(t.bootstrap_peers.contains(&prev));
            assert!(t.bootstrap_peers.contains(&next));
            for &p in &t.bootstrap_peers {
                assert_ne!(p, i, "self loop in node {i}");
            }
            // Total = 2 ring neighbours + seed_extra extras (which must
            // be off-ring and distinct).
            assert_eq!(t.bootstrap_peers.len(), 2 + 2);
        }
    }

    #[test]
    fn deterministic_under_same_seed() {
        let a = generate(&spec(30, 7, 10, 99)).unwrap();
        let b = generate(&spec(30, 7, 10, 99)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_diverge() {
        // For n=10, k=2 there are 7 off-ring candidates per node; seed
        // changes should usually pick different draws somewhere.
        let a = generate(&spec(10, 2, 5, 1)).unwrap();
        let b = generate(&spec(10, 2, 5, 2)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_target_too_small() {
        assert!(generate(&spec(7, 2, 3, 1)).is_err());
    }

    #[test]
    fn rejects_seed_extra_exceeds_candidates() {
        // n=4 means only one off-ring candidate per node.
        assert!(generate(&spec(4, 2, 5, 1)).is_err());
    }

    #[test]
    fn rejects_too_few_nodes() {
        assert!(generate(&spec(3, 0, 3, 1)).is_err());
    }

    /// The three sizing presets called out in the issue's acceptance
    /// criteria all generate without error.
    #[test]
    fn issue_189_acceptance_presets_validate() {
        // (n=7,  k=0, target=3): pure ring.
        assert!(generate(&spec(7, 0, 3, 1)).is_ok());
        // (n=10, k=2, target=5): ring + 2 extras.
        assert!(generate(&spec(10, 2, 5, 1)).is_ok());
        // (n=30, k=7, target=10): ring + 7 extras.
        assert!(generate(&spec(30, 7, 10, 1)).is_ok());
    }
}
