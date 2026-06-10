use rand::SeedableRng;
use rand::seq::IndexedRandom;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologySpec {
    pub nodes: usize,
    pub seed_extra: usize,
    pub target_degree: usize,
    pub seed: u64,
}

impl TopologySpec {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.nodes < 4 {
            anyhow::bail!("--nodes must be at least 4 (HotStuff needs 3f+1, f>=1)");
        }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTopology {
    pub index: usize,

    pub bootstrap_peers: Vec<usize>,
}

pub fn generate(spec: &TopologySpec) -> anyhow::Result<Vec<NodeTopology>> {
    spec.validate()?;
    let n = spec.nodes;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let prev = (i + n - 1) % n;
        let next = (i + 1) % n;
        let mut peers: Vec<usize> = vec![prev, next];

        if spec.seed_extra > 0 {
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
