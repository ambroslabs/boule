use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::View;

pub const PARAM_UPDATE_TAG: &[u8; 6] = b"CPARM\0";

pub const MIN_PARAM_V_EFF_DELAY: View = View::new(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParams {
    pub min_block_interval_ms: u64,
}

impl ConsensusParams {
    pub fn min_block_interval(&self) -> Duration {
        Duration::from_millis(self.min_block_interval_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParamUpdate {
    pub min_block_interval_ms: Option<u64>,

    pub v_eff: View,
}

impl ConsensusParamUpdate {
    pub fn encode(&self) -> Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of ConsensusParamUpdate cannot fail");
        let mut out = Vec::with_capacity(PARAM_UPDATE_TAG.len() + body.len());
        out.extend_from_slice(PARAM_UPDATE_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_param_update_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(PARAM_UPDATE_TAG)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(PARAM_UPDATE_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing param-update tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed ConsensusParamUpdate: {e}"))
    }

    pub fn is_empty(&self) -> bool {
        self.min_block_interval_ms.is_none()
    }

    pub fn apply_to(&self, base: ConsensusParams) -> ConsensusParams {
        ConsensusParams {
            min_block_interval_ms: self
                .min_block_interval_ms
                .unwrap_or(base.min_block_interval_ms),
        }
    }

    pub fn validate_against(&self, block_view: View) -> anyhow::Result<()> {
        if self.is_empty() {
            anyhow::bail!("param update changes nothing");
        }
        let floor = block_view
            .checked_add(MIN_PARAM_V_EFF_DELAY)
            .ok_or_else(|| anyhow::anyhow!("v_eff floor overflow"))?;
        if self.v_eff < floor {
            anyhow::bail!(
                "v_eff {} is sooner than the floor {} (block view {} + delay {})",
                self.v_eff.0,
                floor.0,
                block_view.0,
                MIN_PARAM_V_EFF_DELAY.0,
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusParamHistory {
    genesis: ConsensusParams,

    boundaries: Vec<(View, ConsensusParams)>,
}

impl ConsensusParamHistory {
    pub fn new(genesis: ConsensusParams) -> Self {
        Self {
            genesis,
            boundaries: Vec::new(),
        }
    }

    pub fn at(&self, view: View) -> ConsensusParams {
        self.boundaries
            .iter()
            .rev()
            .find(|(v_eff, _)| view >= *v_eff)
            .map(|(_, p)| *p)
            .unwrap_or(self.genesis)
    }

    pub fn latest(&self) -> ConsensusParams {
        self.boundaries
            .last()
            .map(|(_, p)| *p)
            .unwrap_or(self.genesis)
    }

    pub fn insert_boundary(&mut self, v_eff: View, params: ConsensusParams) -> anyhow::Result<()> {
        if let Some((last, _)) = self.boundaries.last() {
            if v_eff <= *last {
                anyhow::bail!(
                    "param boundary v_eff {} does not exceed the last boundary {}",
                    v_eff.0,
                    last.0,
                );
            }
        } else if v_eff == View::ZERO {
            anyhow::bail!("param boundary v_eff must be greater than genesis (view 0)");
        }
        self.boundaries.push((v_eff, params));
        Ok(())
    }

    pub fn to_persisted(&self) -> PersistedConsensusParamHistory {
        PersistedConsensusParamHistory {
            genesis: self.genesis,
            boundaries: self
                .boundaries
                .iter()
                .map(|(v_eff, params)| PersistedParamBoundary {
                    v_eff: *v_eff,
                    params: *params,
                })
                .collect(),
        }
    }

    pub fn from_persisted(persisted: PersistedConsensusParamHistory) -> anyhow::Result<Self> {
        let mut history = Self::new(persisted.genesis);
        for boundary in persisted.boundaries {
            history.insert_boundary(boundary.v_eff, boundary.params)?;
        }
        Ok(history)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedParamBoundary {
    pub v_eff: View,

    pub params: ConsensusParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedConsensusParamHistory {
    pub genesis: ConsensusParams,

    pub boundaries: Vec<PersistedParamBoundary>,
}
