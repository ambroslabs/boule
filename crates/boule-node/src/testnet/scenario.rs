use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::events;
use super::lifecycle;
use super::wait;
use super::workdir::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    #[serde(default)]
    pub scenario: ScenarioMeta,
    #[serde(default)]
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScenarioMeta {
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    WaitAllReachHeight {
        height: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },

    WaitAllAdvanceBy {
        delta: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },

    WaitAllHealthy {
        #[serde(default = "default_within")]
        within: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },

    WaitQuiescent {
        for_secs: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },

    WaitCatchUp {
        node: String,
        #[serde(default = "default_tolerance")]
        tolerance: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },

    KillRandom {
        #[serde(default = "default_kill_count")]
        count: usize,
    },

    Kill {
        node: String,
    },

    Up {
        node: String,
    },

    VerifySafety,
}

fn default_within() -> u64 {
    5
}
fn default_tolerance() -> u64 {
    2
}
fn default_kill_count() -> usize {
    1
}
fn default_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub op: String,
    pub detail: String,
}

pub async fn run(
    workdir: &Path,
    binary: &Path,
    scenario: Scenario,
) -> anyhow::Result<Vec<StepOutcome>> {
    let seed = scenario.scenario.seed.unwrap_or(0);
    let mut outcomes = Vec::with_capacity(scenario.steps.len());
    let mut step_seed = seed;
    for (idx, step) in scenario.steps.into_iter().enumerate() {
        let state = State::load(workdir)?;
        let result = run_step(workdir, binary, &state, &step, step_seed).await;
        let label = step_label(&step);
        match result {
            Ok(detail) => {
                events::record(
                    workdir,
                    "scenario_step_ok",
                    None,
                    Some(&format!("{idx}:{label} {detail}")),
                );
                outcomes.push(StepOutcome { op: label, detail });
            }
            Err(e) => {
                events::record(
                    workdir,
                    "scenario_step_fail",
                    None,
                    Some(&format!("{idx}:{label} seed={seed} err={e}")),
                );
                anyhow::bail!("scenario step {idx} ({label}) failed (seed={seed}): {e}");
            }
        }
        step_seed = step_seed.wrapping_add(1);
    }
    Ok(outcomes)
}

fn step_label(s: &Step) -> String {
    match s {
        Step::WaitAllReachHeight { height, .. } => format!("wait_all_reach_height({height})"),
        Step::WaitAllAdvanceBy { delta, .. } => format!("wait_all_advance_by({delta})"),
        Step::WaitAllHealthy { within, .. } => format!("wait_all_healthy(within={within})"),
        Step::WaitQuiescent { for_secs, .. } => format!("wait_quiescent({for_secs}s)"),
        Step::WaitCatchUp {
            node, tolerance, ..
        } => format!("wait_catch_up({node}, tol={tolerance})"),
        Step::KillRandom { count } => format!("kill_random(count={count})"),
        Step::Kill { node } => format!("kill({node})"),
        Step::Up { node } => format!("up({node})"),
        Step::VerifySafety => "verify_safety".to_string(),
    }
}

async fn run_step(
    workdir: &Path,
    binary: &Path,
    state: &State,
    step: &Step,
    step_seed: u64,
) -> anyhow::Result<String> {
    match step {
        Step::WaitAllReachHeight {
            height,
            timeout_secs,
        } => {
            wait::all_reach_height(state, *height, Duration::from_secs(*timeout_secs)).await?;
            Ok(format!("height>={height}"))
        }
        Step::WaitAllAdvanceBy {
            delta,
            timeout_secs,
        } => {
            wait::all_advance_by(state, *delta, Duration::from_secs(*timeout_secs)).await?;
            Ok(format!("delta>={delta}"))
        }
        Step::WaitAllHealthy {
            within,
            timeout_secs,
        } => {
            wait::all_healthy(state, *within, Duration::from_secs(*timeout_secs)).await?;
            Ok(format!("within={within}"))
        }
        Step::WaitQuiescent {
            for_secs,
            timeout_secs,
        } => {
            wait::quiescent(
                state,
                Duration::from_secs(*for_secs),
                Duration::from_secs((*timeout_secs).max(*for_secs + 5)),
            )
            .await?;
            Ok(format!("held={for_secs}s"))
        }
        Step::WaitCatchUp {
            node,
            tolerance,
            timeout_secs,
        } => {
            let n = state.node(node)?;
            wait::node_caught_up(state, n, *tolerance, Duration::from_secs(*timeout_secs)).await?;
            Ok(format!("{node} within {tolerance}"))
        }
        Step::KillRandom { count } => {
            let killed = lifecycle::kill_random(workdir, state, *count, step_seed)?;
            let names: Vec<String> = killed
                .into_iter()
                .map(|i| state.nodes[i].display_name())
                .collect();
            Ok(format!("killed=[{}]", names.join(",")))
        }
        Step::Kill { node } => {
            let n = state.node(node)?.clone();
            lifecycle::kill_one(workdir, &n)?;
            Ok(format!("killed={node}"))
        }
        Step::Up { node } => {
            let n = state.node(node)?.clone();

            if lifecycle::pid_alive(&n).is_some() {
                return Ok(format!("up={node} (already running)"));
            }
            lifecycle::up_one(workdir, binary, &n).await?;
            Ok(format!("up={node}"))
        }
        Step::VerifySafety => {
            let v = super::safety::verify(state)?;
            if !v.is_empty() {
                anyhow::bail!("safety violations detected: {} entries", v.len());
            }
            Ok("ok".to_string())
        }
    }
}

pub fn load(path: &Path) -> anyhow::Result<Scenario> {
    let bytes = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&bytes)?)
}

pub fn rotating_failure(f: usize, seed: u64) -> Scenario {
    let timeout = 30;
    Scenario {
        scenario: ScenarioMeta {
            seed: Some(seed),
            name: Some(format!("rotating-failure-f{f}")),
        },
        steps: vec![
            Step::WaitAllReachHeight {
                height: 5,
                timeout_secs: timeout,
            },
            Step::KillRandom { count: f },
            Step::WaitAllAdvanceBy {
                delta: 10,
                timeout_secs: timeout,
            },
            Step::VerifySafety,
        ],
    }
}

pub fn disconnect_random(count: usize, liveness_window_secs: u64, seed: u64) -> Scenario {
    let post_kill_delta = (liveness_window_secs * 2).max(10);
    let timeout = liveness_window_secs * 2 + 30;
    Scenario {
        scenario: ScenarioMeta {
            seed: Some(seed),
            name: Some("disconnect-random".into()),
        },
        steps: vec![
            Step::WaitAllHealthy {
                within: 5,
                timeout_secs: 30,
            },
            Step::KillRandom { count },
            Step::WaitAllAdvanceBy {
                delta: post_kill_delta,
                timeout_secs: timeout,
            },
            Step::VerifySafety,
        ],
    }
}

pub fn reconnect_with_catchup(node: &str) -> Scenario {
    Scenario {
        scenario: ScenarioMeta {
            seed: Some(0),
            name: Some(format!("reconnect-{node}")),
        },
        steps: vec![
            Step::Up {
                node: node.to_string(),
            },
            Step::WaitCatchUp {
                node: node.to_string(),
                tolerance: 2,
                timeout_secs: 60,
            },
            Step::VerifySafety,
        ],
    }
}

pub fn rotating_failure_7n_f2(seed: u64) -> Scenario {
    rotating_failure(2, seed)
}
