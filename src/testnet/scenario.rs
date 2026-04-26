//! Built-in scenario subcommands and the typed TOML scenario format.
//!
//! A scenario is a deterministic sequence of [`Step`]s the driver
//! executes against a workdir. Each step that depends on randomness
//! (e.g. `kill_random`) draws from a seed-derived RNG, so re-running
//! the same scenario file with the same seed reproduces the same
//! behaviour.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::events;
use super::lifecycle;
use super::wait;
use super::workdir::State;

/// Composed-scenario file: top-level `[scenario]` table plus an
/// ordered `[[steps]]` list.
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

/// One step in a scenario. Tagged by `op =` for human-readable TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    /// Wait until every live node has committed at least `height`.
    WaitAllReachHeight {
        height: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    /// Snapshot every live node's `last_committed_height` and wait until
    /// each has advanced by at least `delta` blocks. The post-kill
    /// liveness check `WaitAllReachHeight` can't honestly express,
    /// because that one is satisfied immediately if the cluster
    /// already reached the target before the kill.
    WaitAllAdvanceBy {
        delta: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    /// Wait until every live node is healthy and within `within` views.
    WaitAllHealthy {
        #[serde(default = "default_within")]
        within: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    /// Wait until heights stop changing for `for_secs` seconds.
    WaitQuiescent {
        for_secs: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    /// Wait until `node` is within `tolerance` of the cluster's max height.
    WaitCatchUp {
        node: String,
        #[serde(default = "default_tolerance")]
        tolerance: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    /// SIGKILL `count` random live nodes.
    KillRandom {
        #[serde(default = "default_kill_count")]
        count: usize,
    },
    /// SIGKILL one specific node.
    Kill { node: String },
    /// Re-spawn `node` (must be down).
    Up { node: String },
    /// Verify safety across every commit-log line. Aborts the scenario
    /// run on violation.
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

/// Outcome of a single executed step. The CLI prints these as it goes.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub op: String,
    pub detail: String,
}

/// Run the scenario against `workdir`. The state file is reloaded
/// after each step to pick up `up`/`kill` mutations.
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
            // Mirror `cmd_up`'s "already running" no-op so the step is
            // composable: `cmd_scenario` calls `up_all` before running
            // steps, which means a scenario whose first step is `Up`
            // (e.g. `reconnect_with_catchup`) would otherwise always
            // fail on a re-spawned node. Treat an already-live node as
            // success.
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

/// Read a scenario TOML file from disk.
pub fn load(path: &Path) -> anyhow::Result<Scenario> {
    let bytes = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&bytes)?)
}

/// Built-in: `rotating-failure --f F`. Mirrors §9b's rotating-failure
/// script: bring the cluster to steady state, SIGKILL `f` random nodes,
/// confirm survivors keep committing, then verify safety. Requires the
/// cluster to be up already.
///
/// The post-kill liveness check is `WaitAllAdvanceBy`, *not*
/// `WaitAllReachHeight`. The latter is satisfied immediately when the
/// cluster already passed the target before the kill, which makes it
/// a vacuous predicate on a cluster that commits 40+ blocks per
/// second. `WaitAllAdvanceBy` snapshots heights at the start of the
/// step and waits for the survivors to commit `delta` *more* blocks —
/// which is what "did the survivors keep making progress?" actually
/// means.
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

/// Built-in: `disconnect-random --count N --restart-after Ns`.
/// Kills `count` random live nodes, then asserts the survivors keep
/// committing, and finally verifies safety.
///
/// The pre-kill `WaitAllHealthy` is load-bearing: with the default
/// 7-node ring (`bootstrap_peers = [i-1, i+1]` mod n), some seeds
/// pick two ring-neighbours of the same node — e.g. seed=7 + count=2
/// kills node1 + node3, both of which are bootstrap peers of node2.
/// If we kill before the gossip overlay has expanded past the
/// bootstrap pairs, node2 ends up with zero peers and the cluster
/// stalls. `WaitAllHealthy` waits until every live node has at least
/// `n - 1` consensus peers, which guarantees each survivor still has
/// quorum-many connections after any `count`-sized kill subset.
///
/// `restart_after_secs` was originally meant to gate "restart the
/// dead nodes after N seconds", but the scenario format has no way
/// to propagate the seed-chosen kill targets to a subsequent `up`
/// step, so the param now just sizes the post-kill liveness window.
/// Run a follow-up `testnet scenario reconnect-with-catchup <node>`
/// (or a TOML file referencing each restart target by name) to
/// exercise the bring-back path.
pub fn disconnect_random(count: usize, restart_after_secs: u64, seed: u64) -> Scenario {
    // Survivors must commit at least this many *additional* blocks
    // after the kill. Sized off `restart_after_secs` so longer-running
    // scenarios get a proportionally bigger liveness window.
    let post_kill_delta = (restart_after_secs * 2).max(10);
    let timeout = restart_after_secs * 2 + 30;
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

/// Built-in: `reconnect <node> --wait-catch-up`. Intended to be run
/// after the named node was killed earlier in the same workdir.
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

/// Path to the canonical `rotating-failure-7n-f2` scenario referenced
/// in the issue's acceptance criteria. Returned as a [`Scenario`] so
/// the CLI can invoke it without a TOML file on disk.
pub fn rotating_failure_7n_f2(seed: u64) -> Scenario {
    rotating_failure(2, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let s = Scenario {
            scenario: ScenarioMeta {
                seed: Some(42),
                name: Some("ex".into()),
            },
            steps: vec![
                Step::WaitAllReachHeight {
                    height: 30,
                    timeout_secs: 30,
                },
                Step::KillRandom { count: 2 },
                Step::WaitQuiescent {
                    for_secs: 3,
                    timeout_secs: 30,
                },
                Step::VerifySafety,
            ],
        };
        let serialized = toml::to_string_pretty(&s).unwrap();
        let back: Scenario = toml::from_str(&serialized).unwrap();
        assert_eq!(back.scenario.seed, Some(42));
        assert_eq!(back.steps.len(), 4);
    }

    #[test]
    fn parses_example_scenario_from_issue() {
        let toml_text = r#"
[scenario]
seed = 42

[[steps]]
op = "wait_all_reach_height"
height = 30

[[steps]]
op = "kill_random"
count = 2

[[steps]]
op = "wait_quiescent"
for_secs = 3

[[steps]]
op = "verify_safety"
"#;
        let s: Scenario = toml::from_str(toml_text).unwrap();
        assert_eq!(s.scenario.seed, Some(42));
        assert_eq!(s.steps.len(), 4);
    }

    #[test]
    fn rotating_failure_has_kill_then_verify() {
        let s = rotating_failure(2, 1);
        assert!(matches!(s.steps[0], Step::WaitAllReachHeight { .. }));
        assert!(matches!(s.steps[1], Step::KillRandom { count: 2 }));
        // Post-kill liveness must be `WaitAllAdvanceBy`, not
        // `WaitAllReachHeight`; the latter is satisfied immediately if
        // the cluster already passed the target, which makes it a
        // vacuous predicate (issue #205, item 3).
        assert!(
            matches!(s.steps[2], Step::WaitAllAdvanceBy { delta: 10, .. }),
            "expected post-kill WaitAllAdvanceBy, got {:?}",
            s.steps[2]
        );
        assert!(matches!(s.steps.last(), Some(Step::VerifySafety)));
    }

    #[test]
    fn disconnect_random_has_pre_kill_mesh_warmup() {
        let s = disconnect_random(2, 5, 7);
        // First step must be the mesh-warmup gate: with the default
        // ring topology, killing two ring-neighbours of the same node
        // before gossip expands the mesh isolates the survivor (issue
        // #205, item 4).
        assert!(
            matches!(s.steps[0], Step::WaitAllHealthy { .. }),
            "expected pre-kill WaitAllHealthy, got {:?}",
            s.steps[0]
        );
        assert!(matches!(s.steps[1], Step::KillRandom { count: 2 }));
        assert!(matches!(s.steps[2], Step::WaitAllAdvanceBy { .. }));
        assert!(matches!(s.steps.last(), Some(Step::VerifySafety)));
    }

    #[test]
    fn wait_all_advance_by_round_trips_through_toml() {
        let s = Scenario {
            scenario: ScenarioMeta {
                seed: Some(0),
                name: None,
            },
            steps: vec![Step::WaitAllAdvanceBy {
                delta: 7,
                timeout_secs: 20,
            }],
        };
        let serialized = toml::to_string_pretty(&s).unwrap();
        let back: Scenario = toml::from_str(&serialized).unwrap();
        match &back.steps[0] {
            Step::WaitAllAdvanceBy {
                delta,
                timeout_secs,
            } => {
                assert_eq!(*delta, 7);
                assert_eq!(*timeout_secs, 20);
            }
            other => panic!("expected WaitAllAdvanceBy, got {other:?}"),
        }
    }
}
