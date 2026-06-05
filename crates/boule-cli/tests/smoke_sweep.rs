//! Deterministic multi-process smoke sweep, as a cargo test.
//!
//! This is the executable replacement for the prose
//! `prompts/testnet-smoke-sweep.md`: a tier-gated scenario matrix run
//! against real multi-process `boule` clusters, with per-trial safety
//! and steady-state back-pressure checks. Counters are read as typed
//! `ConsensusStatus` structs (no log/column/JSON parsing), the
//! partition probe is a real BFS over `/peers`, and the thresholds are
//! code rather than a shell pipeline.
//!
//! It is **not** part of the per-PR gate. The cluster sweep
//! ([`smoke_sweep`]) is `#[ignore]`d so `cargo test` skips it; it runs
//! on a nightly schedule (and on the `smoke` PR label) via
//! `.github/workflows/smoke.yml`, the same cadence model as the fuzz
//! target. The fast structural checks below are not ignored — they
//! guard the matrix shape cheaply.
//!
//! Run locally:
//! ```sh
//! SMOKE_TIER=full cargo test -p boule-cli --test smoke_sweep -- --ignored --nocapture
//! ```
//! `SMOKE_TIER` is one of `quick|standard|extended|full` (default
//! `full`). The `boule` node binary is located via `CARGO_BIN_EXE_boule`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use boule_core::crypto::sig_scheme::SignatureSchemeChoice;
use boule_node::testnet::scenario::{Scenario, ScenarioMeta, Step};
use boule_node::testnet::topology::TopologySpec;
use boule_node::testnet::workdir::State;
use boule_node::testnet::{admin, lifecycle, safety, scenario, telemetry, wait};

/// Gap between the two back-pressure samples.
const BP_GAP: Duration = Duration::from_secs(5);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn boule_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_boule"))
}

/// Coverage tier. `full` reproduces the legacy 65-trial sweep one-to-one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    Quick,
    Standard,
    Extended,
    Full,
}

impl Tier {
    fn parse(s: &str) -> Result<Tier, String> {
        Ok(match s {
            "quick" | "15" => Tier::Quick,
            "standard" | "30" => Tier::Standard,
            "extended" | "60" => Tier::Extended,
            "full" | "90" => Tier::Full,
            other => return Err(format!("unknown tier {other:?}")),
        })
    }
    fn label(self) -> &'static str {
        match self {
            Tier::Quick => "quick",
            Tier::Standard => "standard",
            Tier::Extended => "extended",
            Tier::Full => "full",
        }
    }
}

/// One entry in the scenario matrix. Each variant maps to a runner.
enum Trial {
    Rotating {
        group: String,
        nodes: usize,
        f: usize,
        seed: u64,
    },
    KillRestart {
        group: String,
        seed: u64,
    },
    Disconnect {
        group: String,
        count: usize,
        window: u64,
        seed: u64,
    },
    GossipSteady {
        group: String,
        seed: u64,
    },
    PathProbe {
        group: String,
    },
    Bls {
        group: String,
        seed: u64,
    },
    Footgun {
        group: String,
    },
    Gated {
        group: String,
    },
    RestartDisk {
        group: String,
        seed: u64,
    },
    SeqKill {
        group: String,
        seed: u64,
    },
    Partition {
        group: String,
        seed: u64,
    },
}

fn trial_label(t: &Trial) -> String {
    match t {
        Trial::Rotating { group, .. } => format!("{group} rotating-failure"),
        Trial::KillRestart { group, .. } => format!("{group} kill-restart-catchup"),
        Trial::Disconnect { group, .. } => format!("{group} disconnect-random"),
        Trial::GossipSteady { group, .. } => format!("{group} gossip-steady-state"),
        Trial::PathProbe { group } => format!("{group} cli relative-workdir/cwd probe"),
        Trial::Bls { group, .. } => format!("{group} bls-happy-path"),
        Trial::Footgun { group } => format!("{group} footgun (expected-fail)"),
        Trial::Gated { group } => format!("{group} gated (expected-pass)"),
        Trial::RestartDisk { group, .. } => format!("{group} restart-from-disk"),
        Trial::SeqKill { group, .. } => format!("{group} sequential-kill"),
        Trial::Partition { group, .. } => format!("{group} partition-probe"),
    }
}

const D_SEEDS: [u64; 20] = [
    1, 7, 11, 13, 17, 23, 29, 42, 50, 64, 73, 89, 97, 100, 102, 107, 113, 127, 131, 149,
];

/// Build the scenario matrix for a tier. `full` matches the legacy
/// 65-trial sweep: Tier A + Tier B + Tier D (D replaces B5/C1/C2 with
/// their full-size seed sweeps).
fn matrix(tier: Tier) -> Vec<Trial> {
    let g = |s: &str| s.to_string();
    let mut v: Vec<Trial> = vec![
        Trial::Rotating {
            group: g("a1"),
            nodes: 4,
            f: 1,
            seed: 42,
        },
        Trial::KillRestart {
            group: g("a2"),
            seed: 42,
        },
        Trial::Disconnect {
            group: g("a3"),
            count: 2,
            window: 5,
            seed: 42,
        },
        Trial::GossipSteady {
            group: g("a4"),
            seed: 1,
        },
        Trial::PathProbe { group: g("a5") },
        Trial::Bls {
            group: g("a6"),
            seed: 42,
        },
    ];
    if tier == Tier::Quick {
        return v;
    }
    for s in [7, 42, 113] {
        v.push(Trial::Rotating {
            group: format!("b1-{s}"),
            nodes: 4,
            f: 1,
            seed: s,
        });
    }
    for s in [1, 42, 107] {
        v.push(Trial::KillRestart {
            group: format!("b2-{s}"),
            seed: s,
        });
    }
    for s in [1, 42, 102] {
        v.push(Trial::Disconnect {
            group: format!("b3-{s}"),
            count: 2,
            window: 5,
            seed: s,
        });
    }
    v.push(Trial::Footgun { group: g("b4a") });
    v.push(Trial::Gated { group: g("b4b") });
    for s in [7, 42, 113] {
        v.push(Trial::Bls {
            group: format!("b6-{s}"),
            seed: s,
        });
    }
    if tier == Tier::Standard {
        return v;
    }
    if tier == Tier::Extended {
        for s in [1, 42, 107] {
            v.push(Trial::Partition {
                group: format!("c1-{s}"),
                seed: s,
            });
        }
        for s in [1, 7, 11, 13, 17, 23, 29, 42, 50, 64] {
            v.push(Trial::SeqKill {
                group: format!("c2-{s}"),
                seed: s,
            });
        }
        return v;
    }
    // Full: Tier D — replaces B5/C1/C2 with full-size sweeps.
    for s in [1, 7, 42, 102, 107] {
        v.push(Trial::Partition {
            group: format!("d1-{s}"),
            seed: s,
        });
    }
    for s in D_SEEDS {
        v.push(Trial::RestartDisk {
            group: format!("d2-{s}"),
            seed: s,
        });
    }
    for s in D_SEEDS {
        v.push(Trial::SeqKill {
            group: format!("d3-{s}"),
            seed: s,
        });
    }
    v
}

#[derive(Clone)]
struct TrialResult {
    group: String,
    seed: Option<u64>,
    passed: bool,
    detail: String,
}

impl TrialResult {
    fn pass(group: &str, seed: Option<u64>, detail: String) -> Self {
        Self {
            group: group.to_string(),
            seed,
            passed: true,
            detail,
        }
    }
    fn fail(group: &str, seed: Option<u64>, detail: String) -> Self {
        Self {
            group: group.to_string(),
            seed,
            passed: false,
            detail,
        }
    }
}

fn print_table(tier: Tier, results: &[TrialResult]) {
    let passed = results.iter().filter(|r| r.passed).count();
    eprintln!(
        "smoke sweep — tier={} — {}/{} passed",
        tier.label(),
        passed,
        results.len()
    );
    eprintln!("{:<10} {:>6}  {:<6}  detail", "group", "seed", "result");
    for t in results {
        eprintln!(
            "{:<10} {:>6}  {:<6}  {}",
            t.group,
            t.seed.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            if t.passed { "PASS" } else { "FAIL" },
            t.detail
        );
    }
}

async fn run_smoke(tier: Tier, root: &Path, binary: &Path) -> Vec<TrialResult> {
    let trials = matrix(tier);
    let total = trials.len();
    let mut results = Vec::with_capacity(total);
    for (i, trial) in trials.into_iter().enumerate() {
        eprintln!("[smoke] {}/{} {}", i + 1, total, trial_label(&trial));
        let r = run_trial(root, binary, trial).await;
        eprintln!(
            "[smoke]   -> {} {}",
            if r.passed { "PASS" } else { "FAIL" },
            r.detail
        );
        results.push(r);
    }
    results
}

async fn run_trial(root: &Path, binary: &Path, trial: Trial) -> TrialResult {
    match trial {
        Trial::Rotating {
            group,
            nodes,
            f,
            seed,
        } => run_rotating(root, binary, &group, nodes, f, seed).await,
        Trial::KillRestart { group, seed } => run_kill_restart(root, binary, &group, seed).await,
        Trial::Disconnect {
            group,
            count,
            window,
            seed,
        } => run_disconnect(root, binary, &group, count, window, seed).await,
        Trial::GossipSteady { group, seed } => run_gossip_steady(root, binary, &group, seed).await,
        Trial::PathProbe { group } => run_path_probe(root, binary, &group).await,
        Trial::Bls { group, seed } => run_bls(root, binary, &group, seed).await,
        Trial::Footgun { group } => run_footgun(root, binary, &group).await,
        Trial::Gated { group } => run_gated(root, binary, &group).await,
        Trial::RestartDisk { group, seed } => run_restart_disk(root, binary, &group, seed).await,
        Trial::SeqKill { group, seed } => run_seqkill(root, binary, &group, seed).await,
        Trial::Partition { group, seed } => run_partition(root, binary, &group, seed).await,
    }
}

// ── shared helpers ──────────────────────────────────────────────────────────

async fn bringup(
    root: &Path,
    binary: &Path,
    group: &str,
    nodes: usize,
    seed: u64,
    scheme: SignatureSchemeChoice,
) -> anyhow::Result<(PathBuf, State)> {
    let workdir = root.join(group);
    let _ = std::fs::remove_dir_all(&workdir);
    let spec = TopologySpec {
        nodes,
        seed_extra: 0,
        target_degree: 8,
        seed,
    };
    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: workdir.clone(),
        spec,
        binary: binary.to_path_buf(),
        timeout_base_ms: 200,
        timeout_max_ms: 2_000,
        signature_scheme: scheme,
    })
    .await?;
    lifecycle::up_all(&workdir, binary, &state).await?;
    let state = State::load(&workdir)?;
    Ok((workdir, state))
}

/// On a failing trial, dump per-node status + log tails to stderr before
/// the workdir is removed — so the CI run captures the diagnostics the
/// old shell driver's `dump_fail` did, without a manual repro.
async fn dump_diagnostics(state: &State) {
    eprintln!("    --- diagnostics ---");
    match safety::verify(state) {
        Ok(v) => eprintln!("    verify-safety: {} violation(s)", v.len()),
        Err(e) => eprintln!("    verify-safety error: {e}"),
    }
    for n in &state.nodes {
        let name = n.display_name();
        let alive = lifecycle::pid_alive(n).is_some();
        let mut line = format!("    {name}: {}", if alive { "up" } else { "down" });
        if let Some(api) = n.admin_addr {
            if let Ok(Some(s)) = admin::maybe_consensus_status(api).await {
                line += &format!(
                    " height={} role={} gossip_sink_overflow={}",
                    s.last_committed_height.0,
                    s.self_role,
                    s.backpressure.gossip_sink_overflow_total
                );
            }
        }
        eprintln!("{line}");
    }
    for n in &state.nodes {
        if let Ok(content) = std::fs::read_to_string(&n.log_path) {
            let lines: Vec<&str> = content.lines().collect();
            let tail = lines.iter().rev().take(12).rev();
            eprintln!("    {} log tail:", n.display_name());
            for l in tail {
                eprintln!("      {l}");
            }
        }
    }
}

fn teardown(workdir: &Path, state: &State) {
    let _ = lifecycle::down(workdir, state);
    let _ = std::fs::remove_dir_all(workdir);
}

/// The steady-state back-pressure invariant: sample
/// `gossip_sink_overflow_total` on every reachable node twice, `BP_GAP`
/// apart. `Err` lists any node whose counter grew. Typed — no parsing.
async fn backpressure_growth(state: &State) -> Result<(), String> {
    async fn sample(state: &State) -> BTreeMap<String, u64> {
        let mut m = BTreeMap::new();
        for n in &state.nodes {
            if let Some(api) = n.admin_addr {
                if let Ok(Some(s)) = admin::maybe_consensus_status(api).await {
                    m.insert(n.display_name(), s.backpressure.gossip_sink_overflow_total);
                }
            }
        }
        m
    }
    let first = sample(state).await;
    tokio::time::sleep(BP_GAP).await;
    let second = sample(state).await;
    let mut grew = Vec::new();
    for (node, &v1) in &first {
        if let Some(&v2) = second.get(node) {
            if v2 > v1 {
                grew.push(format!("{node}:{v1}->{v2}"));
            }
        }
    }
    if grew.is_empty() {
        Ok(())
    } else {
        Err(grew.join(","))
    }
}

/// Fold a body outcome + a back-pressure outcome, dumping diagnostics
/// (before teardown) on failure.
async fn finalize(
    group: &str,
    seed: Option<u64>,
    workdir: &Path,
    state: &State,
    body: Result<String, String>,
    bp: Result<(), String>,
) -> TrialResult {
    let result = match (body, bp) {
        (Ok(detail), Ok(())) => TrialResult::pass(group, seed, detail),
        (Ok(_), Err(grew)) => TrialResult::fail(group, seed, format!("back-pressure grew: {grew}")),
        (Err(e), _) => TrialResult::fail(group, seed, e),
    };
    if !result.passed {
        dump_diagnostics(state).await;
    }
    teardown(workdir, state);
    result
}

// ── runners ─────────────────────────────────────────────────────────────────

async fn run_rotating(
    root: &Path,
    binary: &Path,
    group: &str,
    nodes: usize,
    f: usize,
    seed: u64,
) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        nodes,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body = scenario::run(&workdir, binary, scenario::rotating_failure(f, seed))
        .await
        .map(|_| format!("f={f}"))
        .map_err(|e| e.to_string());
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(seed), &workdir, &state, body, bp).await
}

async fn run_disconnect(
    root: &Path,
    binary: &Path,
    group: &str,
    count: usize,
    window: u64,
    seed: u64,
) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        7,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body = scenario::run(
        &workdir,
        binary,
        scenario::disconnect_random(count, window, seed),
    )
    .await
    .map(|_| format!("count={count}"))
    .map_err(|e| e.to_string());
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(seed), &workdir, &state, body, bp).await
}

async fn run_kill_restart(root: &Path, binary: &Path, group: &str, seed: u64) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        4,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body: Result<String, String> = async {
        wait::all_reach_height(&state, 5, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        let node2 = state.node("node2").map_err(|e| e.to_string())?.clone();
        lifecycle::kill_one(&workdir, &node2).map_err(|e| e.to_string())?;
        wait::all_advance_by(&state, 10, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        lifecycle::up_one(&workdir, binary, &node2)
            .await
            .map_err(|e| e.to_string())?;
        wait::node_caught_up(&state, &node2, 2, secs(60))
            .await
            .map_err(|e| e.to_string())?;
        let v = safety::verify(&state).map_err(|e| e.to_string())?;
        if !v.is_empty() {
            return Err(format!("{} safety violation(s)", v.len()));
        }
        let counters = telemetry::collect(&state).map_err(|e| e.to_string())?;
        let emit = counters
            .get("node2")
            .and_then(|c| c.get("block_sync_request_emitted"))
            .copied()
            .unwrap_or(0);
        let recv = state
            .nodes
            .iter()
            .filter(|n| n.display_name() != "node2")
            .filter_map(|n| {
                counters
                    .get(&n.display_name())
                    .and_then(|c| c.get("block_sync_request_received"))
            })
            .copied()
            .max()
            .unwrap_or(0);
        if emit == 0 || recv == 0 {
            return Err(format!(
                "block-sync not exercised (emit={emit} recv={recv})"
            ));
        }
        Ok(format!("emit={emit} recv={recv}"))
    }
    .await;
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(seed), &workdir, &state, body, bp).await
}

async fn run_gossip_steady(root: &Path, binary: &Path, group: &str, seed: u64) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        7,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body: Result<String, String> = async {
        wait::all_healthy(&state, 5, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        wait::all_advance_by(&state, 10, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        let v = safety::verify(&state).map_err(|e| e.to_string())?;
        if !v.is_empty() {
            return Err(format!("{} safety violation(s)", v.len()));
        }
        // No block-sync assertion here. `gossip_send_to_dispatched` only
        // ticks on point-to-point sends — block-sync request/response —
        // and a smooth steady-state run never induces block-sync (no node
        // falls behind), so the counter is legitimately zero cluster-wide.
        // Asserting it here is seed/timing-dependent. Block-sync coverage
        // lives in `run_kill_restart`, which deterministically forces it
        // by killing and restarting a node.
        Ok("steady".to_string())
    }
    .await;
    // The back-pressure invariant is the headline check for this trial.
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(seed), &workdir, &state, body, bp).await
}

/// The one trial that exercises the `testnet` CLI itself (every other
/// trial drives the library directly). It guards relative-path / cwd
/// coupling: `new` with a *relative* `--workdir` from one cwd must write
/// absolute internal paths so that `up`/`wait` from a *different* cwd
/// still resolve. A regression in the CLI's path handling breaks here.
async fn run_path_probe(root: &Path, binary: &Path, group: &str) -> TrialResult {
    use tokio::process::Command;
    let testnet = PathBuf::from(env!("CARGO_BIN_EXE_testnet"));
    let base = root.join(group);
    let _ = std::fs::remove_dir_all(&base);
    if let Err(e) = std::fs::create_dir_all(&base) {
        return TrialResult::fail(group, None, format!("mkdir: {e}"));
    }
    let abs = base.join("wd");

    let body: Result<String, String> = async {
        // `new` with a RELATIVE workdir, run from `base` as cwd.
        let st = Command::new(&testnet)
            .current_dir(&base)
            .args(["new", "--nodes", "4", "--workdir", "wd", "--boule-bin"])
            .arg(binary)
            .status()
            .await
            .map_err(|e| format!("spawn new: {e}"))?;
        if !st.success() {
            return Err(format!("`new` (relative workdir) exit {:?}", st.code()));
        }
        // `up` from a DIFFERENT cwd using the ABSOLUTE path.
        let st = Command::new(&testnet)
            .current_dir(root)
            .arg("up")
            .arg("--workdir")
            .arg(&abs)
            .arg("--boule-bin")
            .arg(binary)
            .status()
            .await
            .map_err(|e| format!("spawn up: {e}"))?;
        if !st.success() {
            return Err(format!("`up` (other cwd) exit {:?}", st.code()));
        }
        // `wait` from yet another cwd.
        let st = Command::new(&testnet)
            .current_dir(std::env::temp_dir())
            .args([
                "wait",
                "--all-reach-height",
                "5",
                "--timeout",
                "30",
                "--workdir",
            ])
            .arg(&abs)
            .status()
            .await
            .map_err(|e| format!("spawn wait: {e}"))?;
        if !st.success() {
            return Err(format!("`wait` exit {:?}", st.code()));
        }
        Ok("cli paths resolved across cwds".to_string())
    }
    .await;

    let _ = Command::new(&testnet)
        .arg("down")
        .arg("--workdir")
        .arg(&abs)
        .status()
        .await;
    let _ = std::fs::remove_dir_all(&base);

    match body {
        Ok(d) => TrialResult::pass(group, None, d),
        Err(e) => TrialResult::fail(group, None, e),
    }
}

async fn run_bls(root: &Path, binary: &Path, group: &str, seed: u64) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        4,
        seed,
        SignatureSchemeChoice::BlsAggregated,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body: Result<String, String> = async {
        wait::all_reach_height(&state, 5, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        let v = safety::verify(&state).map_err(|e| e.to_string())?;
        if !v.is_empty() {
            return Err(format!("{} safety violation(s)", v.len()));
        }
        let missing: Vec<String> = state
            .nodes
            .iter()
            .filter(|n| {
                let key = n.config_path.parent().map(|d| d.join("bls.key"));
                !key.map(|k| k.exists()).unwrap_or(false)
            })
            .map(|n| n.display_name())
            .collect();
        if !missing.is_empty() {
            return Err(format!("missing bls.key on {missing:?}"));
        }
        Ok("bls ok".to_string())
    }
    .await;
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(seed), &workdir, &state, body, bp).await
}

async fn run_footgun(root: &Path, binary: &Path, group: &str) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        7,
        7,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(7), format!("bringup: {e}")),
    };
    let scen = Scenario {
        scenario: ScenarioMeta {
            seed: Some(7),
            name: Some("footgun".into()),
        },
        steps: vec![
            Step::WaitAllReachHeight {
                height: 30,
                timeout_secs: 30,
            },
            Step::KillRandom { count: 2 },
            Step::WaitAllReachHeight {
                height: 60,
                timeout_secs: 60,
            },
            Step::VerifySafety,
        ],
    };
    let r = scenario::run(&workdir, binary, scen).await;
    teardown(&workdir, &state);
    match r {
        Err(_) => TrialResult::pass(group, Some(7), "expected-fail: wedged as documented".into()),
        Ok(_) => TrialResult::fail(
            group,
            Some(7),
            "footgun did NOT wedge — engine behaviour may have changed".into(),
        ),
    }
}

async fn run_gated(root: &Path, binary: &Path, group: &str) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        7,
        7,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(7), format!("bringup: {e}")),
    };
    let scen = Scenario {
        scenario: ScenarioMeta {
            seed: Some(7),
            name: Some("gated".into()),
        },
        steps: vec![
            Step::WaitAllHealthy {
                within: 5,
                timeout_secs: 30,
            },
            Step::WaitAllReachHeight {
                height: 30,
                timeout_secs: 30,
            },
            Step::KillRandom { count: 2 },
            Step::WaitAllReachHeight {
                height: 60,
                timeout_secs: 60,
            },
            Step::VerifySafety,
        ],
    };
    let body = scenario::run(&workdir, binary, scen)
        .await
        .map(|_| "ok".to_string())
        .map_err(|e| e.to_string());
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(7), &workdir, &state, body, bp).await
}

async fn run_restart_disk(root: &Path, binary: &Path, group: &str, seed: u64) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        4,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body: Result<String, String> = async {
        scenario::run(&workdir, binary, scenario::rotating_failure(1, seed))
            .await
            .map_err(|e| e.to_string())?;
        lifecycle::down(&workdir, &state).map_err(|e| e.to_string())?;
        lifecycle::up_all(&workdir, binary, &state)
            .await
            .map_err(|e| e.to_string())?;
        let restarted = State::load(&workdir).map_err(|e| e.to_string())?;
        wait::all_reach_height(&restarted, 50, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        let v = safety::verify(&restarted).map_err(|e| e.to_string())?;
        if !v.is_empty() {
            return Err(format!("{} safety violation(s)", v.len()));
        }
        Ok("ok".to_string())
    }
    .await;
    let bp = backpressure_growth(&state).await;
    finalize(group, Some(seed), &workdir, &state, body, bp).await
}

async fn run_seqkill(root: &Path, binary: &Path, group: &str, seed: u64) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        4,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let body: Result<String, String> = async {
        wait::all_reach_height(&state, 5, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        for name in ["node2", "node3", "node4"] {
            let n = state.node(name).map_err(|e| e.to_string())?.clone();
            lifecycle::kill_one(&workdir, &n).map_err(|e| e.to_string())?;
        }
        tokio::time::sleep(secs(30)).await;
        for name in ["node2", "node3", "node4"] {
            let n = state.node(name).map_err(|e| e.to_string())?.clone();
            lifecycle::up_one(&workdir, binary, &n)
                .await
                .map_err(|e| e.to_string())?;
        }
        let restarted = State::load(&workdir).map_err(|e| e.to_string())?;
        wait::all_advance_by(&restarted, 10, secs(120))
            .await
            .map_err(|e| e.to_string())?;
        let v = safety::verify(&restarted).map_err(|e| e.to_string())?;
        if !v.is_empty() {
            return Err(format!("{} safety violation(s)", v.len()));
        }
        Ok("recovered".to_string())
    }
    .await;
    finalize(group, Some(seed), &workdir, &state, body, Ok(())).await
}

async fn run_partition(root: &Path, binary: &Path, group: &str, seed: u64) -> TrialResult {
    let (workdir, state) = match bringup(
        root,
        binary,
        group,
        7,
        seed,
        SignatureSchemeChoice::Ed25519Collected,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return TrialResult::fail(group, Some(seed), format!("bringup: {e}")),
    };
    let res: Result<(String, bool), String> = async {
        wait::all_reach_height(&state, 5, secs(30))
            .await
            .map_err(|e| e.to_string())?;
        let killed =
            lifecycle::kill_random(&workdir, &state, 2, seed).map_err(|e| e.to_string())?;
        if wait::all_advance_by(&state, 10, secs(30)).await.is_ok() {
            let v = safety::verify(&state).map_err(|e| e.to_string())?;
            if !v.is_empty() {
                return Err(format!("healthy but {} safety violation(s)", v.len()));
            }
            return Ok(("healthy".to_string(), true));
        }
        let partitioned = survivors_partitioned(&state).await;
        let v = safety::verify(&state).map_err(|e| e.to_string())?;
        if !v.is_empty() {
            return Err(format!("wedged with {} safety violation(s)", v.len()));
        }
        if !partitioned {
            return Ok(("unpartitioned-wedge".to_string(), false));
        }
        for idx in &killed {
            let n = state.nodes[*idx].clone();
            let _ = lifecycle::up_one(&workdir, binary, &n).await;
        }
        let restarted = State::load(&workdir).map_err(|e| e.to_string())?;
        if wait::all_advance_by(&restarted, 5, secs(60)).await.is_ok() {
            let v = safety::verify(&restarted).map_err(|e| e.to_string())?;
            if !v.is_empty() {
                return Err(format!("recovered with {} safety violation(s)", v.len()));
            }
            Ok(("partitioned-recovered".to_string(), true))
        } else {
            Ok(("partitioned-not-recovered".to_string(), false))
        }
    }
    .await;
    let result = match res {
        Ok((branch, passed)) => TrialResult {
            group: group.to_string(),
            seed: Some(seed),
            passed,
            detail: branch,
        },
        Err(e) => TrialResult::fail(group, Some(seed), e),
    };
    if !result.passed {
        dump_diagnostics(&state).await;
    }
    teardown(&workdir, &state);
    result
}

/// BFS over `/peers` among the live survivors. Returns `true` if the
/// survivor subgraph is partitioned (not all reachable from one start).
async fn survivors_partitioned(state: &State) -> bool {
    let id2name: BTreeMap<String, String> = state
        .nodes
        .iter()
        .filter_map(|n| n.node_id.clone().map(|id| (id, n.display_name())))
        .collect();
    let survivors: Vec<_> = state
        .nodes
        .iter()
        .filter(|n| lifecycle::pid_alive(n).is_some())
        .collect();
    let names: BTreeSet<String> = survivors.iter().map(|n| n.display_name()).collect();
    if names.len() <= 1 {
        return false;
    }
    let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for n in &survivors {
        let me = n.display_name();
        adj.entry(me.clone()).or_default();
        if let Some(api) = n.admin_addr {
            if let Ok(Some(peers)) = admin::maybe_peers(api).await {
                for pid in peers {
                    if let Some(pname) = id2name.get(&pid) {
                        if names.contains(pname) {
                            adj.entry(me.clone()).or_default().insert(pname.clone());
                            adj.entry(pname.clone()).or_default().insert(me.clone());
                        }
                    }
                }
            }
        }
    }
    let start = survivors[0].display_name();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut q: VecDeque<String> = VecDeque::new();
    seen.insert(start.clone());
    q.push_back(start);
    while let Some(cur) = q.pop_front() {
        if let Some(neighbours) = adj.get(&cur) {
            for nb in neighbours {
                if seen.insert(nb.clone()) {
                    q.push_back(nb.clone());
                }
            }
        }
    }
    seen.len() < names.len()
}

// ── the cadence sweep (ignored: run on schedule / label, never in the PR gate) ──

#[tokio::test(flavor = "multi_thread")]
#[ignore = "heavy multi-process smoke sweep; run on cadence via `-- --ignored` (see smoke.yml)"]
async fn smoke_sweep() {
    let tier_str = std::env::var("SMOKE_TIER").unwrap_or_else(|_| "full".into());
    let tier = Tier::parse(&tier_str).unwrap_or_else(|e| panic!("SMOKE_TIER: {e}"));
    let root = std::env::temp_dir().join(format!("boule-smoke-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&root);

    let results = run_smoke(tier, &root, &boule_bin()).await;
    let _ = std::fs::remove_dir_all(&root);
    print_table(tier, &results);

    let failed: Vec<&TrialResult> = results.iter().filter(|r| !r.passed).collect();
    assert!(
        failed.is_empty(),
        "{} smoke trial(s) failed: {}",
        failed.len(),
        failed
            .iter()
            .map(|t| format!("{}(seed={:?}): {}", t.group, t.seed, t.detail))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

// ── fast structural guards (run in the normal gate; no clusters) ─────────────

#[test]
fn full_matrix_is_the_65_trial_sweep() {
    assert_eq!(matrix(Tier::Full).len(), 65);
}

#[test]
fn tier_parses_names_and_minutes() {
    assert_eq!(Tier::parse("quick").unwrap(), Tier::Quick);
    assert_eq!(Tier::parse("90").unwrap(), Tier::Full);
    assert!(Tier::parse("bogus").is_err());
}

#[test]
fn tier_sizes_are_as_documented() {
    assert_eq!(matrix(Tier::Quick).len(), 6);
    assert_eq!(matrix(Tier::Standard).len(), 20);
    assert!(matrix(Tier::Extended).len() > matrix(Tier::Standard).len());
}
