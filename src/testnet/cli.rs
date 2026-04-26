//! Argument parser + dispatcher for the `testnet` binary.
//!
//! Parses argv and routes to the testnet driver lib functions in the
//! sibling modules. Mirrors the no-clap style used by `src/main.rs` so
//! the surface stays consistent between the two binaries.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;

use super::admin;
use super::topology::TopologySpec;
use super::workdir::State;
use super::{events, lifecycle, safety, scenario, telemetry, wait};

/// Default workdir when `--workdir` is omitted.
const DEFAULT_WORKDIR: &str = "./testnet";
/// Default per-step wait timeout for `wait` and scenarios.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 30;
/// Default consensus pacemaker base timeout (smaller than the
/// production default so smoke tests commit quickly).
const DEFAULT_TIMEOUT_BASE_MS: u64 = 200;
const DEFAULT_TIMEOUT_MAX_MS: u64 = 2_000;

/// Top-level entry point. Returns `Ok(())` on success; the binary
/// translates `Err` into a non-zero exit status.
pub async fn dispatch(args: &[String]) -> anyhow::Result<()> {
    let first = match args.first().map(String::as_str) {
        Some(s) => s,
        None => {
            print_usage();
            anyhow::bail!("missing subcommand");
        }
    };
    match first {
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "new" => cmd_new(&args[1..]).await,
        "up" => cmd_up(&args[1..]).await,
        "down" => cmd_down(&args[1..]),
        "kill" => cmd_kill(&args[1..]),
        "ls" => cmd_ls(&args[1..]).await,
        "info" => cmd_info(&args[1..]).await,
        "logs" => cmd_logs(&args[1..]),
        "snap" => cmd_snap(&args[1..]).await,
        "wait" => cmd_wait(&args[1..]).await,
        "verify-safety" => cmd_verify_safety(&args[1..]),
        "telemetry" => cmd_telemetry(&args[1..]),
        "scenario" => cmd_scenario(&args[1..]).await,
        other => {
            print_usage();
            anyhow::bail!("unknown subcommand '{other}'");
        }
    }
}

fn print_usage() {
    println!("Usage: testnet <subcommand> [options]");
    println!();
    println!("Subcommands:");
    println!("  new    --nodes N [--seed-extra K] [--target-degree T]");
    println!("         [--seed S] [--workdir DIR] [--ambros-bin PATH]");
    println!("         [--timeout-base-ms MS] [--timeout-max-ms MS]");
    println!("           Generate a workdir + per-node configs and mint identities.");
    println!();
    println!("  up [<node>] [--workdir DIR] [--ambros-bin PATH]");
    println!("           Spawn every node (or just <node>) listed in state.json.");
    println!();
    println!("  down [--workdir DIR]");
    println!("           SIGTERM every live node, escalate to SIGKILL after 3s.");
    println!();
    println!("  kill (<node> | --random [N] [--seed S]) [--workdir DIR]");
    println!("           SIGKILL one or more nodes (--random picks reproducibly).");
    println!();
    println!("  ls [--workdir DIR]");
    println!("           Tabulate every node: id, p2p addr, api addr, peers, status.");
    println!();
    println!("  info <node> [peers] [--workdir DIR]");
    println!("           /consensus/status, or /peers when 'peers' is appended.");
    println!();
    println!("  logs <node> [--tail [N]] [--workdir DIR]");
    println!("           Dump the per-node log file (or the last N lines).");
    println!();
    println!("  snap [--workdir DIR] [--json]");
    println!("           Per-node commit/height/peers snapshot.");
    println!();
    println!("  wait (--all-reach-height N");
    println!("        | --all-healthy [--within W]");
    println!("        | --node X --catch-up-to-cluster [--tolerance T]");
    println!("        | --quiescent --for SECS) [--timeout SECS] [--workdir DIR]");
    println!();
    println!("  verify-safety [--workdir DIR]");
    println!("           Cross-node (height,view) consistency check. Exit non-zero on violation.");
    println!();
    println!("  telemetry [--workdir DIR]");
    println!("           Per-node tally of well-known consensus/block-sync counters.");
    println!();
    println!("  scenario [--workdir DIR] [--ambros-bin PATH] [--seed S] (");
    println!("    rotating-failure --f F");
    println!("    | rotating-failure-7n-f2");
    println!("    | disconnect-random --count N --restart-after Ns");
    println!("    | reconnect <node>");
    println!("    | --file PATH");
    println!("  )");
    println!("           Run a built-in or TOML-file-defined scenario. Auto-brings");
    println!("           the cluster up if needed; ctrl-c tears it down cleanly.");
    println!();
    println!("If --workdir is omitted, '{DEFAULT_WORKDIR}' is used.");
    println!("If --ambros-bin is omitted, the binary is searched next to the testnet exe.");
}

// ── Shared option parsing ───────────────────────────────────────────────────

fn pop_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> anyhow::Result<&'a str> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn parse_workdir(args: &[String]) -> anyhow::Result<(PathBuf, Vec<String>)> {
    let mut wd: Option<PathBuf> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workdir" => {
                let v = pop_value(args, &mut i, "--workdir")?;
                wd = Some(PathBuf::from(v));
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    Ok((wd.unwrap_or_else(|| PathBuf::from(DEFAULT_WORKDIR)), rest))
}

fn parse_ambros_bin(args: &[String]) -> anyhow::Result<(Option<PathBuf>, Vec<String>)> {
    let mut bin: Option<PathBuf> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ambros-bin" => {
                let v = pop_value(args, &mut i, "--ambros-bin")?;
                bin = Some(PathBuf::from(v));
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    Ok((bin, rest))
}

/// Locate the `ambros-p2p` binary. If `explicit` is provided, use it.
/// Otherwise look next to the current executable (the typical layout for
/// both `cargo run --bin testnet` and a release build), and finally fall
/// back to PATH lookup via the bare `ambros-p2p` name so an installed
/// build still works.
fn resolve_ambros_bin(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.exists() {
            anyhow::bail!("--ambros-bin {} does not exist", p.display());
        }
        return Ok(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join(if cfg!(windows) {
                "ambros-p2p.exe"
            } else {
                "ambros-p2p"
            });
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    // PATH fallback. We don't try to resolve eagerly — Command will
    // exec via PATH and surface a clear error if it's missing.
    Ok(PathBuf::from("ambros-p2p"))
}

// ── `new` ───────────────────────────────────────────────────────────────────

async fn cmd_new(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let (ambros_bin, rest) = parse_ambros_bin(&rest)?;
    let mut nodes: Option<usize> = None;
    let mut seed_extra: usize = 0;
    let mut target_degree: Option<usize> = None;
    let mut seed: u64 = 0;
    let mut timeout_base_ms: u64 = DEFAULT_TIMEOUT_BASE_MS;
    let mut timeout_max_ms: u64 = DEFAULT_TIMEOUT_MAX_MS;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--nodes" => nodes = Some(pop_value(&rest, &mut i, "--nodes")?.parse()?),
            "--seed-extra" => seed_extra = pop_value(&rest, &mut i, "--seed-extra")?.parse()?,
            "--target-degree" => {
                target_degree = Some(pop_value(&rest, &mut i, "--target-degree")?.parse()?)
            }
            "--seed" => seed = pop_value(&rest, &mut i, "--seed")?.parse()?,
            "--timeout-base-ms" => {
                timeout_base_ms = pop_value(&rest, &mut i, "--timeout-base-ms")?.parse()?
            }
            "--timeout-max-ms" => {
                timeout_max_ms = pop_value(&rest, &mut i, "--timeout-max-ms")?.parse()?
            }
            other => anyhow::bail!("unknown `new` flag: {other}"),
        }
        i += 1;
    }
    let nodes = nodes.ok_or_else(|| anyhow::anyhow!("`new` requires --nodes <N>"))?;
    // Match `OverlayConfig::default().target_degree` when --target-degree
    // is omitted. The issue's k+3 minimum applies only when the operator
    // is sweeping a sparse-mesh preset; the default for casual `new`
    // invocations should keep enough redundancy that killing 2 nodes in
    // a 7-node cluster doesn't partition the survivors.
    let target_degree = target_degree.unwrap_or(8);
    let spec = TopologySpec {
        nodes,
        seed_extra,
        target_degree,
        seed,
    };
    let binary = resolve_ambros_bin(ambros_bin)?;
    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: workdir.clone(),
        spec,
        binary,
        timeout_base_ms,
        timeout_max_ms,
    })
    .await?;
    println!(
        "wrote {} nodes to {} (seed={seed}, seed_extra={seed_extra}, target_degree={target_degree})",
        state.nodes.len(),
        workdir.display()
    );
    println!("next: testnet up --workdir {}", workdir.display());
    Ok(())
}

// ── `up` ────────────────────────────────────────────────────────────────────

async fn cmd_up(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let (ambros_bin, rest) = parse_ambros_bin(&rest)?;
    let state = State::load(&workdir)?;
    let binary = resolve_ambros_bin(ambros_bin)?;

    if rest.is_empty() {
        let pids = lifecycle::up_all(&workdir, &binary, &state).await?;
        if pids.is_empty() {
            println!("up: every node was already running");
        } else {
            println!("up: spawned {} node(s)", pids.len());
        }
        return Ok(());
    }
    if rest.len() != 1 {
        anyhow::bail!("`up` takes at most one node argument; got {:?}", rest);
    }
    let layout = state.node(&rest[0])?.clone();
    if lifecycle::pid_alive(&layout).is_some() {
        println!("up: {} already running", layout.display_name());
        return Ok(());
    }
    let pid = lifecycle::up_one(&workdir, &binary, &layout).await?;
    println!("up: {} pid={pid}", layout.display_name());
    Ok(())
}

// ── `down` ──────────────────────────────────────────────────────────────────

fn cmd_down(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    if !rest.is_empty() {
        anyhow::bail!("`down` takes no positional args; got {:?}", rest);
    }
    let state = State::load(&workdir)?;
    lifecycle::down(&workdir, &state)?;
    println!("down: cluster torn down");
    Ok(())
}

// ── `kill` ──────────────────────────────────────────────────────────────────

fn cmd_kill(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let state = State::load(&workdir)?;

    let mut random = false;
    let mut count: usize = 1;
    let mut seed: u64 = 0;
    let mut node: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--random" => {
                random = true;
                if let Some(next) = rest.get(i + 1) {
                    if next.parse::<usize>().is_ok() {
                        count = next.parse()?;
                        i += 1;
                    }
                }
            }
            "--seed" => seed = pop_value(&rest, &mut i, "--seed")?.parse()?,
            other if !other.starts_with("--") => {
                if node.is_some() {
                    anyhow::bail!("`kill` accepts only one node argument; got extra {other:?}");
                }
                node = Some(other.to_string());
            }
            other => anyhow::bail!("unknown `kill` flag: {other}"),
        }
        i += 1;
    }
    if random {
        if node.is_some() {
            anyhow::bail!("`kill` cannot combine --random with a positional node");
        }
        let killed = lifecycle::kill_random(&workdir, &state, count, seed)?;
        let names: Vec<String> = killed
            .iter()
            .map(|i| state.nodes[*i].display_name())
            .collect();
        println!("kill --random: {}", names.join(", "));
        return Ok(());
    }
    let node = node.ok_or_else(|| anyhow::anyhow!("`kill` requires a node or --random"))?;
    let layout = state.node(&node)?.clone();
    lifecycle::kill_one(&workdir, &layout)?;
    println!("kill: {}", layout.display_name());
    Ok(())
}

// ── `ls` ────────────────────────────────────────────────────────────────────

async fn cmd_ls(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    if !rest.is_empty() {
        anyhow::bail!("`ls` takes no positional args; got {:?}", rest);
    }
    let state = State::load(&workdir)?;
    // Columns:
    //   - boot: number of `[[peers]]` bootstrap entries written by `new`
    //   - peers: realized direct-peer count from /peers (live nodes only;
    //     "-" when the node is down, "?" when the API is unreachable).
    //
    // The bootstrap count is what gets configured at boot; the realized
    // count is what the gossip overlay actually maintains. Showing both
    // makes it obvious whether `target_degree` is being honored without
    // chasing down /peers per-node.
    println!(
        "{:>7}  {:<46}  {:<22}  {:<22}  {:<10}  {:>4}  {:>5}",
        "node", "node_id", "p2p", "api", "status", "boot", "peers"
    );
    for n in &state.nodes {
        let pid = lifecycle::pid_alive(n);
        let status = match pid {
            Some(p) => format!("up({p})"),
            None => "down".to_string(),
        };
        let id_short = n
            .node_id
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let p2p = n
            .p2p_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".into());
        let api = n
            .api_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".into());
        let live_peers = match (pid, n.api_addr) {
            (Some(_), Some(addr)) => match admin::maybe_peers(addr).await? {
                Some(v) => v.len().to_string(),
                None => "?".into(),
            },
            _ => "-".into(),
        };
        println!(
            "{:>7}  {:<46}  {:<22}  {:<22}  {:<10}  {:>4}  {:>5}",
            n.display_name(),
            id_short,
            p2p,
            api,
            status,
            n.bootstrap_peers.len(),
            live_peers,
        );
    }
    Ok(())
}

// ── `info` ──────────────────────────────────────────────────────────────────

async fn cmd_info(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let state = State::load(&workdir)?;
    let mut node: Option<&str> = None;
    let mut want_peers = false;
    for a in &rest {
        match a.as_str() {
            "peers" => want_peers = true,
            other if !other.starts_with("--") && node.is_none() => node = Some(other),
            other => anyhow::bail!("unknown `info` arg: {other}"),
        }
    }
    let node_name = node.ok_or_else(|| anyhow::anyhow!("`info` requires a node argument"))?;
    let layout = state.node(node_name)?;
    let api = layout
        .api_addr
        .ok_or_else(|| anyhow::anyhow!("{} has no recorded api addr", layout.display_name()))?;
    if want_peers {
        let peers = admin::peers(api).await?;
        println!("{} /peers ({} direct):", layout.display_name(), peers.len());
        for p in peers {
            println!("  {p}");
        }
    } else {
        let s = admin::consensus_status(api).await?;
        println!("{}: /consensus/status", layout.display_name());
        println!("  node_id              {}", s.node_id);
        println!("  self_role            {}", s.self_role);
        println!("  current_view         {}", s.current_view);
        println!("  last_voted_view      {}", s.last_voted_view);
        println!("  last_committed_height {}", s.last_committed_height);
        println!("  last_committed_view  {}", s.last_committed_view);
        if let Some(l) = &s.locked {
            println!("  locked               view={} height={}", l.view, l.height);
        }
        if let Some(h) = &s.high_qc {
            println!(
                "  high_qc              view={} height={}",
                h.view,
                fmt_opt(h.height)
            );
        }
        println!("  peers_connected      {}", s.peers_connected.len());
        println!("  validator_set        {}", s.validator_set.len());
        println!("  parked_proposals     {}", s.parked_proposals.len());
        println!("  pending_blocks       {}", s.pending_blocks_count);
        println!("  mempool              {}", s.mempool_size);
    }
    Ok(())
}

// ── `logs` ──────────────────────────────────────────────────────────────────

fn cmd_logs(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let state = State::load(&workdir)?;
    let mut node: Option<&str> = None;
    let mut tail: Option<usize> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--tail" => {
                // Optional N; default 80 when --tail with no value.
                if let Some(next) = rest.get(i + 1) {
                    if let Ok(n) = next.parse::<usize>() {
                        tail = Some(n);
                        i += 1;
                    } else {
                        tail = Some(80);
                    }
                } else {
                    tail = Some(80);
                }
            }
            other if !other.starts_with("--") && node.is_none() => node = Some(other),
            other => anyhow::bail!("unknown `logs` arg: {other}"),
        }
        i += 1;
    }
    let node_name = node.ok_or_else(|| anyhow::anyhow!("`logs` requires a node argument"))?;
    let layout = state.node(node_name)?;
    let bytes = std::fs::read(&layout.log_path)
        .with_context(|| format!("reading {}", layout.log_path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    if let Some(n) = tail {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(n);
        for line in &lines[start..] {
            println!("{line}");
        }
    } else {
        print!("{text}");
    }
    Ok(())
}

// ── `snap` ──────────────────────────────────────────────────────────────────

async fn cmd_snap(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let mut as_json = false;
    for a in &rest {
        match a.as_str() {
            "--json" => as_json = true,
            other => anyhow::bail!("unknown `snap` flag: {other}"),
        }
    }
    let state = State::load(&workdir)?;
    let mut rows: Vec<SnapRow> = Vec::with_capacity(state.nodes.len());
    for n in &state.nodes {
        let pid = lifecycle::pid_alive(n);
        let mut row = SnapRow {
            node: n.display_name(),
            status: match pid {
                Some(p) => format!("up({p})"),
                None => "down".into(),
            },
            current_view: None,
            last_committed_height: None,
            peers_connected: None,
            self_role: None,
        };
        if let (Some(_pid), Some(api)) = (pid, n.api_addr) {
            if let Some(s) = admin::maybe_consensus_status(api).await? {
                row.current_view = Some(s.current_view);
                row.last_committed_height = Some(s.last_committed_height);
                row.peers_connected = Some(s.peers_connected.len());
                row.self_role = Some(s.self_role);
            }
        }
        rows.push(row);
    }
    if as_json {
        let v: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "node": r.node,
                    "status": r.status,
                    "current_view": r.current_view,
                    "last_committed_height": r.last_committed_height,
                    "peers_connected": r.peers_connected,
                    "self_role": r.self_role,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!(
            "{:>7}  {:<10}  {:>5}  {:>7}  {:>5}  role",
            "node", "status", "view", "height", "peers"
        );
        for r in &rows {
            println!(
                "{:>7}  {:<10}  {:>5}  {:>7}  {:>5}  {}",
                r.node,
                r.status,
                fmt_opt(r.current_view),
                fmt_opt(r.last_committed_height),
                fmt_opt_usize(r.peers_connected),
                r.self_role.as_deref().unwrap_or("-")
            );
        }
    }
    Ok(())
}

struct SnapRow {
    node: String,
    status: String,
    current_view: Option<u64>,
    last_committed_height: Option<u64>,
    peers_connected: Option<usize>,
    self_role: Option<String>,
}

fn fmt_opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}
fn fmt_opt_usize(v: Option<usize>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

// ── `wait` ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct WaitArgs {
    all_reach_height: Option<u64>,
    all_healthy: bool,
    within: u64,
    catch_up_to_cluster: bool,
    tolerance: u64,
    quiescent: bool,
    quiescent_for_secs: u64,
    node: Option<String>,
    timeout_secs: u64,
}

async fn cmd_wait(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let state = State::load(&workdir)?;
    let mut a = WaitArgs {
        within: 5,
        tolerance: 2,
        timeout_secs: DEFAULT_WAIT_TIMEOUT_SECS,
        ..Default::default()
    };
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--all-reach-height" => {
                a.all_reach_height = Some(pop_value(&rest, &mut i, "--all-reach-height")?.parse()?)
            }
            "--all-healthy" => a.all_healthy = true,
            "--within" => a.within = pop_value(&rest, &mut i, "--within")?.parse()?,
            "--node" => a.node = Some(pop_value(&rest, &mut i, "--node")?.to_string()),
            "--catch-up-to-cluster" => a.catch_up_to_cluster = true,
            "--tolerance" => a.tolerance = pop_value(&rest, &mut i, "--tolerance")?.parse()?,
            "--quiescent" => a.quiescent = true,
            "--for" => a.quiescent_for_secs = pop_value(&rest, &mut i, "--for")?.parse()?,
            "--timeout" => a.timeout_secs = pop_value(&rest, &mut i, "--timeout")?.parse()?,
            other => anyhow::bail!("unknown `wait` flag: {other}"),
        }
        i += 1;
    }
    let timeout = Duration::from_secs(a.timeout_secs);
    let modes = (a.all_reach_height.is_some() as u8)
        + (a.all_healthy as u8)
        + (a.catch_up_to_cluster as u8)
        + (a.quiescent as u8);
    if modes != 1 {
        anyhow::bail!(
            "`wait` requires exactly one of --all-reach-height / --all-healthy / --catch-up-to-cluster / --quiescent"
        );
    }
    if let Some(h) = a.all_reach_height {
        wait::all_reach_height(&state, h, timeout).await?;
        println!("wait: every live node committed height>={h}");
    } else if a.all_healthy {
        wait::all_healthy(&state, a.within, timeout).await?;
        println!("wait: cluster healthy (views within {})", a.within);
    } else if a.catch_up_to_cluster {
        let node_name = a
            .node
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--catch-up-to-cluster requires --node <name>"))?;
        let layout = state.node(node_name)?.clone();
        wait::node_caught_up(&state, &layout, a.tolerance, timeout).await?;
        println!(
            "wait: {} caught up within {}",
            layout.display_name(),
            a.tolerance
        );
    } else if a.quiescent {
        if a.quiescent_for_secs == 0 {
            anyhow::bail!("--quiescent requires --for <secs>");
        }
        let hold = Duration::from_secs(a.quiescent_for_secs);
        let outer = Duration::from_secs(a.timeout_secs.max(a.quiescent_for_secs + 5));
        wait::quiescent(&state, hold, outer).await?;
        println!("wait: cluster quiescent for {}s", a.quiescent_for_secs);
    }
    Ok(())
}

// ── `verify-safety` ─────────────────────────────────────────────────────────

fn cmd_verify_safety(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    if !rest.is_empty() {
        anyhow::bail!("`verify-safety` takes no positional args; got {:?}", rest);
    }
    let state = State::load(&workdir)?;
    let violations = safety::verify(&state)?;
    if violations.is_empty() {
        println!("verify-safety: 0 violations");
        return Ok(());
    }
    println!("verify-safety: {} violation(s):", violations.len());
    for v in &violations {
        let pairs: Vec<String> = v
            .views_by_node
            .iter()
            .map(|(n, view)| format!("{n}=view{view}"))
            .collect();
        println!("  height={}: {}", v.height, pairs.join(", "));
    }
    anyhow::bail!("safety violations detected");
}

// ── `telemetry` ─────────────────────────────────────────────────────────────

fn cmd_telemetry(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    if !rest.is_empty() {
        anyhow::bail!("`telemetry` takes no positional args; got {:?}", rest);
    }
    let state = State::load(&workdir)?;
    let table: BTreeMap<String, telemetry::NodeCounters> = telemetry::collect(&state)?;
    let header = std::iter::once("node".to_string())
        .chain(telemetry::COUNTERS.iter().map(|c| (*c).to_string()))
        .collect::<Vec<_>>();
    println!("{}", header.join("\t"));
    for (name, counters) in &table {
        let mut row = vec![name.clone()];
        for c in telemetry::COUNTERS {
            row.push(counters.get(*c).copied().unwrap_or(0).to_string());
        }
        println!("{}", row.join("\t"));
    }
    Ok(())
}

// ── `scenario` ──────────────────────────────────────────────────────────────

async fn cmd_scenario(args: &[String]) -> anyhow::Result<()> {
    let (workdir, rest) = parse_workdir(args)?;
    let (ambros_bin, rest) = parse_ambros_bin(&rest)?;

    let mut seed: u64 = 0;
    let mut file: Option<PathBuf> = None;
    let mut kind: Option<String> = None;
    let mut f_count: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut restart_after_secs: u64 = 5;
    let mut node: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--seed" => seed = pop_value(&rest, &mut i, "--seed")?.parse()?,
            "--file" => file = Some(PathBuf::from(pop_value(&rest, &mut i, "--file")?)),
            "--f" => f_count = Some(pop_value(&rest, &mut i, "--f")?.parse()?),
            "--count" => count = Some(pop_value(&rest, &mut i, "--count")?.parse()?),
            "--restart-after" => {
                let v = pop_value(&rest, &mut i, "--restart-after")?;
                restart_after_secs = parse_secs(v)?;
            }
            other if !other.starts_with("--") => {
                if kind.is_none() {
                    kind = Some(other.to_string());
                } else if node.is_none() {
                    node = Some(other.to_string());
                } else {
                    anyhow::bail!("unexpected positional arg for scenario: {other}");
                }
            }
            other => anyhow::bail!("unknown `scenario` flag: {other}"),
        }
        i += 1;
    }

    let scen = if let Some(path) = file {
        scenario::load(&path)
            .with_context(|| format!("loading scenario file {}", path.display()))?
    } else {
        let kind = kind.ok_or_else(|| {
            anyhow::anyhow!("`scenario` requires a built-in name or --file <path>")
        })?;
        match kind.as_str() {
            "rotating-failure" => {
                let f = f_count
                    .ok_or_else(|| anyhow::anyhow!("rotating-failure requires --f <count>"))?;
                scenario::rotating_failure(f, seed)
            }
            "rotating-failure-7n-f2" => scenario::rotating_failure_7n_f2(seed),
            "disconnect-random" => {
                let count = count
                    .ok_or_else(|| anyhow::anyhow!("disconnect-random requires --count <N>"))?;
                scenario::disconnect_random(count, restart_after_secs, seed)
            }
            "reconnect" => {
                let node =
                    node.ok_or_else(|| anyhow::anyhow!("reconnect requires a <node> argument"))?;
                scenario::reconnect_with_catchup(&node)
            }
            other => anyhow::bail!("unknown built-in scenario: {other}"),
        }
    };

    // Bring the cluster up if it isn't already, so a single `testnet
    // scenario ...` invocation works from a fresh `new`.
    let binary = resolve_ambros_bin(ambros_bin)?;
    let state = State::load(&workdir)?;
    let pids = lifecycle::up_all(&workdir, &binary, &state).await?;
    if !pids.is_empty() {
        println!("scenario: spawned {} node(s); cluster is up", pids.len());
    }

    // Reload state — `up_all` doesn't mutate it but the scenario engine
    // does between steps.
    let state = State::load(&workdir)?;
    events::record(
        &workdir,
        "scenario_start",
        None,
        Some(&format!(
            "name={:?} seed={seed}",
            scen.scenario.name.as_deref().unwrap_or("file")
        )),
    );

    // Drop guard: if the runtime aborts mid-scenario (panic, ctrl-c
    // routed through the ScenarioGuard set up by main), leave the
    // cluster torn down rather than zombie.
    let mut guard = ScenarioGuard::arm(workdir.clone(), state.clone());
    let outcomes = scenario::run(&workdir, &binary, scen.clone()).await;
    guard.disarm();

    match outcomes {
        Ok(steps) => {
            for o in steps {
                println!("  ok: {} {}", o.op, o.detail);
            }
            println!("scenario: complete");
            Ok(())
        }
        Err(e) => {
            // Best-effort cleanup so a failed scenario doesn't leave
            // zombies for the next run.
            let _ = lifecycle::down(&workdir, &state);
            Err(e)
        }
    }
}

fn parse_secs(s: &str) -> anyhow::Result<u64> {
    let trimmed = s.trim_end_matches('s');
    Ok(trimmed.parse()?)
}

/// Tear the cluster down on `Drop` unless explicitly disarmed. Used to
/// guarantee scenario crashes don't leave zombie node processes behind.
pub struct ScenarioGuard {
    workdir: PathBuf,
    state: State,
    armed: bool,
}

impl ScenarioGuard {
    pub fn arm(workdir: PathBuf, state: State) -> Self {
        Self {
            workdir,
            state,
            armed: true,
        }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
    }
    pub fn disarm_into_state(mut self) -> State {
        self.armed = false;
        self.state.clone()
    }
}

impl Drop for ScenarioGuard {
    fn drop(&mut self) {
        if self.armed {
            // Best effort — we're already in an unwinding/abort path.
            let _ = lifecycle::down(&self.workdir, &self.state);
        }
    }
}

/// Entry point used by `src/bin/testnet.rs` after parsing global flags.
/// Routes ctrl-c so that scenario commands tear the cluster down before
/// the process exits.
pub async fn run_with_signal_handling(args: &[String]) -> anyhow::Result<()> {
    // Spawn a ctrl-c watcher that calls `down` against the workdir
    // currently in use, then exits the process. We resolve the workdir
    // by snooping `--workdir` out of argv (defaulting to DEFAULT_WORKDIR);
    // this is best-effort — non-scenario commands are short-lived so
    // there's nothing to clean up.
    let (workdir, _rest) = parse_workdir_for_signal(args);
    let workdir_for_signal = workdir.clone();
    let _watcher = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            // Try to load state; if the workdir doesn't have one (e.g.
            // ctrl-c during `new` mid-discovery), just exit.
            if let Ok(state) = State::load(&workdir_for_signal) {
                let _ = lifecycle::down(&workdir_for_signal, &state);
            }
            std::process::exit(130);
        }
    });
    dispatch(args).await
}

/// Best-effort `--workdir` extraction for the signal handler. Mirrors
/// `parse_workdir` but never fails — we don't want a malformed argv to
/// crash the watcher before we've even entered dispatch.
fn parse_workdir_for_signal(args: &[String]) -> (PathBuf, ()) {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == "--workdir" {
            if let Some(v) = iter.next() {
                return (PathBuf::from(v), ());
            }
        }
    }
    (PathBuf::from(DEFAULT_WORKDIR), ())
}

#[allow(dead_code)]
fn _ensure_path_used(p: &Path) -> &Path {
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_workdir_strips_flag_only() {
        let args = vec![
            "--workdir".into(),
            "/tmp/foo".into(),
            "--nodes".into(),
            "4".into(),
        ];
        let (wd, rest) = parse_workdir(&args).unwrap();
        assert_eq!(wd, PathBuf::from("/tmp/foo"));
        assert_eq!(rest, vec!["--nodes".to_string(), "4".to_string()]);
    }

    #[test]
    fn parse_workdir_default() {
        let (wd, _) = parse_workdir(&[]).unwrap();
        assert_eq!(wd, PathBuf::from(DEFAULT_WORKDIR));
    }

    #[test]
    fn parse_secs_accepts_both_forms() {
        assert_eq!(parse_secs("3").unwrap(), 3);
        assert_eq!(parse_secs("15s").unwrap(), 15);
    }
}
