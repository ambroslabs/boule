//! Wait-for-condition primitives backed by polling the admin API.
//!
//! Each predicate is `async fn(&State) -> bool` so it can be composed
//! into the same driver loop the CLI's `wait` subcommand and the
//! scenario runner share.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::admin;
use super::workdir::{NodeLayout, State};

/// How long to sleep between polls. Short enough that small clusters
/// converge quickly, long enough that the driver isn't a CPU hog.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Poll `predicate` until it returns `true` or `timeout` elapses.
pub async fn poll_until<F, Fut>(timeout: Duration, mut predicate: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<bool>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if predicate().await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("wait timed out after {timeout:?}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// `--all-reach-height N`: every live node has `last_committed_height >= height`.
/// Dead nodes (no pid file) are skipped — semantics match `testnet ls`.
pub async fn all_reach_height(state: &State, height: u64, timeout: Duration) -> anyhow::Result<()> {
    poll_until(timeout, || async {
        let live = live_nodes(state);
        if live.is_empty() {
            return Ok(false);
        }
        for n in live {
            let api = match n.api_addr {
                Some(a) => a,
                None => return Ok(false),
            };
            match admin::maybe_consensus_status(api).await? {
                Some(s) if s.last_committed_height >= height => continue,
                _ => return Ok(false),
            }
        }
        Ok(true)
    })
    .await
}

/// `--all-advance-by N`: snapshot every live node's current
/// `last_committed_height`, then wait until every still-live node has
/// committed at least `delta` blocks beyond its baseline.
///
/// Unlike [`all_reach_height`], which is satisfied as soon as a target
/// height is met (and is therefore vacuous if the cluster already
/// reached the target before the wait started), this gates on *new*
/// progress relative to the moment the wait began. That's what the
/// `§9a` manual-reconnect recipe and post-kill liveness checks really
/// want — "did the survivors keep advancing?".
///
/// Nodes that go down during the wait are dropped from the gating
/// set (matching `live_nodes`'s pid_alive filter). Nodes that come
/// back from the dead during the wait are skipped — they have no
/// baseline to compare against.
pub async fn all_advance_by(state: &State, delta: u64, timeout: Duration) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut targets: Option<HashMap<usize, u64>> = None;
    loop {
        if started.elapsed() > timeout {
            anyhow::bail!("wait advance_by({delta}) timed out after {timeout:?}");
        }
        let live = live_nodes(state);
        if live.is_empty() {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        if targets.is_none() {
            // Try to capture a baseline. Skip and retry if any live
            // node refuses the connection or is missing api_addr —
            // we want every gated node to have a baseline.
            let mut snap: HashMap<usize, u64> = HashMap::new();
            let mut all_reachable = true;
            for n in &live {
                let api = match n.api_addr {
                    Some(a) => a,
                    None => {
                        all_reachable = false;
                        break;
                    }
                };
                match admin::maybe_consensus_status(api).await? {
                    Some(s) => {
                        snap.insert(n.index, s.last_committed_height.saturating_add(delta));
                    }
                    None => {
                        all_reachable = false;
                        break;
                    }
                }
            }
            if all_reachable {
                targets = Some(snap);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        let targets_ref = targets.as_ref().unwrap();
        let mut all_advanced = true;
        for n in &live {
            // Nodes that weren't live at snapshot time aren't gated.
            let target = match targets_ref.get(&n.index) {
                Some(t) => *t,
                None => continue,
            };
            let api = match n.api_addr {
                Some(a) => a,
                None => {
                    all_advanced = false;
                    break;
                }
            };
            match admin::maybe_consensus_status(api).await? {
                Some(s) if s.last_committed_height >= target => continue,
                _ => {
                    all_advanced = false;
                    break;
                }
            }
        }
        if all_advanced {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// `--all-healthy --within N`: every live node is on a `current_view`
/// within `within` of the cluster max, has at least the expected
/// number of consensus peers, and reports `last_committed_height >= 1`.
pub async fn all_healthy(state: &State, within: u64, timeout: Duration) -> anyhow::Result<()> {
    poll_until(timeout, || async { all_healthy_check(state, within).await }).await
}

async fn all_healthy_check(state: &State, within: u64) -> anyhow::Result<bool> {
    let live = live_nodes(state);
    if live.is_empty() {
        return Ok(false);
    }
    let expected_peers = live.len().saturating_sub(1);
    let mut views = Vec::with_capacity(live.len());
    let mut min_height = u64::MAX;
    for n in &live {
        let api = match n.api_addr {
            Some(a) => a,
            None => return Ok(false),
        };
        let s = match admin::maybe_consensus_status(api).await? {
            Some(s) => s,
            None => return Ok(false),
        };
        if s.last_committed_height < 1 {
            return Ok(false);
        }
        if s.peers_connected.len() < expected_peers {
            return Ok(false);
        }
        views.push(s.current_view);
        min_height = min_height.min(s.last_committed_height);
    }
    let max_view = views.iter().max().copied().unwrap_or(0);
    let min_view = views.iter().min().copied().unwrap_or(0);
    Ok(max_view.saturating_sub(min_view) <= within)
}

/// `--node X --catch-up-to-cluster --tolerance T`: the named node's
/// `last_committed_height` is within `tolerance` of the maximum across
/// the rest of the live cluster.
pub async fn node_caught_up(
    state: &State,
    node: &NodeLayout,
    tolerance: u64,
    timeout: Duration,
) -> anyhow::Result<()> {
    poll_until(timeout, || async {
        let api = match node.api_addr {
            Some(a) => a,
            None => return Ok(false),
        };
        let mine = match admin::maybe_consensus_status(api).await? {
            Some(s) => s.last_committed_height,
            None => return Ok(false),
        };
        let mut others_max = 0u64;
        let mut saw_other = false;
        for n in state.nodes.iter().filter(|n| n.index != node.index) {
            if super::lifecycle::pid_alive(n).is_none() {
                continue;
            }
            saw_other = true;
            let api = match n.api_addr {
                Some(a) => a,
                None => return Ok(false),
            };
            if let Some(s) = admin::maybe_consensus_status(api).await? {
                others_max = others_max.max(s.last_committed_height);
            } else {
                return Ok(false);
            }
        }
        if !saw_other {
            // Single-node cluster — vacuously caught up.
            return Ok(true);
        }
        Ok(mine + tolerance >= others_max)
    })
    .await
}

/// `--quiescent --for SECS`: every live node reports its
/// `last_committed_height` and `current_view` are unchanged for the
/// given duration. Polling cadence is `POLL_INTERVAL`.
pub async fn quiescent(state: &State, hold: Duration, timeout: Duration) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut quiet_since: Option<Instant> = None;
    let mut last_snapshot: Option<Vec<(u64, u64)>> = None;
    loop {
        if started.elapsed() > timeout {
            anyhow::bail!("wait quiescent timed out after {timeout:?}");
        }
        let mut snap: Vec<(u64, u64)> = Vec::new();
        let live = live_nodes(state);
        let mut all_reachable = true;
        for n in &live {
            let api = match n.api_addr {
                Some(a) => a,
                None => {
                    all_reachable = false;
                    break;
                }
            };
            match admin::maybe_consensus_status(api).await? {
                Some(s) => snap.push((s.current_view, s.last_committed_height)),
                None => {
                    all_reachable = false;
                    break;
                }
            }
        }
        if !all_reachable || live.is_empty() {
            quiet_since = None;
            last_snapshot = None;
        } else if last_snapshot.as_ref() == Some(&snap) {
            // Same view + height as last poll on every live node.
            if let Some(t0) = quiet_since {
                if t0.elapsed() >= hold {
                    return Ok(());
                }
            } else {
                quiet_since = Some(Instant::now());
            }
        } else {
            quiet_since = Some(Instant::now());
            last_snapshot = Some(snap);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn live_nodes(state: &State) -> Vec<NodeLayout> {
    state
        .nodes
        .iter()
        .filter(|n| super::lifecycle::pid_alive(n).is_some())
        .cloned()
        .collect()
}
