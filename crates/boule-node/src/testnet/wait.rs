use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::admin;
use super::workdir::{NodeLayout, State};

const POLL_INTERVAL: Duration = Duration::from_millis(100);

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

pub async fn all_reach_height(state: &State, height: u64, timeout: Duration) -> anyhow::Result<()> {
    let height = boule_consensus::Height(height);
    poll_until(timeout, || async {
        let live = live_nodes(state);
        if live.is_empty() {
            return Ok(false);
        }
        for n in live {
            let api = match n.admin_addr {
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
            let mut snap: HashMap<usize, u64> = HashMap::new();
            let mut all_reachable = true;
            for n in &live {
                let api = match n.admin_addr {
                    Some(a) => a,
                    None => {
                        all_reachable = false;
                        break;
                    }
                };
                match admin::maybe_consensus_status(api).await? {
                    Some(s) => {
                        snap.insert(n.index, s.last_committed_height.0.saturating_add(delta));
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
            let target = match targets_ref.get(&n.index) {
                Some(t) => *t,
                None => continue,
            };
            let api = match n.admin_addr {
                Some(a) => a,
                None => {
                    all_advanced = false;
                    break;
                }
            };
            match admin::maybe_consensus_status(api).await? {
                Some(s) if s.last_committed_height.0 >= target => continue,
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
        let api = match n.admin_addr {
            Some(a) => a,
            None => return Ok(false),
        };
        let s = match admin::maybe_consensus_status(api).await? {
            Some(s) => s,
            None => return Ok(false),
        };
        if s.last_committed_height < boule_consensus::Height(1) {
            return Ok(false);
        }
        if s.peers_connected.len() < expected_peers {
            return Ok(false);
        }
        views.push(s.current_view.0);
        min_height = min_height.min(s.last_committed_height.0);
    }
    let max_view = views.iter().max().copied().unwrap_or(0);
    let min_view = views.iter().min().copied().unwrap_or(0);
    Ok(max_view.saturating_sub(min_view) <= within)
}

pub async fn node_caught_up(
    state: &State,
    node: &NodeLayout,
    tolerance: u64,
    timeout: Duration,
) -> anyhow::Result<()> {
    poll_until(timeout, || async {
        let api = match node.admin_addr {
            Some(a) => a,
            None => return Ok(false),
        };
        let mine = match admin::maybe_consensus_status(api).await? {
            Some(s) => s.last_committed_height.0,
            None => return Ok(false),
        };
        let mut others_heights: Vec<u64> = Vec::new();
        for n in state.nodes.iter().filter(|n| n.index != node.index) {
            if super::lifecycle::pid_alive(n).is_none() {
                continue;
            }
            let api = match n.admin_addr {
                Some(a) => a,
                None => return Ok(false),
            };
            if let Some(s) = admin::maybe_consensus_status(api).await? {
                others_heights.push(s.last_committed_height.0);
            } else {
                return Ok(false);
            }
        }
        Ok(caught_up_predicate(mine, &mut others_heights, tolerance))
    })
    .await
}

fn caught_up_predicate(mine: u64, others: &mut [u64], tolerance: u64) -> bool {
    if others.is_empty() {
        return true;
    }
    others.sort_unstable();
    let target = others[(others.len() - 1) / 2];
    mine + tolerance >= target
}

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
            let api = match n.admin_addr {
                Some(a) => a,
                None => {
                    all_reachable = false;
                    break;
                }
            };
            match admin::maybe_consensus_status(api).await? {
                Some(s) => snap.push((s.current_view.0, s.last_committed_height.0)),
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
