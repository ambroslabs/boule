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
/// `last_committed_height` is within `tolerance` of the median
/// `last_committed_height` across the rest of the live cluster.
///
/// Comparing against the median rather than the max is what makes the
/// predicate robust to bursty commits. The 3-chain commit rule means a
/// single new QC can extend `last_committed_height` by several blocks
/// at once, and proposals reach replicas at slightly different times,
/// so `max(others) - mine` routinely jumps to 5+ for a single sample
/// even on a healthy cluster (issue #396). The median tracks the
/// cluster body, which is what "X has caught up" actually wants to
/// assert: not "X is at the leader's instantaneous tip" (the leader is
/// always ahead by definition) but "X is in the cluster body".
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
        let mut others_heights: Vec<u64> = Vec::new();
        for n in state.nodes.iter().filter(|n| n.index != node.index) {
            if super::lifecycle::pid_alive(n).is_none() {
                continue;
            }
            let api = match n.api_addr {
                Some(a) => a,
                None => return Ok(false),
            };
            if let Some(s) = admin::maybe_consensus_status(api).await? {
                others_heights.push(s.last_committed_height);
            } else {
                return Ok(false);
            }
        }
        Ok(caught_up_predicate(mine, &mut others_heights, tolerance))
    })
    .await
}

/// Predicate for [`node_caught_up`], factored out for testability.
///
/// Returns `true` if `mine` is within `tolerance` of the median of
/// `others`. Mutates `others` (sorts in place) — callers don't need it
/// preserved. With an empty `others` (single-node cluster) the result
/// is vacuously `true`.
///
/// The median is the lower of the two middle elements on an even-sized
/// sample. With three others — the typical 4-node-cluster case for
/// this helper — that's the unambiguous middle replica.
fn caught_up_predicate(mine: u64, others: &mut [u64], tolerance: u64) -> bool {
    if others.is_empty() {
        return true;
    }
    others.sort_unstable();
    let target = others[(others.len() - 1) / 2];
    mine + tolerance >= target
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

#[cfg(test)]
mod tests {
    use super::caught_up_predicate;

    fn caught_up(mine: u64, mut others: Vec<u64>, tolerance: u64) -> bool {
        caught_up_predicate(mine, &mut others, tolerance)
    }

    #[test]
    fn empty_others_is_vacuously_caught_up() {
        // Single-node cluster: nothing to lag behind.
        assert!(caught_up(42, vec![], 0));
        assert!(caught_up(0, vec![], 0));
    }

    #[test]
    fn issue_396_a2_post_restart_passes_with_median() {
        // Heights captured in #396: node1=1381 (laggard survivor),
        // node2=1382 (restarted, queried), node3=1384, node4=1387
        // (leader). With tolerance=2, max(others)=1387 fails
        // (1382+2=1384 < 1387). Median(1381, 1384, 1387) = 1384,
        // 1382+2 >= 1384 — passes.
        assert!(caught_up(1382, vec![1381, 1384, 1387], 2));
    }

    #[test]
    fn issue_396_b2_seed1_post_restart_passes_with_median() {
        // Heights captured in #396 B2 seed=1: node1=1365, node2=1366
        // (queried), node3=1368, node4=1370.
        assert!(caught_up(1366, vec![1365, 1368, 1370], 2));
    }

    #[test]
    fn permanent_lag_still_fails() {
        // Restored node permanently 5 behind a 4-node cluster: median
        // of survivors is around the cluster tip, mine + tolerance
        // doesn't reach it.
        assert!(!caught_up(95, vec![100, 101, 101], 2));
        // And not even with tolerance up to 5.
        assert!(!caught_up(95, vec![100, 101, 101], 5));
        // tolerance=6 finally accepts it (median=101).
        assert!(caught_up(95, vec![100, 101, 101], 6));
    }

    #[test]
    fn ahead_of_cluster_is_caught_up() {
        // Queried node leading the others: predicate trivially holds
        // because the gap is non-positive.
        assert!(caught_up(110, vec![100, 100, 100], 0));
    }

    #[test]
    fn outlier_leader_does_not_drag_median() {
        // One leader far ahead, two replicas at the body: median picks
        // the body element, so a node sitting at the body is caught
        // up even with tolerance=0.
        assert!(caught_up(100, vec![100, 100, 200], 0));
    }

    #[test]
    fn floor_median_on_even_count() {
        // Six others evenly split: floor median picks index 2 of
        // sorted [10, 10, 10, 11, 11, 11] -> 10. Queried at 10 is
        // caught up at tolerance=0; at 9 it isn't.
        assert!(caught_up(10, vec![11, 10, 11, 10, 11, 10], 0));
        assert!(!caught_up(9, vec![11, 10, 11, 10, 11, 10], 0));
        assert!(caught_up(9, vec![11, 10, 11, 10, 11, 10], 1));
    }

    #[test]
    fn two_others_picks_lower() {
        // After a second kill mid-wait, others_heights might be just
        // two. Floor median picks the lower one — least surprising
        // because that's how the predicate was already lenient under
        // partial cluster outages.
        assert!(caught_up(10, vec![10, 12], 0));
        assert!(caught_up(10, vec![12, 10], 0));
        // Genuinely 4 behind both is not caught up.
        assert!(!caught_up(8, vec![12, 12], 2));
    }
}
