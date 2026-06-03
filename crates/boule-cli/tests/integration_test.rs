use std::io::Write;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::NamedTempFile;

#[derive(serde::Deserialize)]
struct NodeAddrs {
    p2p_addr: String,
    api_addr: String,
    node_id: String,
}

struct NodeGuard {
    child: Child,
    api_port: u16,
    p2p_addr: String,
    node_id: String,
    _config: NamedTempFile,
    _key_dir: tempfile::TempDir,
    _addr_file: NamedTempFile,
}

impl NodeGuard {
    fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.api_port, path)
    }
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        // Graceful shutdown: send SIGINT so the node runs its ctrl_c path
        // (flushing TLS `close_notify` on every connection) before exiting.
        // Without this, peers still running in other NodeGuards would see
        // the TCP FIN without a close_notify and log ERROR.
        //
        // If the node can't be reached by signal (already exited, platform
        // unsupported), or doesn't exit within the grace period, fall back
        // to SIGKILL so the test doesn't hang.
        let graceful = send_sigint(&self.child)
            && wait_with_timeout(&mut self.child, Duration::from_secs(3)).is_some();
        if !graceful {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn send_sigint(child: &Child) -> bool {
    // `Child::id()` returns `Option<u32>` only after being waited on; the
    // std variant returns `u32` directly.
    // SAFETY: libc::kill with a valid PID is safe; an invalid/stale PID
    // just returns -1 with errno set to ESRCH, which we treat as "already
    // gone" and return false.
    let pid = child.id();
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) };
    rc == 0
}

#[cfg(not(unix))]
fn send_sigint(_child: &Child) -> bool {
    false
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

/// Synchronously run `boule init --config <path>` so the file
/// backend mints a key before `start` is invoked. `start` refuses to
/// run before `init`, so every spawn helper threads through this.
fn run_init(config_path: &str) {
    let bin = env!("CARGO_BIN_EXE_boule");
    let output = Command::new(bin)
        .args(["init", "--config", config_path])
        .env("RUST_LOG", "warn")
        .output()
        .expect("failed to spawn `init` binary");
    assert!(
        output.status.success(),
        "`init` exited non-zero: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Peer descriptor used when configuring a node's `[[peers]]` list.
struct PeerDesc<'a> {
    p2p_addr: &'a str,
    node_id: &'a str,
}

#[derive(Clone, Copy)]
enum IdentitySchema {
    /// Uses the deprecated `key_file = ...` scalar inside `[node]`.
    Legacy,
    /// Uses the `[node.identity]` table with `backend = "file"`.
    NewFileBackend,
}

async fn spawn_node(peers: &[PeerDesc<'_>]) -> NodeGuard {
    spawn_node_with_schema(peers, IdentitySchema::Legacy).await
}

/// Spawn a node with port 0 for both listeners. The node writes its actual
/// bound addresses and node ID to a temp file; we poll until the file is
/// populated and parse the real values — no TOCTOU window, no reserved-port races.
async fn spawn_node_with_schema(peers: &[PeerDesc<'_>], schema: IdentitySchema) -> NodeGuard {
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    // Use a temp dir so the key file path is valid but the file doesn't exist yet,
    // causing the node to generate a fresh key on first run.
    let key_dir = tempfile::tempdir().unwrap();
    let key_file_path = key_dir.path().join("node.key").to_str().unwrap().to_owned();

    let peer_lines: String = peers
        .iter()
        .map(|p| {
            format!(
                "\n[[peers]]\naddr = \"{}\"\nnode_id = \"{}\"\n",
                p.p2p_addr, p.node_id
            )
        })
        .collect();

    let (scalar_field, identity_table) = match schema {
        IdentitySchema::Legacy => (format!("key_file = \"{key_file_path}\"\n"), String::new()),
        IdentitySchema::NewFileBackend => (
            String::new(),
            format!("\n[node.identity]\nbackend = \"file\"\npath = \"{key_file_path}\"\n"),
        ),
    };

    let config = format!(
        "[node]\nlisten_addr = \"127.0.0.1:0\"\n{scalar_field}addr_file = \"{addr_file_path}\"\n{identity_table}\n[api]\nlisten_addr = \"127.0.0.1:0\"\n{peer_lines}"
    );

    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    run_init(config_file.path().to_str().unwrap());

    let bin = env!("CARGO_BIN_EXE_boule");
    let child = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn node binary");

    // Poll until the node writes its actual bound addresses to addr_file.
    // 30s (not 10s): under CI's oversubscribed test-thread parallelism a
    // freshly-spawned binary can take well over 10s just to bind its
    // listener and write addr_file, which flaked this setup step (#303).
    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break addrs;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = addrs.api_addr.rsplit(':').next().unwrap().parse().unwrap();

    NodeGuard {
        child,
        api_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: key_dir,
        _addr_file: addr_file,
    }
}

async fn wait_until_ready(node: &NodeGuard, timeout: Duration) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            panic!(
                "node on port {} did not become ready in time",
                node.api_port
            );
        }
        if client.get(node.api_url("/peers")).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_peer_count(node: &NodeGuard, expected: usize, timeout: Duration) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            panic!(
                "node on port {} did not reach {} peer(s) in time",
                node.api_port, expected
            );
        }
        if let Ok(resp) = client.get(node.api_url("/peers")).send().await {
            if let Ok(peers) = resp.json::<Value>().await {
                if peers.as_array().map(|a| a.len()).unwrap_or(0) >= expected {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Start a three-node fully-connected cluster using OS-assigned ports.
/// Sequential startup builds the mesh via inbound connections:
/// node1 (no peers) → node2 connects to node1 → node3 connects to both.
/// Each pair ends up with exactly one TCP connection, giving every node 2 peers.
async fn start_cluster() -> (NodeGuard, NodeGuard, NodeGuard) {
    let node1 = spawn_node(&[]).await;
    let node2 = spawn_node(&[PeerDesc {
        p2p_addr: &node1.p2p_addr,
        node_id: &node1.node_id,
    }])
    .await;
    let node3 = spawn_node(&[
        PeerDesc {
            p2p_addr: &node1.p2p_addr,
            node_id: &node1.node_id,
        },
        PeerDesc {
            p2p_addr: &node2.p2p_addr,
            node_id: &node2.node_id,
        },
    ])
    .await;

    let ready_timeout = Duration::from_secs(10);
    wait_until_ready(&node1, ready_timeout).await;
    wait_until_ready(&node2, ready_timeout).await;
    wait_until_ready(&node3, ready_timeout).await;

    let mesh_timeout = Duration::from_secs(10);
    wait_for_peer_count(&node1, 2, mesh_timeout).await;
    wait_for_peer_count(&node2, 2, mesh_timeout).await;
    wait_for_peer_count(&node3, 2, mesh_timeout).await;

    (node1, node2, node3)
}

/// Boots two nodes with `[node.identity] backend = "file"` (the new schema)
/// and verifies they connect to each other. Covers the end-to-end path that
/// the backward-compat legacy tests don't exercise.
#[tokio::test]
async fn test_new_identity_schema_end_to_end() {
    let node1 = spawn_node_with_schema(&[], IdentitySchema::NewFileBackend).await;
    let node2 = spawn_node_with_schema(
        &[PeerDesc {
            p2p_addr: &node1.p2p_addr,
            node_id: &node1.node_id,
        }],
        IdentitySchema::NewFileBackend,
    )
    .await;

    let ready_timeout = Duration::from_secs(10);
    wait_until_ready(&node1, ready_timeout).await;
    wait_until_ready(&node2, ready_timeout).await;

    let mesh_timeout = Duration::from_secs(10);
    wait_for_peer_count(&node1, 1, mesh_timeout).await;
    wait_for_peer_count(&node2, 1, mesh_timeout).await;
}

/// Regression test for #114. Spawns a full-mesh 4-node cluster where every
/// node lists every other node as a `[[peers]]` entry — so every pair
/// dials each other concurrently at startup and the tie-breaker at each
/// manager has to resolve the resulting duplicate connections.
///
/// Pre-fix: the tie-breaker replace path fired a spurious `peer_gone` for
/// every duplicate, which made the dialer redial immediately, producing
/// an unending connect → tie-breaker → reconnect churn. Post-fix the mesh
/// forms within seconds and stays stable.
///
/// The two-phase scheme (discover addresses → relaunch with full peer
/// lists) is needed because every node must know every other node's
/// `node_id` and listen port before it starts, which is a chicken-and-egg
/// problem when ports are OS-assigned.
#[tokio::test]
async fn test_four_node_full_mesh_is_stable_under_simultaneous_dials() {
    // Phase 1: spawn each node once with no peers so it generates its
    // identity and binds a port. Capture the address + node_id, then
    // shut it down — but keep the key file tempdir alive so phase 2 can
    // reuse the same identity.
    const N: usize = 4;
    let key_dirs: Vec<tempfile::TempDir> = (0..N).map(|_| tempfile::tempdir().unwrap()).collect();
    let key_paths: Vec<String> = key_dirs
        .iter()
        .map(|d| d.path().join("node.key").to_str().unwrap().to_owned())
        .collect();

    // Phase 1: discover every node's identity concurrently. The port phase 1
    // binds is discarded — phase 2 uses a freshly *reserved* port (below), so
    // no address is freed for a concurrent shard test to grab in between.
    let discovered: Vec<DiscoveryInfo> =
        futures_util::future::join_all(key_paths.iter().map(|p| launch_once_for_discovery(p)))
            .await;
    let node_ids: Vec<String> = discovered.iter().map(|d| d.node_id.clone()).collect();

    // Reserve a fresh P2P port per node and HOLD it through peer-list
    // construction, so the seconds-long window that made re-binding a
    // phase-1-freed port flaky (#678/#680) is gone: each reservation is
    // released only in the same breath as its node spawns.
    let reservations: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a P2P port"))
        .collect();
    let p2p_addrs: Vec<String> = reservations
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();

    // Phase 2: relaunch every node concurrently with the full peer list.
    let peer_lists: Vec<Vec<PeerDesc<'_>>> = (0..N)
        .map(|i| {
            (0..N)
                .filter(|j| *j != i)
                .map(|j| PeerDesc {
                    p2p_addr: &p2p_addrs[j],
                    node_id: &node_ids[j],
                })
                .collect()
        })
        .collect();
    let guards: Vec<NodeGuard> =
        futures_util::future::join_all(reservations.into_iter().enumerate().map(
            |(i, reservation)| spawn_node_fixed_port(&key_paths[i], reservation, &peer_lists[i]),
        ))
        .await;

    let ready_timeout = Duration::from_secs(10);
    futures_util::future::join_all(guards.iter().map(|g| wait_until_ready(g, ready_timeout))).await;

    // Every node must see every other node, within the 2s budget from the
    // issue's acceptance criteria (after the last node starts).
    let mesh_timeout = Duration::from_secs(10);
    futures_util::future::join_all(
        guards
            .iter()
            .map(|g| wait_for_peer_count(g, N - 1, mesh_timeout)),
    )
    .await;

    // Mesh is up. Watch it for 2s and assert every node keeps reporting
    // (N - 1) peers continuously — no flapping. 8 polls at 250ms each
    // are enough to catch the churn pattern from #114; the original 5s
    // watch was over-budgeted.
    let client = reqwest::Client::new();
    let watch_end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < watch_end {
        for guard in &guards {
            let peers: Value = client
                .get(guard.api_url("/peers"))
                .send()
                .await
                .expect("/peers request failed")
                .json()
                .await
                .expect("/peers returned non-JSON");
            let count = peers.as_array().map(|a| a.len()).unwrap_or(0);
            assert_eq!(
                count,
                N - 1,
                "mesh flapped: node {} reported {} peers at t+{:?} (expected {}); churn from #114 has regressed",
                guard.node_id,
                count,
                watch_end.saturating_duration_since(Instant::now()),
                N - 1,
            );
        }
        // Sampling cadence, not a wait: this loop verifies the mesh count
        // *stays* at N-1 across a window — there is no positive observable
        // to early-exit on, so a fixed real-time cadence is correct.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Keep key_dirs alive until end of test; NodeGuard drops shut nodes down
    // first so we can then safely let the tempdirs clean up.
    drop(guards);
    drop(key_dirs);
}

struct DiscoveryInfo {
    p2p_addr: String,
    node_id: String,
}

/// Spawn a node with a persistent key file at `key_path`, wait for it to
/// bind + write its addr file, capture p2p addr + node_id, and shut it
/// down gracefully. The key file survives the shutdown so a subsequent
/// spawn with the same path gets the same node_id.
async fn launch_once_for_discovery(key_path: &str) -> DiscoveryInfo {
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    let config = format!(
        "[node]\nlisten_addr = \"127.0.0.1:0\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n[api]\nlisten_addr = \"127.0.0.1:0\"\n"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    run_init(config_file.path().to_str().unwrap());

    let bin = env!("CARGO_BIN_EXE_boule");
    let mut child = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn node binary");

    // 30s headroom for a spawned binary to bind + write addr_file under
    // CI's oversubscribed parallelism (#303).
    let deadline = Instant::now() + Duration::from_secs(30);
    let info = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("discovery node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break DiscoveryInfo {
                    p2p_addr: addrs.p2p_addr,
                    node_id: addrs.node_id,
                };
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Discovery-phase nodes have no peers, so nothing is gained by a
    // graceful close. SIGKILL releases the port immediately and keeps the
    // test's wall-clock short.
    let _ = child.kill();
    let _ = child.wait();

    info
}

/// Spawn a node whose P2P listener binds the port `reservation` is holding,
/// and whose `[[peers]]` list is set from `peers`. The API listener still uses
/// port 0.
///
/// `reservation` is a `TcpListener` the caller bound on `127.0.0.1:0` and has
/// held continuously since phase 1 — so the port could not be grabbed by a
/// concurrent test during discovery + config construction (the seconds-long
/// window that made re-binding a phase-1-freed port flaky, #678/#680). It is
/// released here only at the last moment, in the same breath as the node
/// spawn, leaving just this node's own startup→bind as the residual race (which
/// the reap-and-retry loop absorbs).
async fn spawn_node_fixed_port(
    key_path: &str,
    reservation: std::net::TcpListener,
    peers: &[PeerDesc<'_>],
) -> NodeGuard {
    let fixed_p2p_addr = reservation
        .local_addr()
        .expect("reservation has a local address")
        .to_string();
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    let peer_lines: String = peers
        .iter()
        .map(|p| {
            format!(
                "\n[[peers]]\naddr = \"{}\"\nnode_id = \"{}\"\n",
                p.p2p_addr, p.node_id
            )
        })
        .collect();

    let config = format!(
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n[api]\nlisten_addr = \"127.0.0.1:0\"\n{peer_lines}"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    run_init(config_file.path().to_str().unwrap());

    let bin = env!("CARGO_BIN_EXE_boule");
    let config_path = config_file.path().to_str().unwrap().to_owned();
    let spawn_child = || {
        Command::new(bin)
            .args(["start", "--config", &config_path])
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("failed to spawn node binary")
    };
    // `run_init` above only generated the key — it never bound the port, so the
    // reservation held it throughout. Release it and spawn the node in the same
    // breath, so the only window in which the port is free is this node's own
    // startup → bind, not the whole discovery phase.
    drop(reservation);
    let mut child = spawn_child();

    // 30s headroom for a spawned binary to bind + write addr_file under
    // CI's oversubscribed parallelism (#303). This is the phase-2
    // concurrent spawn fan-out, the worst case for startup contention.
    //
    // The reservation closed the seconds-long window that made this flaky
    // (#678/#680), but a foreign port-0 bind can still, very rarely, land on
    // the just-released port during the node's startup. If the child exits
    // before publishing its addr file (an `EADDRINUSE` on bind), reap and
    // re-spawn on the same port — once we win the bind the running node holds
    // it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("phase-2 node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break addrs;
            }
        }
        // Reap-and-retry on an early exit (the EADDRINUSE bind race).
        // `try_wait` reaps the process when it reports `Some`.
        if matches!(child.try_wait(), Ok(Some(_))) {
            child = spawn_child();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = addrs.api_addr.rsplit(':').next().unwrap().parse().unwrap();

    // The key_dir is owned by the test function (so the key survives the
    // phase-1 shutdown); hand this guard a throwaway TempDir to keep the
    // Drop invariant simple.
    let placeholder_dir = tempfile::tempdir().unwrap();

    NodeGuard {
        child,
        api_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: placeholder_dir,
        _addr_file: addr_file,
    }
}

/// Regression for #678/#680: phase 2 binds a *reserved* port — one the test
/// has held continuously since phase 1 — so a concurrent test cannot grab it
/// in the discovery→bind window. The node binds exactly the reserved port and
/// comes up, with the reservation released only at spawn time (inside
/// `spawn_node_fixed_port`).
#[tokio::test]
async fn phase_two_node_binds_its_reserved_port() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p2p_addr = reservation.local_addr().unwrap().to_string();

    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("node.key").to_str().unwrap().to_owned();

    let guard = spawn_node_fixed_port(&key_path, reservation, &[]).await;

    // The node bound the exact reserved port. `key_dir` and `guard` live to
    // the end of scope, keeping the key file and node process alive.
    assert_eq!(guard.p2p_addr, p2p_addr);
}

#[tokio::test]
async fn test_peers_endpoint_lists_connected_peers() {
    let (node1, node2, node3) = start_cluster().await;
    let _ = (&node2, &node3); // keep alive

    let client = reqwest::Client::new();
    let peers: Value = client
        .get(node1.api_url("/peers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let peer_list = peers.as_array().unwrap();
    assert!(
        peer_list.len() >= 2,
        "expected at least 2 peers, got {}",
        peer_list.len()
    );
}

// ── Consensus status endpoint (#123) ────────────────────────────────────────

/// Node spec used by [`start_consensus_cluster`]: a node IDs in the
/// committee has a stable key path (so phase 1 / phase 2 re-spawn
/// preserves identity) and a pre-bound P2P address.
struct ConsensusNodeSpec {
    key_path: String,
    p2p_addr: String,
    node_id: String,
}

/// Spawn a 4-node HotStuff cluster with `[consensus]` configured on
/// every node. Uses the same two-phase discovery pattern as the full-
/// mesh stability test: mint identities, capture base58 IDs, then
/// relaunch every node with the complete committee list.
async fn start_consensus_cluster(n: usize) -> (Vec<NodeGuard>, Vec<tempfile::TempDir>) {
    let key_dirs: Vec<tempfile::TempDir> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
    let key_paths: Vec<String> = key_dirs
        .iter()
        .map(|d| d.path().join("node.key").to_str().unwrap().to_owned())
        .collect();

    // Phase 1: discover addresses + node IDs.
    let mut specs: Vec<ConsensusNodeSpec> = Vec::with_capacity(n);
    for key_path in &key_paths {
        let info = launch_once_for_discovery(key_path).await;
        specs.push(ConsensusNodeSpec {
            key_path: key_path.clone(),
            p2p_addr: info.p2p_addr,
            node_id: info.node_id,
        });
    }

    // Phase 2: relaunch with full peer list + [consensus] section.
    let validators_toml = specs
        .iter()
        .map(|s| format!("\"{}\"", s.node_id))
        .collect::<Vec<_>>()
        .join(", ");

    let mut guards: Vec<NodeGuard> = Vec::with_capacity(n);
    for (i, spec) in specs.iter().enumerate() {
        let peer_descs: Vec<PeerDesc<'_>> = specs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| PeerDesc {
                p2p_addr: &other.p2p_addr,
                node_id: &other.node_id,
            })
            .collect();
        guards.push(
            spawn_consensus_node(
                &spec.key_path,
                &spec.p2p_addr,
                &peer_descs,
                &validators_toml,
            )
            .await,
        );
    }

    let ready_timeout = Duration::from_secs(10);
    for g in &guards {
        wait_until_ready(g, ready_timeout).await;
    }

    let mesh_timeout = Duration::from_secs(10);
    for g in &guards {
        wait_for_peer_count(g, n - 1, mesh_timeout).await;
    }

    (guards, key_dirs)
}

async fn spawn_consensus_node(
    key_path: &str,
    fixed_p2p_addr: &str,
    peers: &[PeerDesc<'_>],
    validators_toml: &str,
) -> NodeGuard {
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    let peer_lines: String = peers
        .iter()
        .map(|p| {
            format!(
                "\n[[peers]]\naddr = \"{}\"\nnode_id = \"{}\"\n",
                p.p2p_addr, p.node_id
            )
        })
        .collect();

    // Use short timeouts + in-memory storage so the test commits
    // blocks within a few hundred ms. Without this a stock config
    // (timeout_base_ms = 200) still works, but shorter base keeps the
    // test tight.
    let config = format!(
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n{peer_lines}\n\
        [consensus]\nvalidators = [{validators_toml}]\npropose_limit = 64\ntimeout_base_ms = 200\ntimeout_max_ms = 2000\n"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    run_init(config_file.path().to_str().unwrap());

    let bin = env!("CARGO_BIN_EXE_boule");
    let child = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn consensus node binary");

    // 30s headroom for a spawned binary to bind + write addr_file under
    // CI's oversubscribed parallelism (#303).
    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("consensus node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break addrs;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = addrs.api_addr.rsplit(':').next().unwrap().parse().unwrap();

    NodeGuard {
        child,
        api_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: tempfile::tempdir().unwrap(),
        _addr_file: addr_file,
    }
}

/// Acceptance criterion for #123: every node in a running 4-node
/// consensus cluster must eventually return a `/consensus/status`
/// response reporting `last_committed_height > 0`, `current_view > 0`,
/// and a peer list of size `n - 1`. Also covers the gossip-only
/// negative path (no `[consensus]` section → 404) and the stale-
/// initial-state path (freshly booted → sane zero-valued snapshot).
#[tokio::test]
async fn test_consensus_status_endpoint_reports_live_progress() {
    const N: usize = 4;
    let (guards, key_dirs) = start_consensus_cluster(N).await;

    let client = reqwest::Client::new();

    // Before committing anything, every node must already serve a
    // sane snapshot (startup-window path): the status is published
    // once at boot, so the endpoint must never 500.
    for g in &guards {
        let resp = client.get(g.api_url("/consensus/status")).send().await;
        let resp = resp.expect("/consensus/status must respond during startup");
        assert_eq!(
            resp.status(),
            200,
            "consensus/status must return 200 even pre-commit",
        );
        let body: Value = resp.json().await.unwrap();
        assert!(body["current_view"].is_u64());
        assert!(body["last_committed_height"].is_u64());
        assert_eq!(body["validator_set"].as_array().map(|a| a.len()), Some(N));
        assert_eq!(body["node_id"], g.node_id);
    }

    // Wait until every node reports `last_committed_height > 0` and
    // `current_view > 0`. 15s is generous for a 4-node cluster on a
    // laptop (HotStuff commits the 3rd proposal, which at
    // timeout_base_ms=200 lands in well under a second).
    let deadline = Instant::now() + Duration::from_secs(15);
    'outer: loop {
        if Instant::now() > deadline {
            panic!("consensus cluster did not commit within 15s");
        }
        for g in &guards {
            let resp = client.get(g.api_url("/consensus/status")).send().await;
            let body: Value = match resp {
                Ok(r) if r.status() == 200 => r.json().await.unwrap_or(Value::Null),
                _ => Value::Null,
            };
            let committed = body["last_committed_height"].as_u64().unwrap_or(0);
            let current_view = body["current_view"].as_u64().unwrap_or(0);
            if committed == 0 || current_view == 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue 'outer;
            }
        }
        break;
    }

    // All nodes now show live state. Assert the peer_connected set is
    // correct on every node.
    for g in &guards {
        let body: Value = client
            .get(g.api_url("/consensus/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let peers = body["peers_connected"].as_array().unwrap();
        assert_eq!(
            peers.len(),
            N - 1,
            "node {} reported {} consensus peers, expected {}",
            g.node_id,
            peers.len(),
            N - 1,
        );

        let vset = body["validator_set"].as_array().unwrap();
        assert_eq!(vset.len(), N);
        assert!(
            vset.iter().any(|v| v == &Value::String(g.node_id.clone())),
            "validator_set on node {} must include self",
            g.node_id,
        );

        // self_role is either "replica" or "leader(view=N)".
        let role = body["self_role"].as_str().unwrap();
        assert!(
            role == "replica" || role.starts_with("leader(view="),
            "unexpected self_role: {role}",
        );
    }

    drop(guards);
    drop(key_dirs);
}

// ── Gossip-overlay smoke test (#137) ────────────────────────────────────────

/// Spawn a consensus-running node with `[overlay] mode = "gossip"`.
/// `[[peers]]` is left empty; reachability is driven by
/// `bootstrap_addrs` which the gossip overlay's
/// [`Discovery::add_bootstrap`](https://github.com/ambroslabs/boule/issues/137)
/// dials as TOFU.
#[allow(clippy::too_many_arguments)]
async fn spawn_consensus_node_gossip(
    key_path: &str,
    fixed_p2p_addr: &str,
    bootstrap_addrs: &[String],
    validators_toml: &str,
    target_degree: usize,
    peer_gossip_interval_ms: u64,
    mesh_check_interval_ms: u64,
) -> NodeGuard {
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    let bootstrap_toml = if bootstrap_addrs.is_empty() {
        "[]".to_string()
    } else {
        let inner = bootstrap_addrs
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{inner}]")
    };

    let config = format!(
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n\n\
        [overlay]\nmode = \"gossip\"\noutbound_target = {target_degree}\npeer_gossip_interval_ms = {peer_gossip_interval_ms}\nmesh_check_interval_ms = {mesh_check_interval_ms}\nbootstrap_addrs = {bootstrap_toml}\n\n\
        [consensus]\nvalidators = [{validators_toml}]\npropose_limit = 64\ntimeout_base_ms = 200\ntimeout_max_ms = 2000\n"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    run_init(config_file.path().to_str().unwrap());

    let bin = env!("CARGO_BIN_EXE_boule");
    let child = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn gossip-overlay consensus node");

    // 30s headroom for a spawned binary to bind + write addr_file under
    // CI's oversubscribed parallelism (#303).
    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("gossip-overlay node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break addrs;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = addrs.api_addr.rsplit(':').next().unwrap().parse().unwrap();

    NodeGuard {
        child,
        api_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: tempfile::tempdir().unwrap(),
        _addr_file: addr_file,
    }
}

/// Boot an `n`-node consensus cluster running the partial-mesh gossip
/// overlay. Each node `i > 0` lists node 0's P2P address in
/// `bootstrap_addrs`; the peer-list publisher then teaches the rest of
/// the cluster about everyone within a few ticks. `target_degree = 2`
/// in the tests below — small enough that with `n = 3` each node
/// holds a direct connection to every other node, big enough that the
/// maintenance loop is exercised. `peer_gossip_interval_ms` and
/// `mesh_check_interval_ms` are set to 250 ms so convergence is much
/// faster than the test's 15 s wall-clock budget.
async fn start_gossip_consensus_cluster(
    n: usize,
    target_degree: usize,
) -> (Vec<NodeGuard>, Vec<tempfile::TempDir>) {
    let key_dirs: Vec<tempfile::TempDir> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
    let key_paths: Vec<String> = key_dirs
        .iter()
        .map(|d| d.path().join("node.key").to_str().unwrap().to_owned())
        .collect();

    // Phase 1: discover addresses + node IDs (same two-phase pattern
    // as the mesh helper).
    let mut specs: Vec<ConsensusNodeSpec> = Vec::with_capacity(n);
    for key_path in &key_paths {
        let info = launch_once_for_discovery(key_path).await;
        specs.push(ConsensusNodeSpec {
            key_path: key_path.clone(),
            p2p_addr: info.p2p_addr,
            node_id: info.node_id,
        });
    }

    let validators_toml = specs
        .iter()
        .map(|s| format!("\"{}\"", s.node_id))
        .collect::<Vec<_>>()
        .join(", ");

    // Phase 2: relaunch with [overlay] + [consensus]. Node 0 has no
    // bootstrap (others connect TO it); every other node uses node
    // 0's address as the bootstrap.
    let bootstrap_for_node_0: Vec<String> = Vec::new();
    let bootstrap_via_node_0: Vec<String> = vec![specs[0].p2p_addr.clone()];

    let mut guards: Vec<NodeGuard> = Vec::with_capacity(n);
    for (i, spec) in specs.iter().enumerate() {
        let bootstrap = if i == 0 {
            &bootstrap_for_node_0
        } else {
            &bootstrap_via_node_0
        };
        guards.push(
            spawn_consensus_node_gossip(
                &spec.key_path,
                &spec.p2p_addr,
                bootstrap,
                &validators_toml,
                target_degree,
                /* peer_gossip_interval_ms */ 250,
                /* mesh_check_interval_ms  */ 250,
            )
            .await,
        );
    }

    let ready_timeout = Duration::from_secs(10);
    for g in &guards {
        wait_until_ready(g, ready_timeout).await;
    }

    (guards, key_dirs)
}

/// 3-node smoke test for #137 stack 7: nodes 1 and 2 reach node 0
/// via `bootstrap_addrs`, peer-list gossip teaches the cluster about
/// the third member, and consensus commits at steady state.
///
/// Assertions (poll-with-budget within 15 s):
///   1. Every node ends up with `n - 1` direct peers (a 3-node
///      cluster at K=2 is a full mesh — exercises both the
///      bootstrap path and the maintenance dial path).
///   2. Every node reports `last_committed_height > 0`, proving the
///      gossip overlay actually carries consensus traffic
///      end-to-end.
#[tokio::test]
async fn test_gossip_overlay_3_node_smoke() {
    const N: usize = 3;
    let (guards, key_dirs) = start_gossip_consensus_cluster(N, /* target_degree */ 2).await;

    // (1) Every node ends up with the other two as direct peers.
    let peer_timeout = Duration::from_secs(15);
    for g in &guards {
        wait_for_peer_count(g, N - 1, peer_timeout).await;
    }

    // (2) Consensus commits — the gossip overlay relays consensus
    // messages correctly.
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    'outer: loop {
        if Instant::now() > deadline {
            panic!("gossip-overlay cluster did not commit within 15s");
        }
        for g in &guards {
            let resp = client.get(g.api_url("/consensus/status")).send().await;
            let body: Value = match resp {
                Ok(r) if r.status() == 200 => r.json().await.unwrap_or(Value::Null),
                _ => Value::Null,
            };
            let committed = body["last_committed_height"].as_u64().unwrap_or(0);
            let current_view = body["current_view"].as_u64().unwrap_or(0);
            if committed == 0 || current_view == 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue 'outer;
            }
        }
        break;
    }

    drop(guards);
    drop(key_dirs);
}

#[tokio::test]
async fn test_consensus_status_returns_404_on_gossip_only_node() {
    // A vanilla (no [consensus]) node must not expose the endpoint.
    // Mounting is gated in main.rs on consensus being enabled; axum's
    // default 404 covers the negative path.
    let node = spawn_node(&[]).await;
    wait_until_ready(&node, Duration::from_secs(10)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(node.api_url("/consensus/status"))
        .send()
        .await
        .expect("GET /consensus/status must reach the node");
    assert_eq!(
        resp.status(),
        404,
        "gossip-only node must return 404 on /consensus/status",
    );
}

// ── Outbound-only mode (issue #138) ─────────────────────────────────────────
//
// A node carrying `[p2p] inbound_disabled = true` skips binding its
// TCP listener entirely; the test exercises that the gossip overlay
// still reaches it via the connection it dials out, and that consensus
// commits across the four-node cluster.
//
// macOS / Linux laptops can't reliably script iptables in a unit test,
// and we don't want to require docker. Skipping the listener bind is
// in fact a stronger blocker than iptables — there is no socket to
// connect to at all — and works identically on every host.

/// Spawn a consensus node with `[p2p] inbound_disabled = true` and the
/// gossip overlay enabled. The node never binds its P2P listener, so
/// `bootstrap_addrs` MUST point at a reachable peer that this node can
/// dial out to. The "p2p_addr" in the returned guard is whatever was
/// configured (typically `127.0.0.1:0` resolved to a phony address);
/// no other node should attempt to dial it.
#[allow(clippy::too_many_arguments)]
async fn spawn_consensus_node_inbound_disabled(
    key_path: &str,
    bootstrap_addrs: &[String],
    validators_toml: &str,
    target_degree: usize,
) -> NodeGuard {
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    let bootstrap_toml = bootstrap_addrs
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");

    // listen_addr is still required by the parser, but the listener is
    // never bound; pick `127.0.0.1:0` so the parser is happy.
    let config = format!(
        "[node]\nlisten_addr = \"127.0.0.1:0\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n\n\
        [p2p]\ninbound_disabled = true\n\n\
        [overlay]\nmode = \"gossip\"\noutbound_target = {target_degree}\npeer_gossip_interval_ms = 250\nmesh_check_interval_ms = 250\nbootstrap_addrs = [{bootstrap_toml}]\n\n\
        [consensus]\nvalidators = [{validators_toml}]\npropose_limit = 64\ntimeout_base_ms = 200\ntimeout_max_ms = 2000\n"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    run_init(config_file.path().to_str().unwrap());

    let bin = env!("CARGO_BIN_EXE_boule");
    let child = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn inbound-disabled consensus node");

    // 30s headroom for a spawned binary to bind + write addr_file under
    // CI's oversubscribed parallelism (#303).
    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("inbound-disabled node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break addrs;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = addrs.api_addr.rsplit(':').next().unwrap().parse().unwrap();

    NodeGuard {
        child,
        api_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: tempfile::tempdir().unwrap(),
        _addr_file: addr_file,
    }
}

/// Issue #138 acceptance test: a four-node gossip cluster where node 3
/// is configured with `[p2p] inbound_disabled = true`. Asserts:
///
/// 1. Every node — including the unreachable one — commits at steady
///    state (proves consensus traffic flows over the connection node 3
///    initiated).
/// 2. The reachable nodes' `/peers` endpoints list node 3 as a peer
///    (because it dialed in to one of them and the gossip overlay
///    propagated the connection through the partial mesh).
/// 3. The reachable nodes never attempted to dial node 3 — verified
///    indirectly by the fact that node 3's listener never bound (the
///    listener task is only spawned when `inbound_disabled = false`),
///    so any spurious dial would fail with connection-refused and node
///    3 would have zero direct peers, contradicting (2).
#[tokio::test]
async fn test_inbound_disabled_node_participates_via_outbound_only() {
    const N: usize = 4;
    const UNREACHABLE_IDX: usize = 3;

    let key_dirs: Vec<tempfile::TempDir> = (0..N).map(|_| tempfile::tempdir().unwrap()).collect();
    let key_paths: Vec<String> = key_dirs
        .iter()
        .map(|d| d.path().join("node.key").to_str().unwrap().to_owned())
        .collect();

    // Phase 1: discover everyone's identity. Reachable nodes (0..3)
    // also discover their bound P2P addresses; node 3 binds during
    // phase-1 discovery (which uses the default config) but won't bind
    // in phase 2 — its addr is unused after phase 1.
    let mut specs: Vec<ConsensusNodeSpec> = Vec::with_capacity(N);
    for key_path in &key_paths {
        let info = launch_once_for_discovery(key_path).await;
        specs.push(ConsensusNodeSpec {
            key_path: key_path.clone(),
            p2p_addr: info.p2p_addr,
            node_id: info.node_id,
        });
    }

    let validators_toml = specs
        .iter()
        .map(|s| format!("\"{}\"", s.node_id))
        .collect::<Vec<_>>()
        .join(", ");

    // Phase 2: relaunch.
    //
    // Node 0: gossip overlay, no bootstrap (others connect to it).
    // Nodes 1, 2: gossip overlay, bootstrap via node 0.
    // Node 3:    gossip overlay + inbound_disabled, bootstrap via node 0.
    //
    // The cluster topology: node 3 only ever reaches the rest via the
    // outbound TCP connection it initiated to node 0; the partial-mesh
    // maintenance loop on every other node sees node 3 advertised as
    // reachable=false (issue #138's reachability gossip) and never
    // attempts to dial back.
    let mut guards: Vec<NodeGuard> = Vec::with_capacity(N);
    for (i, spec) in specs.iter().enumerate() {
        let bootstrap = if i == 0 {
            Vec::new()
        } else {
            vec![specs[0].p2p_addr.clone()]
        };
        let g = if i == UNREACHABLE_IDX {
            spawn_consensus_node_inbound_disabled(
                &spec.key_path,
                &bootstrap,
                &validators_toml,
                /* target_degree */ 3,
            )
            .await
        } else {
            spawn_consensus_node_gossip(
                &spec.key_path,
                &spec.p2p_addr,
                &bootstrap,
                &validators_toml,
                /* target_degree */ 3,
                /* peer_gossip_interval_ms */ 250,
                /* mesh_check_interval_ms  */ 250,
            )
            .await
        };
        guards.push(g);
    }

    let ready_timeout = Duration::from_secs(10);
    for g in &guards {
        wait_until_ready(g, ready_timeout).await;
    }

    // (1) Every node — including the inbound-disabled one — commits.
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    'outer: loop {
        if Instant::now() > deadline {
            panic!("4-node cluster with one inbound-disabled node did not commit within 15s");
        }
        for g in &guards {
            let resp = client.get(g.api_url("/consensus/status")).send().await;
            let body: Value = match resp {
                Ok(r) if r.status() == 200 => r.json().await.unwrap_or(Value::Null),
                _ => Value::Null,
            };
            let committed = body["last_committed_height"].as_u64().unwrap_or(0);
            if committed == 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue 'outer;
            }
        }
        break;
    }

    // (2) The unreachable node established at least one direct peer
    // (the gossip overlay routed via the connection it dialed). It also
    // commits, which it could not without ingress on that connection.
    let unreachable = &guards[UNREACHABLE_IDX];
    wait_for_peer_count(unreachable, 1, Duration::from_secs(10)).await;

    drop(guards);
    drop(key_dirs);
}

// ── `config` subcommand tests (issue #148) ──────────────────────────────────
//
// These tests exercise the binary directly — no node is spawned, since the
// subcommand reads/edits config files synchronously and never opens
// listeners. Every test writes a self-contained config in a temp dir and
// invokes `cargo`-built `boule config ...`.

const SAMPLE_CONFIG: &str = r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path    = "/tmp/boule-config-test/node.key"

[api]
listen_addr = "127.0.0.1:8000"

[consensus]
validators = ["abc", "def"]
"#;

fn write_sample_config(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, SAMPLE_CONFIG).expect("write sample config");
    path
}

fn run_config(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_boule");
    Command::new(bin)
        .arg("config")
        .args(args)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn `boule config`")
}

#[test]
fn test_config_path_prints_resolved_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&["--config", path.to_str().unwrap(), "--path"]);
    assert!(
        out.status.success(),
        "config --path failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.trim(), path.to_str().unwrap());
}

#[test]
fn test_config_default_resolved_toml_round_trips() {
    // The acceptance criterion is that `--format toml` (the default)
    // produces output that re-parses to the same logical config — i.e.,
    // the resolved view is a valid config the node could load.
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&["--config", path.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "config (default) failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[node]"));
    assert!(stdout.contains("[node.identity]"));
    assert!(stdout.contains("[consensus]"));
    // Defaults filled in: timeout_base_ms is in [consensus] even
    // though the source file omitted it.
    assert!(stdout.contains("timeout_base_ms"));
    // [overlay] is fully synthesized from defaults — the source had
    // no [overlay] section at all.
    assert!(stdout.contains("[overlay]"));
    assert!(stdout.contains("mode = \"gossip\""));

    // Round-trip: write the resolved output to a new file and re-run
    // `config`. Output must match byte-for-byte.
    let round1 = dir.path().join("round1.toml");
    std::fs::write(&round1, &stdout).unwrap();
    let out2 = run_config(&["--config", round1.to_str().unwrap()]);
    assert!(
        out2.status.success(),
        "round-trip parse failed: stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let stdout2 = String::from_utf8(out2.stdout).unwrap();
    assert_eq!(stdout, stdout2, "TOML output must round-trip identically");
}

#[test]
fn test_config_format_json_emits_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&["--config", path.to_str().unwrap(), "--format", "json"]);
    assert!(
        out.status.success(),
        "config --format json failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: Value = serde_json::from_str(&stdout).expect("valid JSON");
    // Sanity-check the JSON document the documented `... | jq` recipe
    // would target.
    assert_eq!(parsed["node"]["listen_addr"], json!("127.0.0.1:7000"));
    assert_eq!(parsed["consensus"]["timeout_base_ms"], json!(200));
    assert_eq!(parsed["overlay"]["mode"], json!("gossip"));
}

#[test]
fn test_config_raw_prints_file_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&["--config", path.to_str().unwrap(), "--raw"]);
    assert!(
        out.status.success(),
        "config --raw failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout, SAMPLE_CONFIG);
}

#[test]
fn test_config_raw_with_format_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&[
        "--config",
        path.to_str().unwrap(),
        "--raw",
        "--format",
        "json",
    ]);
    assert!(!out.status.success(), "--raw + --format must be rejected");
}

#[test]
fn test_config_edit_with_noop_editor_succeeds() {
    // `EDITOR=true` exits 0 immediately without modifying the file —
    // the most basic happy-path: editor opens, user makes no change.
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let bin = env!("CARGO_BIN_EXE_boule");
    let out = Command::new(bin)
        .args(["config", "--config", path.to_str().unwrap(), "--edit"])
        .env("EDITOR", "true")
        .env_remove("VISUAL")
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn config --edit");
    assert!(
        out.status.success(),
        "config --edit (noop editor) must succeed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("config validated"),
        "expected validation message, got: {stdout}"
    );
}

#[test]
fn test_config_edit_aborts_on_nonzero_editor_exit() {
    // `EDITOR=false` always exits 1 — the convention for "editor
    // aborted, do not save". `vim :cq` produces the same.
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let bin = env!("CARGO_BIN_EXE_boule");
    let out = Command::new(bin)
        .args(["config", "--config", path.to_str().unwrap(), "--edit"])
        .env("EDITOR", "false")
        .env_remove("VISUAL")
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn config --edit");
    assert!(
        !out.status.success(),
        "config --edit must propagate editor failure"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("exited"),
        "expected editor-exit diagnostic, got: {stderr}"
    );
}

#[test]
fn test_config_edit_rejects_invalid_save() {
    // Use a tiny shell script as the "editor" that overwrites the
    // file with garbage TOML, then exits 0 (mimicking an operator who
    // saved a typo). The post-edit re-parse must fail.
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let editor_script = dir.path().join("bad-editor.sh");
    std::fs::write(
        &editor_script,
        "#!/bin/sh\nprintf 'this = is = not = toml\\n' > \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&editor_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&editor_script, perms).unwrap();
    }
    let bin = env!("CARGO_BIN_EXE_boule");
    let out = Command::new(bin)
        .args(["config", "--config", path.to_str().unwrap(), "--edit"])
        .env("EDITOR", editor_script.to_str().unwrap())
        .env_remove("VISUAL")
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn config --edit");
    assert!(
        !out.status.success(),
        "config --edit must reject an invalid post-edit file"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no longer valid") || stderr.contains("error"),
        "expected validation diagnostic, got: {stderr}"
    );
}

#[test]
fn test_config_edit_errors_when_file_missing() {
    // `--edit` requires an existing file — there's nothing to open
    // otherwise. Operators are pointed at `init` instead.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.toml");
    let bin = env!("CARGO_BIN_EXE_boule");
    let out = Command::new(bin)
        .args(["config", "--config", missing.to_str().unwrap(), "--edit"])
        .env("EDITOR", "true")
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn config --edit");
    assert!(!out.status.success(), "missing file must be an error");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("init") || stderr.contains("no config"),
        "expected init pointer, got: {stderr}"
    );
}

// ── `[ui] output_format` config + override (issue #149) ─────────────────────
//
// These tests pin the contract: `[ui] output_format` in the config sets the
// default for subcommands with structured output, and the per-invocation
// `--format` flag overrides it. Today only `config` honours it; future
// subcommands (`status`, `peers list`, ...) will inherit the convention via
// the `boule_core::cli` helpers.

const CONFIG_WITH_UI_JSON: &str = r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path    = "/tmp/boule-config-test/node.key"

[api]
listen_addr = "127.0.0.1:8000"

[ui]
output_format = "json"
"#;

const CONFIG_WITH_UI_HUMAN: &str = r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path    = "/tmp/boule-config-test/node.key"

[api]
listen_addr = "127.0.0.1:8000"

[ui]
output_format = "human"
"#;

fn write_config(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, contents).expect("write config");
    path
}

#[test]
fn test_config_ui_output_format_json_is_the_default() {
    // `[ui] output_format = "json"` with no `--format` → JSON output.
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), CONFIG_WITH_UI_JSON);
    let out = run_config(&["--config", path.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "config (with [ui] output_format = json) failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: Value = serde_json::from_str(&stdout)
        .expect("[ui] output_format = json must produce JSON by default");
    assert_eq!(parsed["node"]["listen_addr"], json!("127.0.0.1:7000"));
    assert_eq!(parsed["ui"]["output_format"], json!("json"));
}

#[test]
fn test_config_cli_format_overrides_ui_default() {
    // `[ui] output_format = "json"` + `--format toml` → TOML wins.
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), CONFIG_WITH_UI_JSON);
    let out = run_config(&["--config", path.to_str().unwrap(), "--format", "toml"]);
    assert!(
        out.status.success(),
        "config --format toml override failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[node]"), "expected TOML, got: {stdout}");
    assert!(stdout.contains("[ui]"), "expected TOML, got: {stdout}");
    // Sanity: TOML, not JSON.
    assert!(
        serde_json::from_str::<Value>(&stdout).is_err(),
        "override must produce TOML, but it parsed as JSON"
    );
}

#[test]
fn test_config_ui_output_format_human_falls_back_to_toml() {
    // `[ui] output_format = "human"` is the global default; for the
    // `config` subcommand specifically, `human` falls back to TOML
    // since that mirrors the source schema.
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), CONFIG_WITH_UI_HUMAN);
    let out = run_config(&["--config", path.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "config (with [ui] output_format = human) failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[node]"));
    assert!(stdout.contains("output_format = \"human\""));
}

#[test]
fn test_config_cli_format_human_falls_back_to_toml_for_config() {
    // Operator passes `--format human` explicitly with no `[ui]`
    // section in the file. `config`'s human fallback is TOML, so we
    // still get TOML.
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&["--config", path.to_str().unwrap(), "--format", "human"]);
    assert!(
        out.status.success(),
        "config --format human failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[node]"), "expected TOML, got: {stdout}");
}

#[test]
fn test_config_rejects_unknown_format_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_sample_config(dir.path());
    let out = run_config(&["--config", path.to_str().unwrap(), "--format", "yaml"]);
    assert!(
        !out.status.success(),
        "unknown --format value must be rejected"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("yaml") || stderr.contains("expected"),
        "expected diagnostic naming the bad value, got: {stderr}"
    );
}

// ── Self-dial guards (#188) ─────────────────────────────────────────────────

/// A static `[[peers]]` entry whose `node_id` matches the local TLS
/// identity must fail at boot via `Config::validate`. Catches the
/// "every node ships with the same canned peer list" deployment
/// footgun before the dialer ever runs.
#[tokio::test]
async fn test_self_id_in_peers_list_fails_to_start() {
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("node.key").to_str().unwrap().to_owned();

    // Phase 1: discover this node's NodeId so we can name it as a self-
    // peer in phase 2.
    let info = launch_once_for_discovery(&key_path).await;

    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();
    let config = format!(
        "[node]\nlisten_addr = \"127.0.0.1:0\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n\n\
        [[peers]]\naddr = \"127.0.0.1:9999\"\nnode_id = \"{}\"\n",
        info.node_id,
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_boule");
    let output = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .output()
        .expect("failed to spawn node binary");

    assert!(
        !output.status.success(),
        "node must refuse to start when [[peers]] contains its own NodeId; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("self-dial") || stderr.contains("own NodeId"),
        "stderr must explain the self-dial reason; got: {stderr}",
    );
    assert!(
        stderr.contains(&info.node_id) || stderr.contains("[[peers]]"),
        "stderr must point at the offending entry; got: {stderr}",
    );
}

/// A TOFU `[[peers]]` entry (no `node_id`) that resolves to our own
/// listener can't be caught at config-validation time — the peer's
/// identity is only known after the handshake. The dialer's
/// handshake-time guard (and the listener's symmetric guard on the
/// inbound side) must drop the resulting self-loopback so it never
/// shows up in `/peers`.
#[tokio::test]
async fn test_self_loopback_dial_is_refused_at_handshake() {
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("node.key").to_str().unwrap().to_owned();

    // Phase 1: discover the listen addr so phase 2 can re-bind on it.
    let info = launch_once_for_discovery(&key_path).await;

    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();
    let p2p_addr = info.p2p_addr.clone();
    // [[peers]] has no `node_id` — config validation can't tell this
    // is self. The dialer must catch it at TLS-handshake time.
    let config = format!(
        "[node]\nlisten_addr = \"{p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n\n\
        [[peers]]\naddr = \"{p2p_addr}\"\n",
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_boule");
    let child = Command::new(bin)
        .args(["start", "--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn node binary");

    // Wait for the node to bind both listeners. 30s headroom for a
    // spawned binary to bind + write addr_file under CI's oversubscribed
    // parallelism (#303).
    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("self-loopback node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty() {
            if let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content) {
                break addrs;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let api_port: u16 = addrs.api_addr.rsplit(':').next().unwrap().parse().unwrap();

    let guard = NodeGuard {
        child,
        api_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: key_dir,
        _addr_file: addr_file,
    };

    wait_until_ready(&guard, Duration::from_secs(10)).await;

    // Watch /peers for ~2s — long enough for at least two dialer
    // attempts (initial backoff is 1s) plus a maintenance tick. The
    // count must stay zero: any successful self-dial would surface
    // here immediately.
    let client = reqwest::Client::new();
    let watch_end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < watch_end {
        let peers: Value = client
            .get(guard.api_url("/peers"))
            .send()
            .await
            .expect("/peers request failed")
            .json()
            .await
            .expect("/peers returned non-JSON");
        let count = peers.as_array().map(|a| a.len()).unwrap_or(0);
        assert_eq!(
            count, 0,
            "self-loopback peer surfaced in /peers — handshake guard failed",
        );
        // Sampling cadence, not a wait: this loop verifies the peer count
        // *stays* at 0 across a window — there is no positive observable to
        // early-exit on, so a fixed real-time cadence is correct.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
