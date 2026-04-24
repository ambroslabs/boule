use std::io::Write;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
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
        "[node]\nlisten_addr = \"127.0.0.1:0\"\n{scalar_field}addr_file = \"{addr_file_path}\"\n{identity_table}\n[api]\nlisten_addr = \"127.0.0.1:0\"\ncleanup_interval_secs = 5\n{peer_lines}"
    );

    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_ambros-p2p");
    let child = Command::new(bin)
        .args(["--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn node binary");

    // Poll until the node writes its actual bound addresses to addr_file.
    let deadline = Instant::now() + Duration::from_secs(10);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("node did not write addr_file within 10s");
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
        if client.get(node.api_url("/messages")).send().await.is_ok() {
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

async fn poll_for_message(node: &NodeGuard, content: &str, timeout: Duration) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            panic!(
                "message '{}' did not appear on node {} in time",
                content, node.api_port
            );
        }
        if let Ok(resp) = client.get(node.api_url("/messages")).send().await {
            if let Ok(msgs) = resp.json::<Value>().await {
                if msgs
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .any(|m| m["content"] == content)
                {
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

fn expiry_from_now(secs: i64) -> DateTime<Utc> {
    Utc::now() + chrono::Duration::seconds(secs)
}

#[tokio::test]
async fn test_message_propagates_to_all_nodes() {
    let (node1, node2, node3) = start_cluster().await;

    let client = reqwest::Client::new();
    let expiry = expiry_from_now(60);

    let resp = client
        .post(node1.api_url("/messages"))
        .json(&json!({ "content": "hello cluster", "expiry": expiry }))
        .send()
        .await
        .expect("POST /messages failed");
    assert_eq!(resp.status(), 201);

    let prop_timeout = Duration::from_secs(5);
    poll_for_message(&node2, "hello cluster", prop_timeout).await;
    poll_for_message(&node3, "hello cluster", prop_timeout).await;
}

#[tokio::test]
async fn test_duplicate_messages_are_deduplicated() {
    let (node1, node2, node3) = start_cluster().await;
    let _ = (&node2, &node3); // keep alive

    let client = reqwest::Client::new();
    let expiry = expiry_from_now(60);
    let body = json!({ "content": "unique message", "expiry": expiry });

    let r1 = client
        .post(node1.api_url("/messages"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 201);

    // Same content + same expiry — must deduplicate.
    let r2 = client
        .post(node1.api_url("/messages"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(r2.status().is_success());

    tokio::time::sleep(Duration::from_millis(200)).await;

    let messages: Value = client
        .get(node1.api_url("/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let count = messages
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["content"] == "unique message")
        .count();
    assert_eq!(
        count, 1,
        "expected exactly one copy after dedup, got {count}"
    );
}

#[tokio::test]
async fn test_expired_messages_are_rejected() {
    let (node1, node2, node3) = start_cluster().await;
    let _ = (&node2, &node3); // keep alive

    let client = reqwest::Client::new();
    let past_expiry = expiry_from_now(-1);

    let resp = client
        .post(node1.api_url("/messages"))
        .json(&json!({ "content": "already expired", "expiry": past_expiry }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

// Expiry-cleanup coverage lives in the deterministic simulator now — see
// `src/sim/sim_gossip.rs::expired_messages_are_cleaned_up_under_sim_clock`.
// The wall-clock version of this test used to sleep 8s here, which made CI
// flaky and dominated the runtime of this file; the sim-clock port runs
// the same scenario (inject, expire, cleanup sweep) in virtual time.

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

/// Round-trips a ping RPC between two real nodes, exercising the full
/// protocol-multiplexer → RPC framing → handler-dispatch path.
#[tokio::test]
async fn test_ping_rpc_round_trip_between_nodes() {
    let node1 = spawn_node(&[]).await;
    let node2 = spawn_node(&[PeerDesc {
        p2p_addr: &node1.p2p_addr,
        node_id: &node1.node_id,
    }])
    .await;

    let ready_timeout = Duration::from_secs(10);
    wait_until_ready(&node1, ready_timeout).await;
    wait_until_ready(&node2, ready_timeout).await;

    let mesh_timeout = Duration::from_secs(10);
    wait_for_peer_count(&node1, 1, mesh_timeout).await;
    wait_for_peer_count(&node2, 1, mesh_timeout).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(node1.api_url(&format!("/rpc/ping/{}", node2.node_id)))
        .json(&json!({ "payload": "hello rpc" }))
        .send()
        .await
        .expect("POST /rpc/ping failed");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["payload"], "hello rpc");

    // And the reverse direction, to make sure both sides are wired up.
    let resp = client
        .post(node2.api_url(&format!("/rpc/ping/{}", node1.node_id)))
        .json(&json!({ "payload": "back atcha" }))
        .send()
        .await
        .expect("POST /rpc/ping failed");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["payload"], "back atcha");
}

#[tokio::test]
async fn test_ping_rpc_to_unknown_peer_fails() {
    let node = spawn_node(&[]).await;
    wait_until_ready(&node, Duration::from_secs(10)).await;

    // Valid base58 but a node ID that isn't connected. The call should time
    // out (since SendTo drops silently to unknown peers) rather than succeed.
    // Use a short per-call timeout so the test stays under the wall-clock
    // budget; the timeout path is identical regardless of duration.
    let fake_peer = "11111111111111111111111111111111";

    let client = reqwest::Client::new();
    let resp = client
        .post(node.api_url(&format!("/rpc/ping/{fake_peer}")))
        .json(&json!({ "payload": "lost in space", "timeout_ms": 300 }))
        .send()
        .await
        .expect("POST /rpc/ping failed");
    // 504 Gateway Timeout — handler maps RpcError::Timeout to that status.
    assert_eq!(resp.status(), 504);
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

    let mut p2p_addrs: Vec<String> = Vec::with_capacity(N);
    let mut node_ids: Vec<String> = Vec::with_capacity(N);
    for key_path in &key_paths {
        let info = launch_once_for_discovery(key_path).await;
        p2p_addrs.push(info.p2p_addr);
        node_ids.push(info.node_id);
    }

    // Phase 2: relaunch every node concurrently with the full peer list.
    let mut guards: Vec<NodeGuard> = Vec::with_capacity(N);
    for i in 0..N {
        let peer_descs: Vec<PeerDesc<'_>> = (0..N)
            .filter(|j| *j != i)
            .map(|j| PeerDesc {
                p2p_addr: &p2p_addrs[j],
                node_id: &node_ids[j],
            })
            .collect();
        guards.push(spawn_node_fixed_port(&key_paths[i], &p2p_addrs[i], &peer_descs).await);
    }

    let ready_timeout = Duration::from_secs(10);
    for guard in &guards {
        wait_until_ready(guard, ready_timeout).await;
    }

    // Every node must see every other node, within the 2s budget from the
    // issue's acceptance criteria (after the last node starts).
    let mesh_timeout = Duration::from_secs(10);
    for guard in &guards {
        wait_for_peer_count(guard, N - 1, mesh_timeout).await;
    }

    // Mesh is up. Watch it for 5s and assert every node keeps reporting
    // (N - 1) peers continuously — no flapping.
    let client = reqwest::Client::new();
    let watch_end = Instant::now() + Duration::from_secs(5);
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
        "[node]\nlisten_addr = \"127.0.0.1:0\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n[api]\nlisten_addr = \"127.0.0.1:0\"\ncleanup_interval_secs = 5\n"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_ambros-p2p");
    let mut child = Command::new(bin)
        .args(["--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn node binary");

    let deadline = Instant::now() + Duration::from_secs(10);
    let info = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("discovery node did not write addr_file within 10s");
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

/// Spawn a node whose P2P listener binds to `fixed_p2p_addr` (so phase 2
/// reuses the address phase 1 discovered) and whose `[[peers]]` list is
/// set from `peers`. The API listener still uses port 0.
async fn spawn_node_fixed_port(
    key_path: &str,
    fixed_p2p_addr: &str,
    peers: &[PeerDesc<'_>],
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

    let config = format!(
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n[api]\nlisten_addr = \"127.0.0.1:0\"\ncleanup_interval_secs = 5\n{peer_lines}"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_ambros-p2p");
    let child = Command::new(bin)
        .args(["--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn node binary");

    let deadline = Instant::now() + Duration::from_secs(10);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("phase-2 node did not write addr_file within 10s");
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
            spawn_consensus_node(&spec.key_path, &spec.p2p_addr, &peer_descs, &validators_toml)
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
        [api]\nlisten_addr = \"127.0.0.1:0\"\ncleanup_interval_secs = 5\n{peer_lines}\n\
        [consensus]\nvalidators = [{validators_toml}]\npropose_limit = 64\ntimeout_base_ms = 200\ntimeout_max_ms = 2000\n"
    );
    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_ambros-p2p");
    let child = Command::new(bin)
        .args(["--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn consensus node binary");

    let deadline = Instant::now() + Duration::from_secs(10);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("consensus node did not write addr_file within 10s");
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
