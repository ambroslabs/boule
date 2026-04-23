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
        let _ = self.child.kill();
        let _ = self.child.wait();
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

#[tokio::test]
async fn test_expired_messages_are_cleaned_up() {
    let (node1, node2, node3) = start_cluster().await;
    let _ = (&node2, &node3); // keep alive

    let client = reqwest::Client::new();
    // Expire in 2 seconds; cleanup_interval_secs = 5 in the test config.
    let expiry = expiry_from_now(2);

    let resp = client
        .post(node1.api_url("/messages"))
        .json(&json!({ "content": "short lived", "expiry": expiry }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Message should be visible immediately.
    let msgs: Value = client
        .get(node1.api_url("/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        msgs.as_array()
            .unwrap()
            .iter()
            .any(|m| m["content"] == "short lived"),
        "message should be visible before expiry"
    );

    // Wait past expiry + one cleanup cycle (2s expiry + 5s interval + 1s buffer = 8s).
    tokio::time::sleep(Duration::from_secs(8)).await;

    let msgs: Value = client
        .get(node1.api_url("/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !msgs
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["content"] == "short lived"),
        "message should be gone after cleanup"
    );
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
    let fake_peer = "11111111111111111111111111111111";

    let client = reqwest::Client::new();
    let resp = client
        .post(node.api_url(&format!("/rpc/ping/{fake_peer}")))
        .json(&json!({ "payload": "lost in space" }))
        .send()
        .await
        .expect("POST /rpc/ping failed");
    // 504 Gateway Timeout — handler maps RpcError::Timeout to that status.
    assert_eq!(resp.status(), 504);
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
