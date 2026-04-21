use std::io::Write;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tempfile::NamedTempFile;

// Ports used by the three-node cluster in tests.
// Using high port numbers to avoid conflicts with common services.
const P2P_PORT_1: u16 = 19001;
const P2P_PORT_2: u16 = 19002;
const P2P_PORT_3: u16 = 19003;
const API_PORT_1: u16 = 19101;
const API_PORT_2: u16 = 19102;
const API_PORT_3: u16 = 19103;

struct NodeGuard {
    child: Child,
    api_port: u16,
    _config: NamedTempFile,
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

fn spawn_node(p2p_port: u16, api_port: u16, peers: &[u16]) -> NodeGuard {
    let peer_lines: String = peers
        .iter()
        .map(|p| format!("\n[[peers]]\naddr = \"127.0.0.1:{p}\"\n"))
        .collect();

    let config = format!(
        "[node]\nlisten_addr = \"127.0.0.1:{p2p_port}\"\n\n[api]\nlisten_addr = \"127.0.0.1:{api_port}\"\ncleanup_interval_secs = 5\n{peer_lines}",
    );

    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config.as_bytes()).unwrap();
    config_file.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_ambros-p2p");
    let child = Command::new(bin)
        .args(["--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG", "warn") // keep test output quiet
        .spawn()
        .expect("failed to spawn node binary");

    NodeGuard {
        child,
        api_port,
        _config: config_file,
    }
}

async fn wait_until_ready(node: &NodeGuard, timeout: Duration) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            panic!("node on port {} did not become ready in time", node.api_port);
        }
        if client
            .get(node.api_url("/messages"))
            .send()
            .await
            .is_ok()
        {
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

/// Start a three-node fully-connected cluster and return the nodes.
async fn start_cluster() -> (NodeGuard, NodeGuard, NodeGuard) {
    let node1 = spawn_node(P2P_PORT_1, API_PORT_1, &[P2P_PORT_2, P2P_PORT_3]);
    let node2 = spawn_node(P2P_PORT_2, API_PORT_2, &[P2P_PORT_1, P2P_PORT_3]);
    let node3 = spawn_node(P2P_PORT_3, API_PORT_3, &[P2P_PORT_1, P2P_PORT_2]);

    let ready_timeout = Duration::from_secs(10);
    wait_until_ready(&node1, ready_timeout).await;
    wait_until_ready(&node2, ready_timeout).await;
    wait_until_ready(&node3, ready_timeout).await;

    // Wait for at least 2 peers on each node (fully connected mesh).
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
    assert_eq!(count, 1, "expected exactly one copy after dedup, got {count}");
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
