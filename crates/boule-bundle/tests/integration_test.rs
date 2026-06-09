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
    /// Admin listener address, present when `[api.admin] listen_addr` is set.
    /// The internal-state reads `/consensus/status` + `/peers` moved here (#823).
    #[serde(default)]
    admin_addr: Option<String>,
}

/// Parse the `host:port` tail of an addr-file address into a port.
fn port_of(addr: &str) -> u16 {
    addr.rsplit(':').next().unwrap().parse().unwrap()
}

struct NodeGuard {
    child: Child,
    api_port: u16,
    /// Admin-listener port, when the node was configured with `[api.admin]`.
    admin_port: Option<u16>,
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

    /// URL on the admin listener. The internal-state reads `/consensus/status`
    /// and `/peers` live here now (#823), so the harness spins up an admin
    /// listener for every node and queries them through this.
    fn admin_url(&self, path: &str) -> String {
        let port = self
            .admin_port
            .expect("admin listener not configured for this node");
        format!("http://127.0.0.1:{port}{path}")
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

/// Spawn a node with port 0 for both listeners. The node writes its actual
/// bound addresses and node ID to a temp file; we poll until the file is
/// populated and parse the real values — no TOCTOU window, no reserved-port races.
async fn spawn_node(peers: &[PeerDesc<'_>]) -> NodeGuard {
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

    let config = format!(
        "[node]\nlisten_addr = \"127.0.0.1:0\"\nkey_file = \"{key_file_path}\"\naddr_file = \"{addr_file_path}\"\n\n[api]\nlisten_addr = \"127.0.0.1:0\"\n[api.admin]\nlisten_addr = \"127.0.0.1:0\"\n{peer_lines}"
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
        if !content.is_empty()
            && let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content)
        {
            break addrs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = port_of(&addrs.api_addr);
    let admin_port: Option<u16> = addrs.admin_addr.as_deref().map(port_of);

    NodeGuard {
        child,
        api_port,
        admin_port,
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
        // Probe the public observability listener (`/ready` is always served
        // there); the internal-state reads moved to the admin listener (#823).
        if client.get(node.api_url("/ready")).send().await.is_ok() {
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
        if let Ok(resp) = client.get(node.admin_url("/peers")).send().await
            && let Ok(peers) = resp.json::<Value>().await
            && peers.as_array().map(|a| a.len()).unwrap_or(0) >= expected
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
        if !content.is_empty()
            && let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content)
        {
            break DiscoveryInfo {
                p2p_addr: addrs.p2p_addr,
                node_id: addrs.node_id,
            };
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
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n[api]\nlisten_addr = \"127.0.0.1:0\"\n[api.admin]\nlisten_addr = \"127.0.0.1:0\"\n{peer_lines}"
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
        if !content.is_empty()
            && let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content)
        {
            break addrs;
        }
        // Reap-and-retry on an early exit (the EADDRINUSE bind race).
        // `try_wait` reaps the process when it reports `Some`.
        if matches!(child.try_wait(), Ok(Some(_))) {
            child = spawn_child();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = port_of(&addrs.api_addr);
    let admin_port: Option<u16> = addrs.admin_addr.as_deref().map(port_of);

    // The key_dir is owned by the test function (so the key survives the
    // phase-1 shutdown); hand this guard a throwaway TempDir to keep the
    // Drop invariant simple.
    let placeholder_dir = tempfile::tempdir().unwrap();

    NodeGuard {
        child,
        api_port,
        admin_port,
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

// ── Consensus status endpoint (#123) ────────────────────────────────────────

/// Node spec used by [`start_consensus_cluster`]: a node IDs in the
/// committee has a stable key path (so phase 1 / phase 2 re-spawn
/// preserves identity) and a pre-bound P2P address.
struct ConsensusNodeSpec {
    key_path: String,
    p2p_addr: String,
    node_id: String,
    /// Path to this node's minted BLS validator-signing key. The node
    /// loads it via `[node.bls_validator_identity]` to produce vote
    /// partials.
    bls_key_path: String,
}

/// One `[[consensus.validators_bls]]` genesis row: base58 NodeId,
/// hex-encoded 48-byte BLS pubkey, hex-encoded 96-byte chain-bound PoP.
/// Mirrors the testnet driver's `BlsGenesisEntry`
/// (`boule-node/src/testnet/lifecycle.rs`).
#[derive(Clone)]
struct BlsGenesisEntry {
    node_id: String,
    bls_pubkey_hex: String,
    bls_pop_hex: String,
}

/// Mint a BLS keypair per validator, derive the deployment chain_id
/// from the genesis parts, and sign a chain-bound PoP per validator —
/// the exact recipe `mint_bls_keys_if_needed`
/// (`boule-node/src/testnet/lifecycle.rs`) uses. `specs` carries each
/// node's base58 node_id (collected in phase 1); the minted BLS key
/// path is written back into each spec so the per-node config can
/// reference it under `[node.bls_validator_identity]`.
///
/// BLS is the only consensus scheme now, so the cluster always needs a
/// valid `[consensus.validators_bls]` table to boot.
fn mint_bls_genesis(
    specs: &mut [ConsensusNodeSpec],
    key_dirs: &[tempfile::TempDir],
) -> Vec<BlsGenesisEntry> {
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
    use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey};
    use boule_core::identity::{NodeId, base58_to_node_id};

    // Pass 1: provision each validator's BLS key file and collect
    // (node_id, secret, pubkey). PoPs are deferred until the chain_id
    // is known.
    let mut node_id_bytes: Vec<NodeId> = Vec::with_capacity(specs.len());
    let mut pubkeys: Vec<(NodeId, BlsPublicKey)> = Vec::with_capacity(specs.len());
    let mut secrets = Vec::with_capacity(specs.len());
    for (spec, dir) in specs.iter_mut().zip(key_dirs) {
        let bls_path = dir.path().join("bls.key");
        let identity = BlsKeyFile::new(bls_path.clone())
            .load_or_init()
            .expect("minting BLS validator key");
        let nid = base58_to_node_id(&spec.node_id).expect("valid base58 node_id");
        node_id_bytes.push(nid);
        pubkeys.push((nid, identity.public));
        secrets.push(identity.secret);
        spec.bls_key_path = bls_path.to_str().unwrap().to_owned();
    }

    // Pass 2: derive the deployment chain_id from the genesis parts
    // (validators + BLS pubkeys, no operator keys, default all-zeros
    // seed — matching a config that omits `genesis_seed_hex`), then
    // mint a chain-bound PoP per validator (#410).
    let chain_id = boule_consensus::genesis::derive_chain_id_from_parts(
        &node_id_bytes,
        &pubkeys,
        &[],
        [0u8; 32],
    );

    specs
        .iter()
        .zip(pubkeys.iter())
        .zip(secrets.iter())
        .map(|((spec, (_, pubkey)), secret)| {
            let pop = BlsAggregated::sign_pop(secret, &chain_id).expect("signing BLS PoP");
            BlsGenesisEntry {
                node_id: spec.node_id.clone(),
                bls_pubkey_hex: hex::encode(pubkey),
                bls_pop_hex: hex::encode(pop.sig),
            }
        })
        .collect()
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
            bls_key_path: String::new(),
        });
    }

    // Phase 1b: mint the BLS genesis table now that every validator's
    // base58 node_id is known. BLS is the only consensus scheme, so the
    // cluster cannot boot without a valid `[consensus.validators_bls]`
    // table + per-node BLS signing key.
    let bls_genesis = mint_bls_genesis(&mut specs, &key_dirs);

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
                &spec.bls_key_path,
                &bls_genesis,
            )
            .await,
        );
    }

    // Generous failure-timeouts: readiness + libp2p gossipsub mesh
    // formation are sensitive to CI core contention and slower than the
    // old TCP transport's immediate connect. The happy path early-exits.
    let ready_timeout = Duration::from_secs(20);
    for g in &guards {
        wait_until_ready(g, ready_timeout).await;
    }

    let mesh_timeout = Duration::from_secs(20);
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
    bls_key_path: &str,
    bls_genesis: &[BlsGenesisEntry],
) -> NodeGuard {
    let addr_file = NamedTempFile::new().unwrap();
    let addr_file_path = addr_file.path().to_str().unwrap().to_owned();

    // libp2p discovery is driven by bootstrap_addrs (the gossip overlay's
    // [[peers]] peer-list was removed with the legacy transport).
    let bootstrap_toml: String = peers
        .iter()
        .map(|p| format!("\"{}\"", p.p2p_addr))
        .collect::<Vec<_>>()
        .join(", ");

    // BLS genesis (#360): BLS is the only consensus scheme, so every
    // node needs the `[[consensus.validators_bls]]` table the genesis
    // validator set requires plus its own `[node.bls_validator_identity]`
    // key file to produce vote partials. Mirrors `write_final_config`
    // in `boule-node/src/testnet/lifecycle.rs`.
    let mut validators_bls_toml = String::new();
    for e in bls_genesis {
        validators_bls_toml.push_str(&format!(
            "\n[[consensus.validators_bls]]\nnode_id    = \"{nid}\"\nbls_pubkey = \"{pk}\"\nbls_pop    = \"{pop}\"\n",
            nid = e.node_id,
            pk = e.bls_pubkey_hex,
            pop = e.bls_pop_hex,
        ));
    }

    // Use short timeouts + in-memory storage so the test commits
    // blocks within a few hundred ms. Without this a stock config
    // (timeout_base_ms = 200) still works, but shorter base keeps the
    // test tight.
    let config = format!(
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [node.bls_validator_identity]\nbackend = \"file\"\npath = \"{bls_key_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n[api.admin]\nlisten_addr = \"127.0.0.1:0\"\n\n\
        [overlay]\nmode = \"libp2p\"\nbootstrap_addrs = [{bootstrap_toml}]\n\n\
        [consensus]\nvalidators = [{validators_toml}]\npropose_limit = 64\ntimeout_base_ms = 200\ntimeout_max_ms = 2000\nallow_counter_state_machine = true\n\
        {validators_bls_toml}"
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
        if !content.is_empty()
            && let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content)
        {
            break addrs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = port_of(&addrs.api_addr);
    let admin_port: Option<u16> = addrs.admin_addr.as_deref().map(port_of);

    NodeGuard {
        child,
        api_port,
        admin_port,
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
        let resp = client.get(g.admin_url("/consensus/status")).send().await;
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
    // `current_view > 0`. Failure-timeout only: the happy path early-exits
    // in well under a second once the cluster commits, but libp2p
    // mesh-formation latency is sensitive to CI core contention, so the
    // bound is generous to cover the pathological-slow case.
    let deadline = Instant::now() + Duration::from_secs(30);
    'outer: loop {
        if Instant::now() > deadline {
            panic!("consensus cluster did not commit within 30s");
        }
        for g in &guards {
            let resp = client.get(g.admin_url("/consensus/status")).send().await;
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
            .get(g.admin_url("/consensus/status"))
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

// ── libp2p-overlay smoke test (#842) ─────────────────────────────────────────

/// Spawn a consensus-running node with `[overlay] mode = "libp2p"`. Unlike the
/// gossip overlay, Phase 2 libp2p has no peer-list gossip, so every node lists
/// every other node in `bootstrap_addrs` up front (full mesh).
async fn spawn_consensus_node_libp2p(
    key_path: &str,
    fixed_p2p_addr: &str,
    bootstrap_addrs: &[String],
    validators_toml: &str,
    bls_key_path: &str,
    bls_genesis: &[BlsGenesisEntry],
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

    // BLS genesis table + per-node signing key — required since BLS is
    // the only consensus scheme (mirrors `write_final_config` in the
    // testnet driver).
    let mut validators_bls_toml = String::new();
    for e in bls_genesis {
        validators_bls_toml.push_str(&format!(
            "\n[[consensus.validators_bls]]\nnode_id    = \"{nid}\"\nbls_pubkey = \"{pk}\"\nbls_pop    = \"{pop}\"\n",
            nid = e.node_id,
            pk = e.bls_pubkey_hex,
            pop = e.bls_pop_hex,
        ));
    }

    let config = format!(
        "[node]\nlisten_addr = \"{fixed_p2p_addr}\"\nkey_file = \"{key_path}\"\naddr_file = \"{addr_file_path}\"\n\n\
        [node.bls_validator_identity]\nbackend = \"file\"\npath = \"{bls_key_path}\"\n\n\
        [api]\nlisten_addr = \"127.0.0.1:0\"\n[api.admin]\nlisten_addr = \"127.0.0.1:0\"\n\n\
        [overlay]\nmode = \"libp2p\"\nbootstrap_addrs = {bootstrap_toml}\n\n\
        [consensus]\nvalidators = [{validators_toml}]\npropose_limit = 64\ntimeout_base_ms = 200\ntimeout_max_ms = 2000\nallow_counter_state_machine = true\n\
        {validators_bls_toml}"
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
        .expect("failed to spawn libp2p-overlay consensus node");

    let deadline = Instant::now() + Duration::from_secs(30);
    let addrs = loop {
        if Instant::now() > deadline {
            panic!("libp2p-overlay node did not write addr_file within 30s");
        }
        let content = std::fs::read_to_string(&addr_file_path).unwrap_or_default();
        if !content.is_empty()
            && let Ok(addrs) = serde_json::from_str::<NodeAddrs>(&content)
        {
            break addrs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let api_port: u16 = port_of(&addrs.api_addr);
    let admin_port: Option<u16> = addrs.admin_addr.as_deref().map(port_of);

    NodeGuard {
        child,
        api_port,
        admin_port,
        p2p_addr: addrs.p2p_addr,
        node_id: addrs.node_id,
        _config: config_file,
        _key_dir: tempfile::tempdir().unwrap(),
        _addr_file: addr_file,
    }
}

/// Boot an `n`-node consensus cluster over the libp2p overlay. Every node
/// bootstraps to every other node (full mesh) since Phase 2 has no peer
/// discovery yet (#844).
async fn start_libp2p_consensus_cluster(n: usize) -> (Vec<NodeGuard>, Vec<tempfile::TempDir>) {
    let key_dirs: Vec<tempfile::TempDir> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
    let key_paths: Vec<String> = key_dirs
        .iter()
        .map(|d| d.path().join("node.key").to_str().unwrap().to_owned())
        .collect();

    // Phase 1: discover each node's bound p2p addr + node_id (runs in the
    // default gossip mode on an OS-assigned port, then frees it).
    let mut specs: Vec<ConsensusNodeSpec> = Vec::with_capacity(n);
    for key_path in &key_paths {
        let info = launch_once_for_discovery(key_path).await;
        specs.push(ConsensusNodeSpec {
            key_path: key_path.clone(),
            p2p_addr: info.p2p_addr,
            node_id: info.node_id,
            bls_key_path: String::new(),
        });
    }

    // Mint the BLS genesis table (the only consensus scheme requires it).
    let bls_genesis = mint_bls_genesis(&mut specs, &key_dirs);

    let validators_toml = specs
        .iter()
        .map(|s| format!("\"{}\"", s.node_id))
        .collect::<Vec<_>>()
        .join(", ");

    // Phase 2: relaunch each node in libp2p mode bootstrapping to all others.
    let mut guards: Vec<NodeGuard> = Vec::with_capacity(n);
    for (i, spec) in specs.iter().enumerate() {
        let bootstrap: Vec<String> = specs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, s)| s.p2p_addr.clone())
            .collect();
        guards.push(
            spawn_consensus_node_libp2p(
                &spec.key_path,
                &spec.p2p_addr,
                &bootstrap,
                &validators_toml,
                &spec.bls_key_path,
                &bls_genesis,
            )
            .await,
        );
    }

    (guards, key_dirs)
}

/// 3-node smoke test for #842: consensus commits over the libp2p gossipsub
/// overlay end-to-end. No `/peers` assertion — in libp2p mode the boule TCP
/// manager is peerless (libp2p peers live in the Swarm), so liveness is the
/// real proof the overlay carries consensus traffic.
#[tokio::test]
async fn test_libp2p_overlay_3_node_smoke() {
    const N: usize = 3;
    let (guards, key_dirs) = start_libp2p_consensus_cluster(N).await;

    let client = reqwest::Client::new();
    // Failure-timeout only (the happy path early-exits in ~a few seconds once
    // the gossipsub mesh forms and the cluster commits). libp2p mesh-formation
    // latency is sensitive to CI core contention, so this is generous — it
    // bounds the pathological-slow case, not the expected duration.
    let deadline = Instant::now() + Duration::from_secs(60);
    'outer: loop {
        if Instant::now() > deadline {
            panic!("libp2p-overlay cluster did not commit within 60s");
        }
        for g in &guards {
            let resp = client.get(g.admin_url("/consensus/status")).send().await;
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
        .get(node.admin_url("/consensus/status"))
        .send()
        .await
        .expect("GET /consensus/status must reach the node");
    assert_eq!(
        resp.status(),
        404,
        "gossip-only node must return 404 on /consensus/status",
    );
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
    // no [overlay] section at all. libp2p is the default since the #840
    // cutover.
    assert!(stdout.contains("[overlay]"));
    assert!(stdout.contains("mode = \"libp2p\""));

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
    assert_eq!(parsed["overlay"]["mode"], json!("libp2p"));
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
