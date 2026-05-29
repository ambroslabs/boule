//! Process-lifecycle management: spawn, kill, down, and the `new`
//! command's two-phase init flow.
//!
//! The two-phase init is the same trick the integration tests use
//! (`launch_once_for_discovery` in `tests/integration_test.rs`): start
//! every node briefly with empty `[[peers]]`, harvest its `node_id` +
//! actual bound P2P address from the addr_file the binary writes, then
//! re-write each config with the full topology before the cluster
//! actually goes up.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use rand::SeedableRng;
use rand::seq::IndexedRandom;
use rand_chacha::ChaCha20Rng;

use super::events;
use super::topology::{TopologySpec, generate};
use super::workdir::{
    NodeAddrFile, NodeLayout, PersistedSpec, State, node_dir_name, read_addr_file,
};

/// How long to wait for a freshly-spawned node to write its addr_file.
const ADDR_FILE_TIMEOUT: Duration = Duration::from_secs(15);
/// Grace period for SIGTERM before falling back to SIGKILL during `down`.
const TERM_GRACE: Duration = Duration::from_secs(3);

/// Context for the `testnet new` command.
pub struct NewArgs {
    pub workdir: PathBuf,
    pub spec: TopologySpec,
    pub binary: PathBuf,
    /// `timeout_base_ms` to write into each node's `[consensus]` block.
    /// Defaults to 200 — short enough that 4-node smoke tests commit in
    /// well under a second.
    pub timeout_base_ms: u64,
    pub timeout_max_ms: u64,
    /// Chain-level signature scheme (#360). On
    /// `SignatureSchemeChoice::BlsAggregated` the cluster setup mints
    /// a BLS keypair per node, computes per-validator PoPs, and writes
    /// a `[consensus.validators_bls]` genesis table + a
    /// `[node.bls_validator_identity]` reference per node config.
    pub signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice,
}

/// `testnet new`: lay out the workdir, generate the topology, mint
/// every node's identity via `boule init`, harvest each node's
/// `node_id`, and write the final per-node configs with the full
/// `[consensus].validators` list and the bootstrap `[[peers]]` block.
pub async fn new_cluster(args: NewArgs) -> anyhow::Result<State> {
    let NewArgs {
        workdir,
        spec,
        binary,
        timeout_base_ms,
        timeout_max_ms,
        signature_scheme,
    } = args;

    spec.validate()?;
    std::fs::create_dir_all(&workdir)
        .with_context(|| format!("creating workdir {}", workdir.display()))?;
    // Canonicalize so every per-node path written to state.json is
    // absolute. Otherwise `testnet new --workdir testnetN` records
    // cwd-relative paths and any subsequent subcommand from a
    // different cwd fails to open the log/key/addr files.
    let workdir = std::fs::canonicalize(&workdir)
        .with_context(|| format!("canonicalizing workdir {}", workdir.display()))?;

    if workdir.join(super::workdir::STATE_FILE).exists() {
        anyhow::bail!(
            "{} already contains a {} file — pick a fresh workdir or delete the existing one",
            workdir.display(),
            super::workdir::STATE_FILE
        );
    }

    let topo = generate(&spec)?;

    // Phase 1: lay out per-node directories + minimal configs (no
    // peers, no consensus), run `init`, and start the binary briefly
    // to discover the bound P2P address + node_id from the addr_file.
    //
    // The `init` step is sequential (cheap; no I/O contention worth
    // parallelizing). The discovery launch is parallelized — each node
    // is independent, has no peers configured, and the bottleneck is
    // process spawn + a short addr_file poll. Running them concurrently
    // turns N × ~100ms into max(~100ms) on small clusters and is the
    // difference between fitting and not fitting in the integration
    // test budget.
    let mut layouts: Vec<NodeLayout> = Vec::with_capacity(spec.nodes);
    for nt in &topo {
        let layout = node_layout(&workdir, nt.index, nt.bootstrap_peers.clone());
        std::fs::create_dir_all(layout.config_path.parent().unwrap())
            .with_context(|| format!("creating dir for {}", layout.display_name()))?;
        std::fs::create_dir_all(&layout.consensus_dir)
            .with_context(|| format!("creating {}", layout.consensus_dir.display()))?;
        write_minimal_config(&layout)?;
        run_init(&binary, &layout.config_path)
            .with_context(|| format!("init failed for {}", layout.display_name()))?;
        layouts.push(layout);
    }
    let bin_clone = binary.clone();
    let discoveries = futures_util::future::try_join_all(layouts.into_iter().map(|layout| {
        let bin = bin_clone.clone();
        async move {
            let info = launch_once_for_discovery(&bin, &layout)
                .await
                .with_context(|| format!("discovering addrs for {}", layout.display_name()))?;
            Ok::<_, anyhow::Error>((layout, info))
        }
    }))
    .await?;
    let mut nodes: Vec<NodeLayout> = Vec::with_capacity(discoveries.len());
    for (layout, info) in discoveries {
        nodes.push(NodeLayout {
            node_id: Some(info.node_id),
            p2p_addr: Some(info.p2p_addr.parse()?),
            api_addr: Some(info.api_addr.parse()?),
            ..layout
        });
    }
    nodes.sort_by_key(|n| n.index);

    // Phase 2a: on BLS chains, mint each node's BLS validator key now
    // (so we can pre-compute the genesis BLS table and bake the path
    // into the final config). On Ed25519 chains this is a no-op.
    //
    // PoPs are minted in two passes (#410): first the keypairs alone,
    // then — once we can compute the deployment's chain_id from the
    // (validators + bls_pubkeys) tuple — chain-bound PoPs over each
    // validator's pubkey. The single-pass version that lived here
    // before chain_id binding produced PoPs that would replay across
    // any deployment sharing those BLS keys.
    let bls_genesis = mint_bls_keys_if_needed(signature_scheme, &mut nodes)?;

    // Phase 2b: write the final per-node config with the full
    // [consensus] section + sparse [[peers]] block. On BLS chains the
    // `bls_genesis` table is woven in alongside the validator list.
    let validator_ids: Vec<String> = nodes
        .iter()
        .map(|n| n.node_id.clone().expect("node_id populated in phase 1"))
        .collect();
    for n in &nodes {
        write_final_config(
            n,
            &nodes,
            &validator_ids,
            spec.target_degree,
            timeout_base_ms,
            timeout_max_ms,
            signature_scheme,
            bls_genesis.as_deref(),
        )?;
    }

    let state = State {
        spec: PersistedSpec::from(spec),
        nodes,
    };
    state.save(&workdir)?;
    events::record(
        &workdir,
        "new",
        None,
        Some(&format!(
            "nodes={} seed_extra={} target={} seed={}",
            spec.nodes, spec.seed_extra, spec.target_degree, spec.seed
        )),
    );
    Ok(state)
}

fn node_layout(workdir: &Path, index: usize, bootstrap_peers: Vec<usize>) -> NodeLayout {
    let dir = workdir.join(node_dir_name(index));
    NodeLayout {
        index,
        config_path: dir.join("config.toml"),
        key_path: dir.join("node.key"),
        log_path: dir.join("log"),
        pid_path: dir.join("pid"),
        addr_path: dir.join("addr.json"),
        consensus_dir: dir.join("consensus"),
        bootstrap_peers,
        node_id: None,
        p2p_addr: None,
        api_addr: None,
        bls_key_path: None,
    }
}

/// One genesis-table entry built by [`mint_bls_keys_if_needed`].
/// Mirrors the `[consensus.validators_bls]` row shape — base58 NodeId,
/// hex-encoded 48-byte BLS pubkey, hex-encoded 96-byte PoP signature
/// over that pubkey.
struct BlsGenesisEntry {
    node_id: String,
    bls_pubkey_hex: String,
    bls_pop_hex: String,
}

/// On `bls_aggregated` chains: per-node, generate a fresh BLS keypair
/// and persist it to `<node_dir>/bls.key` via the same `BlsKeyFile`
/// provider production uses. Returns the ordered genesis table — one
/// entry per validator, in the same order as `nodes` (which is sorted
/// by index, matching the `[consensus] validators` ordering written to
/// every node's config). On Ed25519 chains: returns `None` and skips
/// all work.
///
/// Mutates each node's `NodeLayout::bls_key_path` so the final-config
/// writer can reference the on-disk path under
/// `[node.bls_validator_identity]`.
///
/// The PoP attached to each entry is derived against the deployment's
/// chain_id (#410), computed in-process from the genesis-block hash
/// over (validators, BLS pubkeys, default genesis seed). Without that
/// binding a PoP minted here would replay across any deployment that
/// happened to reuse the same validator BLS key.
fn mint_bls_keys_if_needed(
    scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice,
    nodes: &mut [NodeLayout],
) -> anyhow::Result<Option<Vec<BlsGenesisEntry>>> {
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
    use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, SignatureSchemeChoice};
    use boule_transport_tcp::tls::base58_to_node_id;
    if scheme == SignatureSchemeChoice::Ed25519Collected {
        return Ok(None);
    }

    // Pass 1: provision each validator's BLS key file on disk and
    // collect (NodeId, secret, pubkey). PoPs are deferred until the
    // chain_id is known.
    struct PendingEntry {
        node_id: String,
        node_id_bytes: boule_transport_tcp::tls::NodeId,
        secret: zeroize::Zeroizing<boule_core::crypto::sig_scheme::BlsSecretKey>,
        public: BlsPublicKey,
    }
    let mut pending: Vec<PendingEntry> = Vec::with_capacity(nodes.len());
    for n in nodes.iter_mut() {
        let dir = n
            .config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("config_path has no parent for {}", n.display_name()))?;
        let bls_path = dir.join("bls.key");
        // The testnet driver runs on the same machine as the node
        // binary; `BlsKeyFile::load_or_init` writes mode 0600 and
        // generates a fresh key on first call. Subsequent calls reload
        // the same key — this matters if `testnet new` is ever rerun
        // against an existing workdir (which `new_cluster` already
        // refuses, but the helper is idempotent regardless).
        let provider = BlsKeyFile::new(bls_path.clone());
        let identity = provider
            .load_or_init()
            .with_context(|| format!("minting BLS key for {}", n.display_name()))?;
        let node_id = n
            .node_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("node_id missing for {}", n.display_name()))?;
        let node_id_bytes = base58_to_node_id(&node_id).map_err(|e| {
            anyhow::anyhow!("invalid node_id {} for {}: {e}", node_id, n.display_name(),)
        })?;
        pending.push(PendingEntry {
            node_id,
            node_id_bytes,
            secret: identity.secret,
            public: identity.public,
        });
        n.bls_key_path = Some(bls_path);
    }

    // Pass 2: compute the deployment's chain_id from the validator
    // pubkeys + BLS table the genesis block will commit to, and mint a
    // chain-bound PoP per validator (#410).
    let validator_ids: Vec<boule_transport_tcp::tls::NodeId> =
        pending.iter().map(|e| e.node_id_bytes).collect();
    let bls_pubkeys: Vec<(boule_transport_tcp::tls::NodeId, BlsPublicKey)> = pending
        .iter()
        .map(|e| (e.node_id_bytes, e.public))
        .collect();
    // `testnet new` doesn't expose `genesis_seed_hex`, so the cluster
    // uses the default all-zeros seed — same as a config that omits
    // the field.
    let chain_id = boule_consensus::genesis::derive_chain_id_from_parts(
        &validator_ids,
        scheme,
        &bls_pubkeys,
        [0u8; 32],
    );

    let mut genesis = Vec::with_capacity(pending.len());
    for entry in pending {
        let pop = BlsAggregated::sign_pop(&entry.secret, &chain_id)
            .map_err(|e| anyhow::anyhow!("signing chain-bound BLS PoP: {e:?}"))?;
        genesis.push(BlsGenesisEntry {
            node_id: entry.node_id,
            bls_pubkey_hex: hex::encode(entry.public),
            bls_pop_hex: hex::encode(pop.sig),
        });
    }
    Ok(Some(genesis))
}

fn write_minimal_config(layout: &NodeLayout) -> anyhow::Result<()> {
    let body = format!(
        "[node]\n\
         listen_addr = \"127.0.0.1:0\"\n\
         addr_file   = \"{addr}\"\n\
         \n\
         [node.identity]\n\
         backend = \"file\"\n\
         path    = \"{key}\"\n\
         \n\
         [api]\n\
         listen_addr = \"127.0.0.1:0\"\n",
        addr = layout.addr_path.display(),
        key = layout.key_path.display(),
    );
    std::fs::write(&layout.config_path, body)
        .with_context(|| format!("writing {}", layout.config_path.display()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_final_config(
    n: &NodeLayout,
    all: &[NodeLayout],
    validators: &[String],
    target_degree: usize,
    timeout_base_ms: u64,
    timeout_max_ms: u64,
    signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice,
    bls_genesis: Option<&[BlsGenesisEntry]>,
) -> anyhow::Result<()> {
    use boule_core::crypto::sig_scheme::SignatureSchemeChoice;
    use std::fmt::Write as _;
    let p2p = n
        .p2p_addr
        .ok_or_else(|| anyhow::anyhow!("missing p2p_addr for {}", n.display_name()))?;
    let validators_toml = validators
        .iter()
        .map(|v| format!("\"{v}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let mut peers_toml = String::new();
    for &peer_idx in &n.bootstrap_peers {
        let p = &all[peer_idx];
        let addr = p
            .p2p_addr
            .ok_or_else(|| anyhow::anyhow!("missing p2p_addr for peer {}", p.display_name()))?;
        let id = p
            .node_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing node_id for peer {}", p.display_name()))?;
        write!(
            peers_toml,
            "\n[[peers]]\naddr    = \"{addr}\"\nnode_id = \"{id}\"\n"
        )
        .unwrap();
    }

    // BLS genesis table (#360): on `bls_aggregated` chains, emit the
    // `[consensus] signature_scheme` field, the
    // `[[consensus.validators_bls]]` rows that the genesis validator
    // set requires (`ConsensusConfig::resolve_genesis_bls_keys`), and
    // a `[node.bls_validator_identity]` block pointing at this node's
    // on-disk BLS key file. Ed25519 chains skip all three.
    let mut bls_consensus_toml = String::new();
    let mut bls_node_identity_toml = String::new();
    if signature_scheme == SignatureSchemeChoice::BlsAggregated {
        let entries = bls_genesis.ok_or_else(|| {
            anyhow::anyhow!(
                "bls_aggregated chain reached write_final_config without a BLS genesis table",
            )
        })?;
        write!(
            bls_consensus_toml,
            "\nsignature_scheme = \"bls_aggregated\"\n",
        )
        .unwrap();
        for e in entries {
            write!(
                bls_consensus_toml,
                "\n[[consensus.validators_bls]]\nnode_id    = \"{nid}\"\nbls_pubkey = \"{pk}\"\nbls_pop    = \"{pop}\"\n",
                nid = e.node_id,
                pk = e.bls_pubkey_hex,
                pop = e.bls_pop_hex,
            )
            .unwrap();
        }
        let bls_path = n.bls_key_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "bls_aggregated chain but {} has no bls_key_path; mint phase did not run",
                n.display_name(),
            )
        })?;
        write!(
            bls_node_identity_toml,
            "\n[node.bls_validator_identity]\nbackend = \"file\"\npath    = \"{path}\"\n",
            path = bls_path.display(),
        )
        .unwrap();
    }

    // Bake the api_addr discovered in phase 1 into the final config
    // (rather than re-binding to port 0). Otherwise `up` would land on
    // a fresh dynamic port and the api_addr in `state.json` would be
    // stale until the driver re-read each addr_file post-spawn.
    let api = n
        .api_addr
        .ok_or_else(|| anyhow::anyhow!("missing api_addr for {}", n.display_name()))?;
    let body = format!(
        "[node]\n\
         listen_addr = \"{p2p}\"\n\
         addr_file   = \"{addr}\"\n\
         \n\
         [node.identity]\n\
         backend = \"file\"\n\
         path    = \"{key}\"\n\
         {bls_node_identity_toml}\n\
         [api]\n\
         listen_addr = \"{api}\"\n\
         \n\
         [overlay]\n\
         mode            = \"gossip\"\n\
         outbound_target = {target_degree}\n\
         \n\
         [consensus]\n\
         validators       = [{validators_toml}]\n\
         storage_dir      = \"{storage}\"\n\
         timeout_base_ms  = {timeout_base_ms}\n\
         timeout_max_ms   = {timeout_max_ms}\n\
         {bls_consensus_toml}\
         {peers_toml}",
        addr = n.addr_path.display(),
        key = n.key_path.display(),
        storage = n.consensus_dir.display(),
    );
    std::fs::write(&n.config_path, body)
        .with_context(|| format!("writing final config {}", n.config_path.display()))?;
    Ok(())
}

fn run_init(binary: &Path, config: &Path) -> anyhow::Result<()> {
    let output = Command::new(binary)
        .args(["init", "--config"])
        .arg(config)
        .env("RUST_LOG", "warn")
        .output()
        .with_context(|| format!("spawning {:?} init", binary))?;
    if !output.status.success() {
        anyhow::bail!(
            "boule init exited {}: stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

struct DiscoveryInfo {
    node_id: String,
    p2p_addr: String,
    api_addr: String,
}

async fn launch_once_for_discovery(
    binary: &Path,
    layout: &NodeLayout,
) -> anyhow::Result<DiscoveryInfo> {
    // Make sure stale addr_file from a previous run doesn't poison the
    // poll loop. (The driver guards against it in `new_cluster` via the
    // state-file existence check, but be defensive anyway.)
    let _ = std::fs::remove_file(&layout.addr_path);

    let mut child = Command::new(binary)
        .args(["start", "--config"])
        .arg(&layout.config_path)
        .env("RUST_LOG", "warn")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning boule start for discovery")?;

    let deadline = Instant::now() + ADDR_FILE_TIMEOUT;
    let info = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "node {} did not write addr_file within {:?}",
                layout.display_name(),
                ADDR_FILE_TIMEOUT
            );
        }
        if layout.addr_path.exists() {
            if let Ok(addrs) = read_addr_file(&layout.addr_path) {
                break NodeAddrFile {
                    p2p_addr: addrs.p2p_addr,
                    api_addr: addrs.api_addr,
                    node_id: addrs.node_id,
                };
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Tear the discovery process down — we relaunch with the final
    // config in `up`. SIGKILL is fine: no peers are connected (this
    // node was started with an empty `[[peers]]` block) so there's no
    // close_notify path to flush, and the node's `tokio::signal::ctrl_c`
    // graceful path waits up to 5s on join handles which dominates an
    // otherwise sub-100ms launch.
    let _ = child.kill();
    let _ = child.wait();

    Ok(DiscoveryInfo {
        node_id: info.node_id,
        p2p_addr: info.p2p_addr,
        api_addr: info.api_addr,
    })
}

/// Spawn one node from a populated `state.json` and write its PID
/// file. Returns the node's PID.
pub async fn up_one(workdir: &Path, binary: &Path, layout: &NodeLayout) -> anyhow::Result<u32> {
    if layout.pid_path.exists() {
        anyhow::bail!(
            "{} already has a pid file at {}; run `down` or `kill {}` first",
            layout.display_name(),
            layout.pid_path.display(),
            layout.display_name(),
        );
    }
    // Truncate any existing addr_file so the address poll below picks
    // up the new bind, not stale state from an earlier `up`/`new`.
    let _ = std::fs::remove_file(&layout.addr_path);

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&layout.log_path)
        .with_context(|| format!("opening log {}", layout.log_path.display()))?;
    let log_err = log
        .try_clone()
        .with_context(|| format!("cloning log fd for {}", layout.display_name()))?;

    let child = Command::new(binary)
        .args(["start", "--config"])
        .arg(&layout.config_path)
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .with_context(|| format!("spawning boule start for {}", layout.display_name()))?;

    let pid = child.id();
    std::fs::write(&layout.pid_path, pid.to_string())
        .with_context(|| format!("writing pid file {}", layout.pid_path.display()))?;
    // Forget the child handle. We track the process through the pid
    // file rather than the std::process::Child so re-invoked drivers
    // can still down the cluster.
    std::mem::forget(child);

    events::record(
        workdir,
        "up",
        Some(&layout.display_name()),
        Some(&format!("pid={pid}")),
    );
    Ok(pid)
}

/// Spawn every down node. Idempotent: nodes that already have a live
/// pid file are skipped.
pub async fn up_all(workdir: &Path, binary: &Path, state: &State) -> anyhow::Result<Vec<u32>> {
    let mut pids = Vec::with_capacity(state.nodes.len());
    for n in &state.nodes {
        if pid_alive(n).is_some() {
            continue;
        }
        // Best effort: clean up a stale pid file from a crashed driver.
        let _ = std::fs::remove_file(&n.pid_path);
        pids.push(up_one(workdir, binary, n).await?);
    }
    Ok(pids)
}

/// Read the `pid` file under a node's directory and confirm the
/// process is still alive (via `kill(pid, 0)`). Returns the live PID
/// or `None` if either the file is missing or the process is gone.
pub fn pid_alive(layout: &NodeLayout) -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(&layout.pid_path)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if pid_is_running(pid) { Some(pid) } else { None }
}

#[cfg(unix)]
fn pid_is_running(pid: u32) -> bool {
    // We `mem::forget` spawned children, so a SIGKILL'd or SIGTERM'd
    // node becomes a zombie until reaped — and `kill(pid, 0)` happily
    // reports zombies as "alive". Reap with `waitpid(WNOHANG)` first;
    // it succeeds only for our own children, returns the pid when the
    // process is gone, returns 0 when it's still actually running, and
    // returns -1 (ECHILD) for processes spawned by a different driver
    // invocation. Fall back to `kill(pid, 0)` for the latter case so
    // re-invoked drivers can still observe nodes from prior `up`s.
    //
    // SAFETY: both syscalls are safe to invoke with arbitrary pid_t —
    // invalid pids surface as -1 with errno set rather than UB.
    unsafe {
        let mut status: libc::c_int = 0;
        let r = libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG);
        if r == pid as libc::pid_t {
            return false;
        }
        if r > 0 {
            return false;
        }
        if r == 0 {
            return true;
        }
        // r == -1: ECHILD (not our child) or another error. Fall through.
        libc::kill(pid as libc::pid_t, 0) == 0
    }
}

#[cfg(not(unix))]
fn pid_is_running(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn libc_sigterm() -> libc::c_int {
    libc::SIGTERM
}

#[cfg(unix)]
fn libc_sigkill() -> libc::c_int {
    libc::SIGKILL
}

#[cfg(not(unix))]
fn libc_sigterm() -> i32 {
    0
}

#[cfg(not(unix))]
fn libc_sigkill() -> i32 {
    0
}

#[cfg(unix)]
fn send_signal(pid: u32, signal: libc::c_int) -> bool {
    // SAFETY: kill with a valid PID + signal is safe; an invalid PID
    // returns -1 and sets errno, which we treat as "process gone".
    unsafe { libc::kill(pid as libc::pid_t, signal) == 0 }
}

#[cfg(not(unix))]
fn send_signal(_pid: u32, _signal: i32) -> bool {
    false
}

/// SIGKILL a single node and clean its pid file. Idempotent.
pub fn kill_one(workdir: &Path, layout: &NodeLayout) -> anyhow::Result<()> {
    let Some(pid) = pid_alive(layout) else {
        let _ = std::fs::remove_file(&layout.pid_path);
        return Ok(());
    };
    send_signal(pid, libc_sigkill());
    let _ = wait_for_exit(pid, Duration::from_secs(2));
    let _ = std::fs::remove_file(&layout.pid_path);
    events::record(
        workdir,
        "kill",
        Some(&layout.display_name()),
        Some(&format!("pid={pid}")),
    );
    Ok(())
}

/// Pick `count` random *live* nodes and SIGKILL them. Returns the
/// indices killed. Reproducible under `seed`.
pub fn kill_random(
    workdir: &Path,
    state: &State,
    count: usize,
    seed: u64,
) -> anyhow::Result<Vec<usize>> {
    let live: Vec<usize> = state
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| pid_alive(n).is_some())
        .map(|(i, _)| i)
        .collect();
    if live.is_empty() {
        anyhow::bail!("no live nodes to kill");
    }
    if count > live.len() {
        anyhow::bail!("can't kill {count} nodes — only {} live", live.len());
    }
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let chosen: Vec<usize> = live.choose_multiple(&mut rng, count).copied().collect();
    for &idx in &chosen {
        kill_one(workdir, &state.nodes[idx])?;
    }
    Ok(chosen)
}

/// Tear down every live node — SIGTERM, then SIGKILL stragglers. Also
/// reaps stale pid files. Idempotent.
pub fn down(workdir: &Path, state: &State) -> anyhow::Result<()> {
    let mut termed = Vec::new();
    for n in &state.nodes {
        if let Some(pid) = pid_alive(n) {
            send_signal(pid, libc_sigterm());
            termed.push((n.clone(), pid));
        } else {
            let _ = std::fs::remove_file(&n.pid_path);
        }
    }
    let deadline = Instant::now() + TERM_GRACE;
    let mut still_alive: Vec<(NodeLayout, u32)> = termed;
    while !still_alive.is_empty() && Instant::now() < deadline {
        still_alive.retain(|(_, pid)| pid_is_running(*pid));
        if !still_alive.is_empty() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    for (layout, pid) in &still_alive {
        send_signal(*pid, libc_sigkill());
        let _ = wait_for_exit(*pid, Duration::from_secs(2));
        events::record(
            workdir,
            "down_force_kill",
            Some(&layout.display_name()),
            Some(&format!("pid={pid}")),
        );
    }
    for n in &state.nodes {
        let _ = std::fs::remove_file(&n.pid_path);
    }
    events::record(workdir, "down", None, None);
    Ok(())
}

fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    !pid_is_running(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnet::workdir::PersistedSpec;

    #[test]
    fn parses_pid_file_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = node_layout(tmp.path(), 0, vec![]);
        std::fs::create_dir_all(layout.config_path.parent().unwrap()).unwrap();
        std::fs::write(&layout.pid_path, "12345").unwrap();
        // 12345 is almost certainly not a real PID owned by us; it
        // doesn't need to exist for the parse path to be exercised.
        let _ = pid_alive(&layout);
    }

    #[test]
    fn down_with_no_nodes_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let state = State {
            spec: PersistedSpec {
                nodes: 0,
                seed_extra: 0,
                target_degree: 4,
                seed: 0,
            },
            nodes: vec![],
        };
        down(tmp.path(), &state).unwrap();
    }
}
