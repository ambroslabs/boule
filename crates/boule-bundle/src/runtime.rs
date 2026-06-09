//! The bundled single-process runtime (#885): launch the custom reth EL
//! (`BouleNode`) via the reth-SDK `NodeBuilder` **in this process**, then run the
//! boule consensus loop against it over the in-process [`InProcessTransport`]
//! (#884) — no second process, no HTTP Engine API, no JWT.
//!
//! This replaces `boule-node`'s standalone `reth_application` setup:
//! - reth is launched here, not assumed-running, so the genesis-state-root read,
//!   the finalized-head read, and reth-peering all happen **in-process** (via the
//!   in-process eth client) instead of over HTTP.
//! - The boule↔EL hop is [`InProcessTransport`], not `HttpTransport`.
//! - The boule consensus loop is `boule_node::run_with_application`, into which we
//!   inject a factory that builds `RethApplication` from the consensus mempool.
//!
//! Preserved from the standalone path: the genesis-root bridge assertion (fails
//! closed when reth's genesis state root ≠ the consensus genesis
//! `state_commitment`), `RethApplication::recover_frontier` on restart, and the
//! `RethApplication::new` construction itself (unchanged).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
use tracing::info;

use reth_ethereum::chainspec::ChainSpec;
use reth_ethereum::cli::chainspec::chain_value_parser;
use reth_ethereum::node::builder::{NodeBuilder, NodeConfig};
use reth_ethereum::node::core::args::DatadirArgs;
use reth_ethereum::node::core::dirs::MaybePlatformPath;
use reth_ethereum::provider::db::init_db;
use reth_ethereum::provider::db::mdbx::DatabaseArguments;
use reth_ethereum::tasks::{Runtime, RuntimeBuilder, RuntimeConfig, TokioConfig};

use boule_core::config::{ApplicationConfig, Config};
use boule_core::identity::NodeIdentity;
use boule_node::{ApplicationContext, ApplicationOverride};
use boule_reth_node::node::BouleNode;

use crate::transport::InProcessTransport;

/// Ports + IPC paths the bundled reth node binds. Defaults match the standalone
/// node's, but every value is overridable so multiple bundled nodes can coexist
/// on one host (the smoke test / a local cluster).
#[derive(Debug, Clone)]
pub struct RethPorts {
    /// Public `eth_*` HTTP RPC port (`--http.port`).
    pub http_port: u16,
    /// Authenticated Engine API port (`--authrpc.port`). The bundle talks to the
    /// auth server over IPC, not this TCP port, but reth still binds it.
    pub auth_port: u16,
    /// devp2p listener port (`--port`). `0` lets the OS pick.
    pub p2p_port: u16,
    /// The auth-server IPC endpoint path the in-process engine client connects to.
    pub auth_ipc_path: PathBuf,
}

impl Default for RethPorts {
    fn default() -> Self {
        Self {
            http_port: 8545,
            auth_port: 8551,
            p2p_port: 0,
            auth_ipc_path: PathBuf::from("/tmp/boule_engine_api.ipc"),
        }
    }
}

/// Everything the bundle needs to boot reth alongside consensus, distinct from
/// the boule [`Config`].
pub struct BundleRethConfig {
    /// The seeded genesis JSON (the build.rs-generated predeploy genesis with
    /// validator weights seeded; see `gen-genesis`). Parsed into a reth
    /// [`ChainSpec`]. A path or an in-memory JSON string both work.
    pub chain_json: String,
    /// reth's data directory (mdbx + static files).
    pub datadir: PathBuf,
    /// Ports / IPC paths.
    pub ports: RethPorts,
    /// Comma-separated `eth_*` RPC module selection for the public HTTP server
    /// (e.g. `"eth,net,web3,txpool,admin"`).
    pub http_api: String,
}

/// Build a reth [`NodeConfig`] for the bundled node: the seeded chainspec, the
/// datadir, the public eth HTTP server, and — crucially — the **auth-server IPC
/// endpoint** the in-process engine client connects to (bypassing TCP + JWT).
/// Discovery is disabled (a bundled validator's reth is driven by consensus, not
/// gossip-synced).
fn build_node_config(cfg: &BundleRethConfig) -> Result<NodeConfig<ChainSpec>> {
    let chain = chain_value_parser(&cfg.chain_json)
        .map_err(|e| anyhow::anyhow!("parsing bundled chainspec genesis: {e}"))?;

    let http_api = cfg
        .http_api
        .parse()
        .map_err(|e| anyhow::anyhow!("parsing http.api module selection: {e}"))?;

    let mut node_config = NodeConfig::new(chain)
        .with_datadir_args(DatadirArgs {
            datadir: MaybePlatformPath::from(cfg.datadir.clone()),
            ..Default::default()
        });

    // Public eth RPC (for the boule eth-facing services + in-process genesis /
    // finalized-head reads). The standalone node serves the same surface.
    node_config.rpc = node_config
        .rpc
        .with_http()
        .with_http_api(http_api)
        .with_auth_ipc();
    node_config.rpc.http_addr = std::net::Ipv4Addr::LOCALHOST.into();
    node_config.rpc.http_port = cfg.ports.http_port;
    node_config.rpc.auth_addr = std::net::Ipv4Addr::LOCALHOST.into();
    node_config.rpc.auth_port = cfg.ports.auth_port;
    node_config.rpc.auth_ipc_path = cfg.ports.auth_ipc_path.to_string_lossy().into_owned();

    // A consensus-driven EL: no devp2p discovery (boule drives block production
    // via the Engine API; there is no second reth to gossip with by default).
    node_config.network.discovery.disable_discovery = true;
    node_config.network.port = cfg.ports.p2p_port;

    Ok(node_config)
}

/// Read reth's genesis block hash + state root in-process via the eth client
/// (`eth_getBlockByNumber(0)`), replacing the HTTP `fetch_genesis`.
async fn fetch_genesis_in_process(transport: &InProcessTransport) -> Result<(String, [u8; 32])> {
    let block = transport
        .eth("eth_getBlockByNumber", json!(["0x0", false]))
        .await
        .context("reading reth genesis block in-process")?;
    let hash = block["hash"]
        .as_str()
        .context("genesis block hash")?
        .to_string();
    let root = boule_reth::root_from_hex(
        block["stateRoot"].as_str().context("genesis stateRoot")?,
    )?;
    Ok((hash, root))
}

/// Read reth's finalized head in-process (`eth_getBlockByNumber("finalized")`),
/// replacing the HTTP `fetch_finalized_head`. `None` when reth has finalized
/// nothing past genesis (a fresh node).
async fn fetch_finalized_head_in_process(
    transport: &InProcessTransport,
) -> Result<Option<(u64, [u8; 32])>> {
    let block = transport
        .eth("eth_getBlockByNumber", json!(["finalized", false]))
        .await
        .context("reading reth finalized head in-process")?;
    if block.is_null() {
        return Ok(None);
    }
    let height = u64::from_str_radix(
        block["number"]
            .as_str()
            .context("finalized block number")?
            .trim_start_matches("0x"),
        16,
    )
    .context("finalized block number not hex")?;
    if height == 0 {
        return Ok(None);
    }
    let root = boule_reth::root_from_hex(
        block["stateRoot"]
            .as_str()
            .context("finalized stateRoot")?,
    )?;
    Ok(Some((height, root)))
}

/// Run the bundled single-process node (#885): launch `BouleNode` in-process,
/// then drive boule consensus against it. Blocks until ctrl-c or reth exits.
pub async fn run_bundled(
    config: Config,
    network_identity: NodeIdentity,
    validator_identity: Option<NodeIdentity>,
    reth_cfg: BundleRethConfig,
) -> Result<()> {
    // Pull the in-process application parameters from the dedicated config
    // variant (`reth-inprocess`); the standalone `reth` variant carries HTTP/JWT
    // fields that are meaningless here.
    let (fee_recipient, build_wait_ms) = match config
        .consensus
        .as_ref()
        .and_then(|c| c.application.as_ref())
    {
        Some(ApplicationConfig::RethInProcess {
            fee_recipient,
            build_wait_ms,
        }) => (fee_recipient.clone(), *build_wait_ms),
        Some(ApplicationConfig::Reth { .. }) => anyhow::bail!(
            "[consensus.application] backend = \"reth\" selects the standalone two-process node; \
             run it with `boule start`. The bundled `boule node` requires backend = \
             \"reth-inprocess\"."
        ),
        None => anyhow::bail!(
            "the bundled `boule node` requires [consensus.application] backend = \
             \"reth-inprocess\""
        ),
    };

    // === Launch reth (BouleNode) in-process ===
    let node_config = build_node_config(&reth_cfg)?;
    let data_dir = node_config.datadir();
    let db_path = data_dir.db();
    std::fs::create_dir_all(&reth_cfg.datadir)
        .with_context(|| format!("creating reth datadir {}", reth_cfg.datadir.display()))?;
    info!(target: "boule::bundle", path = ?db_path, "opening reth database (in-process)");
    let database = init_db(db_path.clone(), DatabaseArguments::default())
        .map_err(|e| anyhow::anyhow!("opening reth database: {e}"))?;

    // Reuse the ambient tokio runtime (the bundle's `#[tokio::main]`) as reth's
    // task executor — no second runtime. The returned `Runtime` IS reth's
    // `TaskExecutor`; its panic-monitor task is dropped on exit with the node.
    let runtime: Runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::existing_handle(tokio::runtime::Handle::current())),
    )
    .build()
    .map_err(|e| anyhow::anyhow!("building reth task runtime: {e}"))?;

    info!(target: "boule::bundle", "launching custom reth EL (BouleNode) in-process");
    let node_handle = NodeBuilder::new(node_config)
        .with_database(database)
        .with_launch_context(runtime)
        .node(BouleNode::default())
        .launch()
        .await
        .map_err(|e| anyhow::anyhow!("launching in-process reth node: {e}"))?;

    let full = node_handle.node.clone();
    let node_exit_future = node_handle.node_exit_future;

    // === Build the in-process transport ===
    // Auth-server IPC client (engine_*, no JWT) — `cfg(unix)`; the bundle targets
    // Linux. The eth HTTP client (eth_*) over the node's public RPC server.
    // The raw `jsonrpsee` async client over the auth server's IPC endpoint (no
    // JWT). `FullNode::engine_ipc_client` wraps this in an `EngineApiClient`
    // opaque type, but the transport speaks raw JSON `Value`, so go to the
    // auth-server handle directly for the `ClientT` we can call `request` on.
    #[cfg(unix)]
    let engine_client = full
        .auth_server_handle()
        .ipc_client()
        .await
        .context(
            "reth auth-server IPC client unavailable; was auth IPC enabled \
             (RpcServerArgs::with_auth_ipc)?",
        )?;
    #[cfg(not(unix))]
    let engine_client: jsonrpsee::async_client::Client = {
        anyhow::bail!(
            "the bundled in-process engine transport requires unix (auth-server IPC); \
             non-unix is not supported"
        )
    };

    let eth_client = full
        .rpc_server_handle()
        .http_client()
        .context("reth public eth HTTP RPC client unavailable; was the HTTP server enabled?")?;

    let transport = InProcessTransport::new(engine_client, eth_client);

    // === Genesis-root bridge (fail closed) ===
    let (reth_genesis_hash, reth_genesis_root) = fetch_genesis_in_process(&transport).await?;
    let genesis_state_commitment = config
        .consensus
        .as_ref()
        .map(|c| {
            // The consensus genesis `state_commitment` derives from
            // `genesis_seed_hex`; decode it the same way consensus does. When
            // absent it is all-zeros (which will mismatch reth and fail closed,
            // exactly as intended).
            c.genesis_seed_hex
                .as_deref()
                .map(decode_seed_hex)
                .transpose()
        })
        .transpose()?
        .flatten()
        .unwrap_or([0u8; 32]);
    if reth_genesis_root != genesis_state_commitment {
        anyhow::bail!(
            "consensus genesis state_commitment {} does not match reth's genesis state root {}; \
             set [consensus] genesis_seed_hex = \"{}\"",
            hex::encode(genesis_state_commitment),
            hex::encode(reth_genesis_root),
            hex::encode(reth_genesis_root),
        );
    }
    info!(
        target: "boule::bundle",
        genesis_root = %hex::encode(reth_genesis_root),
        "in-process reth genesis bridged to consensus genesis",
    );

    // Read the finalized head once, in-process, for frontier recovery on restart.
    let finalized = fetch_finalized_head_in_process(&transport).await?;

    // === Inject the RethApplication factory + race reth's exit future ===
    // The transport is moved into the factory; the genesis / finalized-head reads
    // above already consumed everything the runtime needed from it.
    let factory: boule_node::ApplicationFactory = Box::new(move |ctx: ApplicationContext| {
        Box::pin(async move {
            build_reth_application(
                transport,
                ctx,
                fee_recipient,
                reth_genesis_hash,
                reth_genesis_root,
                build_wait_ms,
                finalized,
            )
            .await
        })
    });

    let exit: boule_node::BoxFutureUnit = Box::pin(async move {
        // `node_exit_future` yields `eyre::Result<()>`; either outcome means reth
        // is done, so map both to `()` and let the consensus side shut down.
        if let Err(e) = node_exit_future.await {
            tracing::error!(target: "boule::bundle", error = %e, "in-process reth node exited with error");
        }
    });

    let app_override = ApplicationOverride {
        factory: Some(factory),
        shutdown: Some(exit),
    };

    // Run boule consensus in THIS process. On shutdown (ctrl-c or reth exit),
    // `run_with_application` tears down consensus + overlay via its oneshots
    // before returning here; only then do we drop `full`/the runtime.
    let result = boule_node::run_with_application(
        config,
        network_identity,
        validator_identity,
        app_override,
    )
    .await;

    info!(target: "boule::bundle", "consensus stopped; shutting down in-process reth");
    drop(full);
    drop(node_handle.node);
    result
}

/// Construct `RethApplication` (unchanged) against the shared consensus mempool,
/// and recover its committed frontier from reth's finalized head on restart.
async fn build_reth_application(
    transport: InProcessTransport,
    ctx: ApplicationContext,
    fee_recipient: String,
    reth_genesis_hash: String,
    reth_genesis_root: [u8; 32],
    build_wait_ms: u64,
    finalized: Option<(u64, [u8; 32])>,
) -> Result<Arc<dyn boule_consensus::replication::application::Application>> {
    let stake_source: Box<dyn boule_consensus::replication::stake_source::StakeSource> = Box::new(
        boule_consensus::replication::stake_source::BondedStakeLedger::seeded_from(
            ctx.genesis_stake,
        ),
    );
    let boxed: Box<dyn boule_reth::EngineTransport> = Box::new(transport);
    let app = boule_reth::RethApplication::new(
        boxed,
        ctx.self_id,
        fee_recipient,
        reth_genesis_hash,
        reth_genesis_root,
        Duration::from_millis(build_wait_ms),
        stake_source,
        ctx.mempool,
    );
    if let Some((height, state_root)) = finalized {
        app.recover_frontier(boule_consensus::Height(height), state_root);
        info!(
            target: "boule::bundle",
            height,
            "recovered reth committed frontier from finalized head on restart",
        );
    }
    Ok(Arc::new(app))
}

/// Decode a 32-byte hex `genesis_seed_hex` (with or without `0x`) into the
/// genesis `state_commitment`.
fn decode_seed_hex(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("[consensus] genesis_seed_hex is not valid hex")?;
    bytes
        .as_slice()
        .try_into()
        .context("[consensus] genesis_seed_hex must be 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::decode_seed_hex;

    #[test]
    fn seed_hex_decodes_with_and_without_prefix() {
        let want = [0xabu8; 32];
        assert_eq!(decode_seed_hex(&"ab".repeat(32)).unwrap(), want);
        assert_eq!(
            decode_seed_hex(&format!("0x{}", "ab".repeat(32))).unwrap(),
            want
        );
    }

    #[test]
    fn seed_hex_rejects_wrong_length() {
        assert!(decode_seed_hex("abcd").is_err());
    }
}
