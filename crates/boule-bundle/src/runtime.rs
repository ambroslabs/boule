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

#[derive(Debug, Clone)]
pub struct RethPorts {

    pub http_addr: std::net::IpAddr,

    pub http_port: u16,

    pub auth_port: u16,

    pub p2p_port: u16,

    pub auth_ipc_path: PathBuf,
}

impl Default for RethPorts {
    fn default() -> Self {
        Self {
            http_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            http_port: 8545,
            auth_port: 8551,
            p2p_port: 0,
            auth_ipc_path: PathBuf::from("/tmp/boule_engine_api.ipc"),
        }
    }
}

pub struct BundleRethConfig {

    pub chain_json: String,

    pub datadir: PathBuf,

    pub ports: RethPorts,

    pub http_api: String,
}

fn build_node_config(cfg: &BundleRethConfig) -> Result<NodeConfig<ChainSpec>> {
    let chain = chain_value_parser(&cfg.chain_json)
        .map_err(|e| anyhow::anyhow!("parsing bundled chainspec genesis: {e}"))?;

    let http_api = cfg
        .http_api
        .parse()
        .map_err(|e| anyhow::anyhow!("parsing http.api module selection: {e}"))?;

    let mut node_config = NodeConfig::new(chain).with_datadir_args(DatadirArgs {
        datadir: MaybePlatformPath::from(cfg.datadir.clone()),
        ..Default::default()
    });

    node_config.rpc = node_config
        .rpc
        .with_http()
        .with_http_api(http_api)
        .with_auth_ipc();
    node_config.rpc.http_addr = cfg.ports.http_addr;
    node_config.rpc.http_port = cfg.ports.http_port;
    node_config.rpc.auth_addr = std::net::Ipv4Addr::LOCALHOST.into();
    node_config.rpc.auth_port = cfg.ports.auth_port;
    node_config.rpc.auth_ipc_path = cfg.ports.auth_ipc_path.to_string_lossy().into_owned();

    node_config.network.discovery.disable_discovery = true;
    node_config.network.port = cfg.ports.p2p_port;

    Ok(node_config)
}

async fn fetch_genesis_in_process(transport: &InProcessTransport) -> Result<(String, [u8; 32])> {
    let block = transport
        .eth("eth_getBlockByNumber", json!(["0x0", false]))
        .await
        .context("reading reth genesis block in-process")?;
    let hash = block["hash"]
        .as_str()
        .context("genesis block hash")?
        .to_string();
    let root =
        boule_reth::root_from_hex(block["stateRoot"].as_str().context("genesis stateRoot")?)?;
    Ok((hash, root))
}

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
    let root =
        boule_reth::root_from_hex(block["stateRoot"].as_str().context("finalized stateRoot")?)?;
    Ok(Some((height, root)))
}

pub type ConfigProvider = Box<
    dyn FnOnce([u8; 32]) -> Result<(Config, NodeIdentity, Option<NodeIdentity>)> + Send + 'static,
>;

pub async fn run_bundled_with(
    reth_cfg: BundleRethConfig,
    config_provider: ConfigProvider,
) -> Result<()> {
    let node_config = build_node_config(&reth_cfg)?;
    let data_dir = node_config.datadir();
    let db_path = data_dir.db();
    std::fs::create_dir_all(&reth_cfg.datadir)
        .with_context(|| format!("creating reth datadir {}", reth_cfg.datadir.display()))?;
    info!(target: "boule::bundle", path = ?db_path, "opening reth database (in-process)");
    let database = init_db(db_path.clone(), DatabaseArguments::default())
        .map_err(|e| anyhow::anyhow!("opening reth database: {e}"))?;

    let runtime: Runtime = RuntimeBuilder::new(RuntimeConfig::default().with_tokio(
        TokioConfig::existing_handle(tokio::runtime::Handle::current()),
    ))
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

    #[cfg(unix)]
    let engine_client = full.auth_server_handle().ipc_client().await.context(
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

    let (reth_genesis_hash, reth_genesis_root) = fetch_genesis_in_process(&transport).await?;

    let finalized = fetch_finalized_head_in_process(&transport).await?;

    let (config, network_identity, validator_identity) = config_provider(reth_genesis_root)?;

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

    info!(
        target: "boule::bundle",
        genesis_root = %hex::encode(reth_genesis_root),
        "in-process reth genesis bridged to consensus genesis",
    );

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

        if let Err(e) = node_exit_future.await {
            tracing::error!(target: "boule::bundle", error = %e, "in-process reth node exited with error");
        }
    });

    let app_override = ApplicationOverride {
        factory: Some(factory),
        shutdown: Some(exit),
    };

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

pub async fn run_bundled(
    config: Config,
    network_identity: NodeIdentity,
    validator_identity: Option<NodeIdentity>,
    reth_cfg: BundleRethConfig,
) -> Result<()> {
    let provider: ConfigProvider = Box::new(move |reth_genesis_root: [u8; 32]| {

        let genesis_state_commitment = config
            .consensus
            .as_ref()
            .map(|c| {

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
                "consensus genesis state_commitment {} does not match reth's genesis state root \
                 {}; set [consensus] genesis_seed_hex = \"{}\"",
                hex::encode(genesis_state_commitment),
                hex::encode(reth_genesis_root),
                hex::encode(reth_genesis_root),
            );
        }
        Ok((config, network_identity, validator_identity))
    });
    run_bundled_with(reth_cfg, provider).await
}

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

fn decode_seed_hex(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("[consensus] genesis_seed_hex is not valid hex")?;
    bytes
        .as_slice()
        .try_into()
        .context("[consensus] genesis_seed_hex must be 32 bytes")
}
