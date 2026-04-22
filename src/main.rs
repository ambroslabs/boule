mod config;
mod gossip;
mod p2p;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::info;

use crate::p2p::manager::ManagerMsg;
use crate::p2p::tls::{node_id_to_base58, TlsIdentity};
use crate::p2p::tls_protocol::TlsConnectionProtocol;
use crate::p2p::ConnectionProtocol;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ambros_p2p=info".into()),
        )
        .init();

    let config_path = parse_config_arg()?;
    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    let identity = Arc::new(TlsIdentity::load_or_generate(&config.node.key_file)?);
    info!("node ID: {}", node_id_to_base58(&identity.node_id));

    let store = Arc::new(gossip::store::GossipStore::new());

    let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<p2p::PeerCommand>(256);
    let (p2p_event_tx, p2p_event_rx) = mpsc::channel::<p2p::PeerEvent>(256);
    let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (peer_gone_tx, _) = broadcast::channel::<p2p::NodeId>(64);

    let manager_handle = {
        let event_tx = p2p_event_tx.clone();
        let itx = internal_tx.clone();
        let pgt = peer_gone_tx.clone();
        let our_id = identity.node_id;
        tokio::spawn(p2p::manager::run(
            our_id, p2p_cmd_rx, event_tx, internal_rx, itx, pgt,
        ))
    };

    let engine_handle = {
        let store = Arc::clone(&store);
        let cmd_tx = p2p_cmd_tx.clone();
        tokio::spawn(gossip::engine::run(p2p_event_rx, cmd_tx, store))
    };

    let cleanup_handle = {
        let store = Arc::clone(&store);
        let interval = config.api.cleanup_interval_secs;
        let srx = shutdown_rx.clone();
        tokio::spawn(gossip::cleanup::run(store, interval, srx))
    };

    // Bind the API listener here so we know the actual port before writing addr_file.
    let api_listener = TcpListener::bind(config.api.listen_addr).await?;
    let api_actual_addr = api_listener.local_addr()?;
    let api_handle = {
        let app = axum::Router::new()
            .merge(p2p::api::router(p2p_cmd_tx.clone()))
            .merge(gossip::api::router(Arc::clone(&store), p2p_cmd_tx.clone()));
        tokio::spawn(async move {
            info!("HTTP API listening on {api_actual_addr}");
            axum::serve(api_listener, app).await.unwrap();
        })
    };

    // Bind the P2P listener before spawning the protocol so the actual port is
    // known before we write addr_file.
    let p2p_listener = TcpListener::bind(config.node.listen_addr).await?;
    let p2p_actual_addr = p2p_listener.local_addr()?;
    info!("P2P listening on {p2p_actual_addr}");

    // Write bound addresses + node ID to addr_file if configured.
    // Tests use this to discover actual ports when listen_addr uses port 0.
    if let Some(ref path) = config.node.addr_file {
        let content = serde_json::json!({
            "p2p_addr": p2p_actual_addr.to_string(),
            "api_addr": api_actual_addr.to_string(),
            "node_id": node_id_to_base58(&identity.node_id),
        });
        std::fs::write(path, content.to_string())?;
    }

    let protocol = TlsConnectionProtocol {
        identity: Arc::clone(&identity),
        peers: config.peers.clone(),
        listener: p2p_listener,
    };
    let protocol_handle = tokio::spawn(protocol.run(internal_tx.clone(), peer_gone_tx.clone()));

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");
    let _ = shutdown_tx.send(true);
    drop(p2p_cmd_tx);

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = protocol_handle.await;
    })
    .await;

    Ok(())
}

fn parse_config_arg() -> anyhow::Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    let mut config_path = PathBuf::from("config.toml");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path argument"))?;
                config_path = PathBuf::from(path);
            }
            "--help" | "-h" => {
                println!("Usage: ambros-p2p [--config <path>]");
                println!();
                println!("Options:");
                println!("  -c, --config <path>   Path to TOML config file [default: config.toml]");
                std::process::exit(0);
            }
            other => {
                anyhow::bail!(
                    "unknown argument '{other}'\nUsage: ambros-p2p [--config <path>]"
                );
            }
        }
    }

    Ok(config_path)
}
