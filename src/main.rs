mod api;
mod config;
mod gossip;
mod p2p;
mod wire;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::p2p::manager::ManagerMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ambros_p2p=info".into()),
        )
        .init();

    let config_path = parse_config_arg();
    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    let store = Arc::new(gossip::store::GossipStore::new());

    let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<p2p::PeerCommand>(256);
    let (p2p_event_tx, p2p_event_rx) = mpsc::channel::<p2p::PeerEvent>(256);
    let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let manager_handle = {
        let event_tx = p2p_event_tx.clone();
        let itx = internal_tx.clone();
        tokio::spawn(p2p::manager::run(p2p_cmd_rx, event_tx, internal_rx, itx))
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

    let api_handle = {
        let store = Arc::clone(&store);
        let cmd_tx = p2p_cmd_tx.clone();
        let addr = config.api.listen_addr;
        tokio::spawn(api::serve(store, cmd_tx, addr))
    };

    let listener = TcpListener::bind(config.node.listen_addr).await?;
    info!("P2P listening on {}", config.node.listen_addr);
    let listener_handle = {
        let itx = internal_tx.clone();
        tokio::spawn(p2p::listener::run(listener, itx))
    };

    for peer_cfg in &config.peers {
        let addr = peer_cfg.addr;
        let itx = internal_tx.clone();
        tokio::spawn(async move {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => {
                    info!("connected to peer {addr}");
                    let _ = itx.send(ManagerMsg::NewConnection { stream, addr }).await;
                }
                Err(e) => {
                    warn!("could not connect to peer {addr}: {e}");
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");
    let _ = shutdown_tx.send(true);
    drop(p2p_cmd_tx);

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = listener_handle.await;
    })
    .await;

    Ok(())
}

fn parse_config_arg() -> PathBuf {
    let mut args = std::env::args().skip(1);
    if let Some(flag) = args.next() {
        if flag == "--config" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from("config.toml")
}
