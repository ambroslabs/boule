mod api;
mod config;
mod gossip;
mod p2p;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{info, warn};

use crate::p2p::manager::ManagerMsg;
use crate::p2p::tls::{base58_to_node_id, node_id_to_base58, TlsIdentity, TlsStream};

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
        let store = Arc::clone(&store);
        let cmd_tx = p2p_cmd_tx.clone();
        tokio::spawn(api::serve(store, cmd_tx, api_listener))
    };

    // Bind the P2P listener before spawning the accept loop for the same reason.
    let listener = TcpListener::bind(config.node.listen_addr).await?;
    let p2p_actual_addr = listener.local_addr()?;
    info!("P2P listening on {p2p_actual_addr}");
    let listener_handle = {
        let itx = internal_tx.clone();
        let acceptor = identity.acceptor.clone();
        tokio::spawn(p2p::listener::run(listener, acceptor, itx))
    };

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

    // For each configured peer, spawn a reconnect task with exponential backoff.
    for peer_cfg in &config.peers {
        let addr = peer_cfg.addr;
        let expected_node_id = peer_cfg
            .node_id
            .as_deref()
            .map(base58_to_node_id)
            .transpose()?;
        let itx = internal_tx.clone();
        let pgt = peer_gone_tx.clone();
        let id = Arc::clone(&identity);
        tokio::spawn(reconnect_loop(addr, expected_node_id, id, itx, pgt));
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");
    let _ = shutdown_tx.send(true);
    drop(p2p_cmd_tx);

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = listener_handle.await;
    })
    .await;

    Ok(())
}

/// Continuously attempts to maintain an outbound connection to `addr`.
/// On success, waits for the connection to die (via the peer_gone broadcast)
/// before retrying. Backs off exponentially on failure, capped at 60 s.
async fn reconnect_loop(
    addr: std::net::SocketAddr,
    expected_node_id: Option<p2p::NodeId>,
    identity: Arc<TlsIdentity>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    peer_gone_tx: broadcast::Sender<p2p::NodeId>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        let mut peer_gone_rx = peer_gone_tx.subscribe();

        match dial(&addr, expected_node_id, &identity).await {
            Ok((stream, node_id)) => {
                if internal_tx
                    .send(ManagerMsg::NewConnection { node_id, addr, stream })
                    .await
                    .is_err()
                {
                    return; // manager has exited — we're shutting down
                }
                backoff = Duration::from_secs(1);

                // Wait until this specific peer disconnects.
                loop {
                    match peer_gone_rx.recv().await {
                        Ok(gone_id) if gone_id == node_id => break,
                        Ok(_) => continue,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
            Err(e) => {
                warn!("could not connect to peer {addr}: {e}; retry in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// Opens a TLS connection to `addr`, verifies the peer's node ID matches
/// `expected_node_id` (if set), and returns the TLS stream + peer's NodeId.
async fn dial(
    addr: &std::net::SocketAddr,
    expected_node_id: Option<p2p::NodeId>,
    identity: &TlsIdentity,
) -> anyhow::Result<(TlsStream, p2p::NodeId)> {
    use tokio_rustls::TlsConnector;

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(Arc::clone(&identity.client_config));
    let server_name = rustls::pki_types::ServerName::try_from("ambros-p2p")
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let tls_stream = connector.connect(server_name, tcp).await?;

    let (_, client_conn) = tls_stream.get_ref();
    let certs = client_conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("peer presented no certificate"))?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty peer certificate chain"))?;
    let node_id = p2p::tls::extract_node_id(cert)?;

    if let Some(expected) = expected_node_id {
        if node_id != expected {
            anyhow::bail!(
                "peer node ID mismatch: expected {}, got {}",
                node_id_to_base58(&expected),
                node_id_to_base58(&node_id),
            );
        }
    }

    info!("connected to peer {addr} (node {})", node_id_to_base58(&node_id));
    Ok((TlsStream::Client(tls_stream), node_id))
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
