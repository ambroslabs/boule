use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use super::manager::{AnyStream, ManagerMsg};
use super::tls::{extract_node_id, node_id_to_base58, NodeId, TlsIdentity, TlsStream};

/// Continuously attempts to maintain an outbound connection to `addr`.
/// On success, waits for the connection to die (via the peer_gone broadcast)
/// before retrying. Backs off exponentially on failure, capped at 60 s.
pub async fn reconnect_loop(
    addr: std::net::SocketAddr,
    expected_node_id: Option<NodeId>,
    identity: Arc<TlsIdentity>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    peer_gone_tx: broadcast::Sender<NodeId>,
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
/// `expected_node_id` (if set), and returns the stream + peer's NodeId.
async fn dial(
    addr: &std::net::SocketAddr,
    expected_node_id: Option<NodeId>,
    identity: &TlsIdentity,
) -> anyhow::Result<(AnyStream, NodeId)> {
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
    let node_id = extract_node_id(cert)?;

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
    Ok((Box::new(TlsStream::Client(tls_stream)), node_id))
}
