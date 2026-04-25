use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{info, warn};

use super::PeerCommand;
use super::manager::{AnyStream, ManagerMsg};
use super::tls::{NodeId, TlsIdentity, TlsStream, extract_node_id, node_id_to_base58};
use crate::clock::Clock;

/// Bundle of per-node dialer dependencies — the parameters every
/// invocation of [`reconnect_loop`] needs that are constant across the
/// lifetime of a node.
///
/// Construct one once at startup and reuse it for every `(addr,
/// expected_node_id)` pair that needs an outbound dialer (the static
/// peers list at boot, plus runtime additions from the gossip
/// overlay's `Discovery::add_bootstrap` and partial-mesh maintenance
/// loop).
#[derive(Clone)]
pub struct DialerCtx {
    /// Long-term TLS identity used for every outbound handshake.
    pub identity: Arc<TlsIdentity>,
    /// Channel into the peer manager for new connections.
    pub internal_tx: mpsc::Sender<ManagerMsg>,
    /// Broadcast that the manager fans out when a peer drops; the
    /// reconnect loop uses it to trigger redials.
    pub peer_gone_tx: broadcast::Sender<NodeId>,
    /// Optional command channel into the manager. When supplied the
    /// reconnect loop skips redials whose target is already directly
    /// connected (issue #114).
    pub peer_cmd_tx: Option<mpsc::Sender<PeerCommand>>,
    /// Clock used for sleep / backoff between failed dials.
    pub clock: Arc<dyn Clock>,
}

impl DialerCtx {
    /// Spawn a [`reconnect_loop`] that maintains an outbound
    /// connection to `addr` (asserting `expected_node_id` when set).
    /// Returns the spawned [`JoinHandle`] so callers that want to
    /// cancel on shutdown can hold it.
    pub fn spawn(
        &self,
        addr: std::net::SocketAddr,
        expected_node_id: Option<NodeId>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(reconnect_loop(
            addr,
            expected_node_id,
            Arc::clone(&self.identity),
            self.internal_tx.clone(),
            self.peer_gone_tx.clone(),
            self.peer_cmd_tx.clone(),
            Arc::clone(&self.clock),
        ))
    }
}

/// Continuously attempts to maintain an outbound connection to `addr`.
/// On success, waits for the connection to die (via the peer_gone broadcast)
/// before retrying. Backs off exponentially on failure, capped at 60 s.
///
/// When `peer_cmd_tx` is supplied, before each (re)dial the loop asks the
/// manager whether it already has a live connection for the expected peer
/// (via [`PeerCommand::HasPeer`]). If so, the dial is skipped — the listener
/// side is already providing connectivity and a redial would just spin up a
/// duplicate that the tie-breaker has to resolve (see #114).
#[allow(clippy::too_many_arguments)]
pub async fn reconnect_loop(
    addr: std::net::SocketAddr,
    expected_node_id: Option<NodeId>,
    identity: Arc<TlsIdentity>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    peer_gone_tx: broadcast::Sender<NodeId>,
    peer_cmd_tx: Option<mpsc::Sender<PeerCommand>>,
    clock: Arc<dyn Clock>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        let mut peer_gone_rx = peer_gone_tx.subscribe();

        // If the manager already tracks a live connection for this peer
        // (typically one the listener just accepted), skip this dial pass
        // and wait for it to go away before trying again. Bounds the
        // connection-churn the tie-breaker would otherwise absorb.
        if let (Some(expected), Some(cmd_tx)) = (expected_node_id, peer_cmd_tx.as_ref())
            && already_connected(cmd_tx, expected).await
        {
            match wait_for_peer_gone(&mut peer_gone_rx, expected).await {
                WaitOutcome::Gone => continue,
                WaitOutcome::ChannelClosed => return,
            }
        }

        match dial(&addr, expected_node_id, &identity).await {
            Ok((stream, node_id)) => {
                if internal_tx
                    .send(ManagerMsg::NewConnection {
                        node_id,
                        addr,
                        stream,
                    })
                    .await
                    .is_err()
                {
                    return; // manager has exited — we're shutting down
                }
                backoff = Duration::from_secs(1);

                // Wait until this specific peer disconnects.
                match wait_for_peer_gone(&mut peer_gone_rx, node_id).await {
                    WaitOutcome::Gone => {}
                    WaitOutcome::ChannelClosed => return,
                }
            }
            Err(e) => {
                warn!("could not connect to peer {addr}: {e}; retry in {backoff:?}");
                clock.sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

enum WaitOutcome {
    Gone,
    ChannelClosed,
}

async fn wait_for_peer_gone(
    peer_gone_rx: &mut broadcast::Receiver<NodeId>,
    expected: NodeId,
) -> WaitOutcome {
    loop {
        match peer_gone_rx.recv().await {
            Ok(gone_id) if gone_id == expected => return WaitOutcome::Gone,
            Ok(_) => continue,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return WaitOutcome::ChannelClosed,
        }
    }
}

async fn already_connected(cmd_tx: &mpsc::Sender<PeerCommand>, node_id: NodeId) -> bool {
    let (reply_tx, reply_rx) = oneshot::channel();
    if cmd_tx
        .send(PeerCommand::HasPeer {
            node_id,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        // Manager has exited — let the caller proceed (the next send on
        // `internal_tx` will also fail and the loop will exit cleanly).
        return false;
    }
    reply_rx.await.unwrap_or(false)
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

    info!(
        "connected to peer {addr} (node {})",
        node_id_to_base58(&node_id)
    );
    Ok((Box::new(TlsStream::Client(tls_stream)), node_id))
}
