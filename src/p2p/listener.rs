use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::limits::Direction;
use super::manager::ManagerMsg;
use super::tls::{NodeId, TlsStream, extract_node_id, node_id_to_base58};
use tokio_rustls::TlsAcceptor;

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    our_id: NodeId,
    manager_tx: mpsc::Sender<ManagerMsg>,
) {
    info!("TCP listener started on {}", listener.local_addr().unwrap());
    loop {
        match listener.accept().await {
            Ok((tcp_stream, addr)) => {
                let acceptor = acceptor.clone();
                let manager_tx = manager_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handshake_inbound(tcp_stream, addr, acceptor, our_id, manager_tx).await
                    {
                        warn!("TLS handshake failed from {addr}: {e}");
                    }
                });
            }
            Err(e) => {
                error!("accept error: {e}");
            }
        }
    }
}

async fn handshake_inbound(
    tcp_stream: tokio::net::TcpStream,
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    our_id: NodeId,
    manager_tx: mpsc::Sender<ManagerMsg>,
) -> anyhow::Result<()> {
    let tls_stream = acceptor.accept(tcp_stream).await?;
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("no client certificate"))?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty cert chain"))?;
    let node_id = extract_node_id(cert)?;
    if node_id == our_id {
        // The remote presented our own NodeId. Either we've dialed
        // ourselves (the dialer's handshake-time guard catches the
        // outbound side; this is the symmetric inbound branch) or
        // someone else is presenting a cert minted from our private
        // key — which shouldn't be possible without our key, but the
        // boundary is the right place to be defensive.
        info!(
            "inbound self-id refused: connection from {addr} presented our own NodeId {} — \
             dropping",
            node_id_to_base58(&node_id),
        );
        return Ok(());
    }
    info!(
        "inbound TLS connection from {} (node {})",
        addr,
        node_id_to_base58(&node_id)
    );
    let _ = manager_tx
        .send(ManagerMsg::NewConnection {
            node_id,
            addr,
            direction: Direction::Inbound,
            stream: Box::new(TlsStream::Server(tls_stream)),
        })
        .await;
    Ok(())
}
