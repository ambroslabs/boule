use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::manager::ManagerMsg;
use super::tls::{NodeId, TlsStream, extract_node_id, node_id_to_base58};
use boule_core::transport::limits::{Direction, HandshakeLimiter};
use tokio_rustls::TlsAcceptor;

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    our_id: NodeId,
    manager_tx: mpsc::Sender<ManagerMsg>,
    handshake_limiter: Option<Arc<HandshakeLimiter>>,
) {
    info!("TCP listener started on {}", listener.local_addr().unwrap());
    loop {
        match listener.accept().await {
            Ok((tcp_stream, addr)) => {
                // Pre-admission guard (#805): reserve a handshake slot
                // *before* spawning any TLS work, bounding the number of
                // half-open handshakes globally and per source IP. Charged
                // here — not after the handshake completes like the
                // `ConnectionLimiter` — so a slowloris flood of half-open
                // TLS handshakes from many IPs cannot spawn unbounded
                // accept tasks. The permit's `Drop` frees the slot on
                // every exit path (success, TLS error, or timeout).
                let permit = match handshake_limiter.as_ref() {
                    Some(limiter) => match limiter.try_acquire(addr.ip()) {
                        Ok(permit) => Some(permit),
                        Err(reason) => {
                            warn!(
                                addr = %addr,
                                reason = reason.label(),
                                "inbound handshake refused: pre-admission cap reached",
                            );
                            // Drop the socket without running TLS; the peer
                            // sees RST/EOF.
                            drop(tcp_stream);
                            continue;
                        }
                    },
                    None => None,
                };
                let timeout = handshake_limiter.as_ref().map(|l| l.timeout());
                let acceptor = acceptor.clone();
                let manager_tx = manager_tx.clone();
                tokio::spawn(async move {
                    // Keep the permit alive for the whole handshake; it
                    // releases on drop when this task returns.
                    let _permit = permit;
                    let result = match timeout {
                        Some(dur) => {
                            match tokio::time::timeout(
                                dur,
                                handshake_inbound(tcp_stream, addr, acceptor, our_id, manager_tx),
                            )
                            .await
                            {
                                Ok(result) => result,
                                Err(_elapsed) => {
                                    // Slowloris: the peer stalled mid-handshake
                                    // and hit the wall-clock deadline. Dropping
                                    // the future closes the socket and frees the
                                    // handshake slot via `_permit`.
                                    warn!(
                                        addr = %addr,
                                        timeout_ms = dur.as_millis(),
                                        "inbound TLS handshake timed out",
                                    );
                                    return;
                                }
                            }
                        }
                        None => {
                            handshake_inbound(tcp_stream, addr, acceptor, our_id, manager_tx).await
                        }
                    };
                    if let Err(e) = result {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use boule_core::identity::NodeIdentity;
    use boule_core::transport::limits::{HandshakeLimitsConfig, HandshakeReject};
    use rcgen::{KeyPair, PKCS_ED25519};
    use tokio::net::TcpStream;
    use zeroize::Zeroizing;

    use super::super::tls::TlsIdentity;
    use super::*;

    fn fresh_acceptor() -> (TlsAcceptor, NodeId) {
        let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        let tls = TlsIdentity::from_identity(&id).unwrap();
        (tls.acceptor.clone(), tls.node_id)
    }

    /// Spawn a listener on an ephemeral port with the given handshake
    /// limiter. Returns the bound addr plus the manager-side receiver so
    /// a test can assert whether any connection was ever admitted.
    async fn spawn_listener(
        limiter: Option<Arc<HandshakeLimiter>>,
    ) -> (SocketAddr, mpsc::Receiver<ManagerMsg>) {
        let (acceptor, our_id) = fresh_acceptor();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let (manager_tx, manager_rx) = mpsc::channel::<ManagerMsg>(16);
        tokio::spawn(run(tcp, acceptor, our_id, manager_tx, limiter));
        (addr, manager_rx)
    }

    /// #805 acceptance — slowloris: a client that opens the TCP socket
    /// but never sends a TLS ClientHello stalls `acceptor.accept(..)`
    /// forever pre-#805. With a short handshake timeout it is dropped at
    /// the deadline, the in-flight handshake slot is freed, and the
    /// manager never sees a `NewConnection`. So a half-open flood can't
    /// pin accept-side resources.
    #[tokio::test]
    async fn half_open_handshake_times_out_and_frees_slot() {
        let limiter = Arc::new(HandshakeLimiter::new(HandshakeLimitsConfig {
            max_inflight: 16,
            max_inflight_per_ip: 16,
            timeout: Duration::from_millis(150),
        }));
        let (addr, mut manager_rx) = spawn_listener(Some(Arc::clone(&limiter))).await;

        // Connect but send nothing — the half-open handshake.
        let _slow = TcpStream::connect(addr).await.unwrap();

        // The slot is taken while the handshake is in flight.
        let mut saw_inflight = false;
        for _ in 0..50 {
            if limiter.inflight() >= 1 {
                saw_inflight = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            saw_inflight,
            "handshake slot should be charged while in flight"
        );

        // After the timeout fires, the slot is released.
        let mut freed = false;
        for _ in 0..100 {
            if limiter.inflight() == 0 {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(freed, "timed-out handshake must free its in-flight slot");

        // The manager never received a NewConnection for the stalled peer.
        assert!(
            manager_rx.try_recv().is_err(),
            "a half-open handshake must never be admitted to the manager",
        );
    }

    /// #805 acceptance — flood does not exhaust accept capacity: many
    /// concurrent half-open handshakes from the same IP fill at most
    /// `max_inflight_per_ip` slots; the rest are refused pre-handshake
    /// (the reject counter climbs) and `inflight()` never exceeds the
    /// cap. Models a single attacker opening sockets faster than they
    /// complete TLS.
    #[tokio::test]
    async fn half_open_flood_is_bounded_by_inflight_cap() {
        // Long-ish timeout so the slow handshakes stay in flight for the
        // duration of the assertion window (they never complete TLS).
        let limiter = Arc::new(HandshakeLimiter::new(HandshakeLimitsConfig {
            max_inflight: 64,
            max_inflight_per_ip: 3,
            timeout: Duration::from_secs(30),
        }));
        let (addr, mut manager_rx) = spawn_listener(Some(Arc::clone(&limiter))).await;

        // Open 20 half-open sockets from 127.0.0.1 — all share one IP, so
        // the per-IP cap of 3 is the binding constraint.
        let mut sockets = Vec::new();
        for _ in 0..20 {
            sockets.push(TcpStream::connect(addr).await.unwrap());
        }

        // Converge: at most 3 in flight, and the surplus shows up as
        // rejects (poll-with-budget, well under the 15s ceiling).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let inflight = limiter.inflight();
            assert!(
                inflight <= 3,
                "in-flight handshakes must never exceed the per-IP cap; got {inflight}",
            );
            if inflight == 3 && limiter.rejects() >= 1 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "did not converge: inflight={inflight}, rejects={}",
                    limiter.rejects(),
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // No half-open connection was admitted to the manager.
        assert!(manager_rx.try_recv().is_err());

        // Direct check on the limiter: a fourth acquire from the same IP
        // is refused with the per-IP reason while the flood holds its
        // slots. (`HandshakePermit` isn't `Debug`/`PartialEq`, so match
        // the variant rather than `assert_eq!` on the whole `Result`.)
        let ip = addr.ip();
        match limiter.try_acquire(ip) {
            Err(HandshakeReject::PerIpInflight) => {}
            Ok(_) => panic!("per-IP cap should refuse a fourth in-flight handshake"),
            Err(other) => panic!("unexpected reject reason: {}", other.label()),
        }
    }
}
