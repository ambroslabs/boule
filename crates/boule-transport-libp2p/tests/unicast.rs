//! Phase 3 (#843): `send_to` is real addressed delivery over request-response
//! — a payload sent to one peer reaches exactly that peer, not the whole mesh.

use std::net::SocketAddr;
use std::time::Duration;

use boule_core::transport::overlay::{Broadcaster as _, Discovery as _, ProtocolEvent};
use boule_transport_libp2p::identity::node_id_for;
use boule_transport_libp2p::overlay::{SpawnConfig, spawn};
use bytes::Bytes;
use libp2p::identity::Keypair;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn send_to_is_addressed_not_broadcast() {
    let kp_a = Keypair::generate_ed25519();
    let kp_b = Keypair::generate_ed25519();
    let kp_c = Keypair::generate_ed25519();
    let node_a = node_id_for(&kp_a.public().to_peer_id()).unwrap();
    let node_b = node_id_for(&kp_b.public().to_peer_id()).unwrap();

    let aa: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let ab: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let ac: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    // Full mesh: every node bootstraps to the other two.
    let a = spawn(SpawnConfig {
        keypair: kp_a,
        listen_addr: Some(aa),
        bootstrap_addrs: vec![ab, ac],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
    })
    .unwrap();
    let mut b = spawn(SpawnConfig {
        keypair: kp_b,
        listen_addr: Some(ab),
        bootstrap_addrs: vec![aa, ac],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
    })
    .unwrap();
    let mut c = spawn(SpawnConfig {
        keypair: kp_c,
        listen_addr: Some(ac),
        bootstrap_addrs: vec![aa, ab],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
    })
    .unwrap();

    // Wait until A has a route to B (so the request-response stream can open).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !a.discovery.known_peers().contains(&node_b) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "A never connected to B"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let payload = Bytes::from_static(b"block-sync-unicast");
    a.broadcaster.send_to(node_b, payload.clone()).await;

    // B must receive it; C must NOT (it's addressed, not flooded).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut b_got = false;
    while !b_got {
        assert!(
            tokio::time::Instant::now() < deadline,
            "B did not receive the unicast"
        );
        tokio::select! {
            ev = b.event_rx.recv() => {
                if let Some(ProtocolEvent::Message { from, payload: got }) = ev {
                    assert_eq!(from, node_a, "B saw wrong sender");
                    assert_eq!(got, payload);
                    b_got = true;
                }
            }
            ev = c.event_rx.recv() => {
                if let Some(ProtocolEvent::Message { payload: got, .. }) = ev {
                    assert_ne!(got, payload, "C received a unicast addressed to B — it was broadcast!");
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }

    // Grace window: confirm C never receives the addressed payload.
    let grace = tokio::time::Instant::now() + Duration::from_millis(750);
    while tokio::time::Instant::now() < grace {
        if let Ok(Some(ProtocolEvent::Message { payload: got, .. })) =
            tokio::time::timeout(Duration::from_millis(100), c.event_rx.recv()).await
        {
            assert_ne!(got, payload, "C received a unicast addressed to B");
        }
    }
}
