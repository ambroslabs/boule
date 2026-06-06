//! Phase 2 (#842): a payload broadcast through the libp2p `Broadcaster`
//! reaches a second node as a `ProtocolEvent::Message` on the seam consensus
//! consumes, attributed to the true (signature-verified) sender.

use std::net::SocketAddr;
use std::time::Duration;

use boule_core::transport::overlay::{Broadcaster as _, ProtocolEvent};
use boule_transport_libp2p::identity::node_id_for;
use boule_transport_libp2p::overlay::{SpawnConfig, spawn};
use bytes::Bytes;
use libp2p::identity::Keypair;

/// Grab an ephemeral port the OS just handed out (good enough for a loopback
/// test; production binds a fixed configured port).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn gossipsub_broadcast_reaches_peer_through_seam() {
    let kp_a = Keypair::generate_ed25519();
    let kp_b = Keypair::generate_ed25519();
    let node_a = node_id_for(&kp_a.public().to_peer_id()).unwrap();

    let addr_a: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    let a = spawn(SpawnConfig {
        keypair: kp_a,
        listen_addr: Some(addr_a),
        bootstrap_addrs: vec![],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
    })
    .unwrap();

    let mut b = spawn(SpawnConfig {
        keypair: kp_b,
        listen_addr: Some(addr_b),
        bootstrap_addrs: vec![addr_a],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
    })
    .unwrap();

    let payload = Bytes::from_static(b"hello-over-gossipsub");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_connect = false;

    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out before delivery (saw_connect={saw_connect})"
        );

        // (Re)broadcast from A each tick — harmless before the mesh forms,
        // and the retry covers gossipsub mesh warm-up.
        a.broadcaster.broadcast(payload.clone()).await;

        match tokio::time::timeout(Duration::from_millis(200), b.event_rx.recv()).await {
            Ok(Some(ProtocolEvent::PeerConnected { node_id, .. })) => {
                assert_eq!(node_id, node_a, "B connected to the wrong peer");
                saw_connect = true;
            }
            Ok(Some(ProtocolEvent::Message { from, payload: got })) => {
                assert_eq!(from, node_a, "message attributed to the wrong sender");
                assert_eq!(got, payload, "payload corrupted in transit");
                assert!(saw_connect, "got a message before a PeerConnected event");
                return; // success
            }
            // PeerDisconnected, channel-closed, or per-tick timeout: keep trying.
            _ => {}
        }
    }
}
