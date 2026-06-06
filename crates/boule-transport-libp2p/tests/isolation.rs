//! Phase 4 (#844/#836): `allowed_peers` connection-gating isolates a node to
//! exactly its allow-list — the libp2p-native form of validator/sentry
//! isolation, replacing the app-enforced approach with no firewall.

use std::net::SocketAddr;
use std::time::Duration;

use boule_core::transport::overlay::Discovery as _;
use boule_transport_libp2p::identity::node_id_for;
use boule_transport_libp2p::overlay::{SpawnConfig, spawn};
use libp2p::identity::Keypair;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn allow_list_refuses_unlisted_peers() {
    let kp_a = Keypair::generate_ed25519();
    let kp_b = Keypair::generate_ed25519();
    let kp_c = Keypair::generate_ed25519();
    let node_b = node_id_for(&kp_b.public().to_peer_id()).unwrap();
    let node_c = node_id_for(&kp_c.public().to_peer_id()).unwrap();

    let aa: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let ab: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let ac: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    // A allows ONLY B, yet bootstraps to both B and C — gating must refuse C
    // on both the outbound dial and any inbound dial from C.
    let a = spawn(SpawnConfig {
        keypair: kp_a,
        listen_addr: Some(aa),
        bootstrap_addrs: vec![ab, ac],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: Some(vec![node_b]),
        limits: Default::default(),
    })
    .unwrap();
    let _b = spawn(SpawnConfig {
        keypair: kp_b,
        listen_addr: Some(ab),
        bootstrap_addrs: vec![aa],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
        limits: Default::default(),
    })
    .unwrap();
    let _c = spawn(SpawnConfig {
        keypair: kp_c,
        listen_addr: Some(ac),
        bootstrap_addrs: vec![aa],
        idle_connection_timeout: Duration::from_secs(30),
        allowed_peers: None,
        limits: Default::default(),
    })
    .unwrap();

    // Over the whole window: A must connect to B and NEVER to C.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut saw_b = false;
    while tokio::time::Instant::now() < deadline {
        let peers = a.discovery.known_peers();
        assert!(
            !peers.contains(&node_c),
            "A connected to C despite the allow-list excluding it"
        );
        if peers.contains(&node_b) {
            saw_b = true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(saw_b, "A never connected to its allowed peer B");
}
