//! Phase 1 connectivity (#841): two libp2p swarms, keyed by distinct Ed25519
//! keys, dial + mutually authenticate (TLS) + exchange identify. Proves the
//! transport works end-to-end and that each side sees the other's true
//! Ed25519 identity over the wire.

use std::time::Duration;

use boule_transport_libp2p::swarm::{BehaviourEvent, build_swarm};
use futures::StreamExt;
use libp2p::{identify, identity::Keypair, swarm::SwarmEvent};

#[tokio::test]
async fn two_nodes_connect_and_identify() {
    let kp_a = Keypair::generate_ed25519();
    let kp_b = Keypair::generate_ed25519();
    let peer_a = kp_a.public().to_peer_id();
    let peer_b = kp_b.public().to_peer_id();

    let mut a = build_swarm(kp_a, Duration::from_secs(30), None).unwrap();
    let mut b = build_swarm(kp_b, Duration::from_secs(30), None).unwrap();

    a.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    // Wait for A's bound listen address, then dial it from B.
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = a.select_next_some().await {
            break address;
        }
    };
    b.dial(addr).unwrap();

    // Drive both swarms until each has received the other's identify info.
    let mut a_saw_b = false;
    let mut b_saw_a = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while !(a_saw_b && b_saw_a) {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                panic!("timed out before mutual identify (a_saw_b={a_saw_b}, b_saw_a={b_saw_a})");
            }
            ev = a.select_next_some() => {
                if let SwarmEvent::Behaviour(BehaviourEvent::Identify(
                    identify::Event::Received { peer_id, .. })) = ev
                {
                    assert_eq!(peer_id, peer_b, "A authenticated the wrong peer");
                    a_saw_b = true;
                }
            }
            ev = b.select_next_some() => {
                if let SwarmEvent::Behaviour(BehaviourEvent::Identify(
                    identify::Event::Received { peer_id, .. })) = ev
                {
                    assert_eq!(peer_id, peer_a, "B authenticated the wrong peer");
                    b_saw_a = true;
                }
            }
        }
    }
}
