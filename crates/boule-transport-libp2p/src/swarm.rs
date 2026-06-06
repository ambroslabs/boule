//! libp2p `Swarm` construction (Phase 1, #841).
//!
//! Builds a tokio-driven libp2p `Swarm` over tcp + TLS (keyed by the node's
//! Ed25519 key, so `PeerId == identity::peer_id_for(node_id)`) + yamux.
//! Phase 1 carries only the `identify` behaviour — enough to prove that two
//! boule nodes mutually authenticate and exchange protocol info over libp2p.
//! gossipsub (#842), request-response (#843), and kad discovery (#844) are
//! added as further [`Behaviour`] fields in later phases.

use std::time::Duration;

use anyhow::Result;
use libp2p::{Swarm, identify, identity::Keypair, swarm::NetworkBehaviour, tcp, tls, yamux};

/// Identify protocol name advertised on the wire.
pub const IDENTIFY_PROTOCOL: &str = "/boule/id/1.0.0";
/// Agent version advertised via identify.
pub const AGENT_VERSION: &str = concat!("boule/", env!("CARGO_PKG_VERSION"));

/// The boule libp2p behaviour. Grows one field per migration phase.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Peer protocol/version exchange + observed-address reporting.
    pub identify: identify::Behaviour,
}

impl Behaviour {
    fn new(keypair: &Keypair) -> Self {
        let identify = identify::Behaviour::new(
            identify::Config::new(IDENTIFY_PROTOCOL.to_string(), keypair.public())
                .with_agent_version(AGENT_VERSION.to_string()),
        );
        Self { identify }
    }
}

/// Build a tokio-driven libp2p [`Swarm`] keyed by `keypair`.
///
/// Transport: tcp + TLS 1.3 (mutual auth, the peer's Ed25519 key is its
/// identity — the same trust model as boule's custom transport) + yamux.
pub fn build_swarm(
    keypair: Keypair,
    idle_connection_timeout: Duration,
) -> Result<Swarm<Behaviour>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            tls::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(Behaviour::new)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(idle_connection_timeout))
        .build();
    Ok(swarm)
}
