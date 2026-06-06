//! libp2p `Swarm` construction (#841/#842).
//!
//! Builds a tokio-driven libp2p `Swarm` over tcp + TLS (keyed by the node's
//! Ed25519 key, so `PeerId == identity::peer_id_for(node_id)`) + yamux,
//! carrying:
//! - `gossipsub` — consensus broadcast over one topic (Phase 2, #842),
//! - `identify` — peer protocol/version exchange.
//!
//! request-response (#843) and kad (#844) are added as further [`Behaviour`]
//! fields in later phases. The event loop that drives this `Swarm` and
//! implements the `Broadcaster`/`Discovery` seam lives in [`crate::overlay`].

use std::time::Duration;

use anyhow::Context as _;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode};
use libp2p::{Swarm, identify, identity::Keypair, swarm::NetworkBehaviour, tcp, tls, yamux};

/// Identify protocol name advertised on the wire.
pub const IDENTIFY_PROTOCOL: &str = "/boule/id/1.0.0";
/// Agent version advertised via identify.
pub const AGENT_VERSION: &str = concat!("boule/", env!("CARGO_PKG_VERSION"));
/// The single gossipsub topic all consensus broadcast traffic flows over.
pub const CONSENSUS_TOPIC: &str = "/boule/consensus/1.0.0";

/// The gossipsub topic handle for [`CONSENSUS_TOPIC`].
pub fn consensus_topic() -> IdentTopic {
    IdentTopic::new(CONSENSUS_TOPIC)
}

/// The boule libp2p behaviour. Grows one field per migration phase.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Consensus broadcast (votes / proposals / timeouts) over one topic.
    pub gossipsub: gossipsub::Behaviour,
    /// Peer protocol/version exchange + observed-address reporting.
    pub identify: identify::Behaviour,
}

impl Behaviour {
    /// Builder for `SwarmBuilder::with_behaviour` — boxes the error so the
    /// builder's `R: TryIntoBehaviour` bound resolves with a concrete
    /// `Error` type.
    fn new(keypair: &Keypair) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::try_new(keypair).map_err(Into::into)
    }

    fn try_new(keypair: &Keypair) -> anyhow::Result<Self> {
        // Signed messages + Strict validation: every received message must
        // carry a valid signature, source PeerId, and sequence number, so
        // `message.source` is the cryptographically-verified publisher — a
        // stronger authenticated-sender guarantee than the custom overlay's
        // unsigned `originator` field.
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            .build()
            .map_err(|e| anyhow::anyhow!("gossipsub config: {e}"))?;
        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow::anyhow!("gossipsub behaviour: {e}"))?;
        gossipsub
            .subscribe(&consensus_topic())
            .context("subscribe consensus topic")?;

        let identify = identify::Behaviour::new(
            identify::Config::new(IDENTIFY_PROTOCOL.to_string(), keypair.public())
                .with_agent_version(AGENT_VERSION.to_string()),
        );
        Ok(Self {
            gossipsub,
            identify,
        })
    }
}

/// Build a tokio-driven libp2p [`Swarm`] keyed by `keypair`.
///
/// Transport: tcp + TLS 1.3 (mutual auth, the peer's Ed25519 key is its
/// identity — the same trust model as boule's custom transport) + yamux.
pub fn build_swarm(
    keypair: Keypair,
    idle_connection_timeout: Duration,
) -> anyhow::Result<Swarm<Behaviour>> {
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
