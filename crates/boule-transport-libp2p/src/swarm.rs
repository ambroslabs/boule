use std::time::Duration;

use anyhow::Context as _;
use boule_core::identity::NodeId;
use libp2p::allow_block_list::{self, AllowedPeers};
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    StreamProtocol, Swarm, identify, identity::Keypair, swarm::NetworkBehaviour, tcp, tls, yamux,
};

use crate::identity::peer_id_for;

pub const IDENTIFY_PROTOCOL: &str = "/boule/id/1.0.0";

pub const AGENT_VERSION: &str = concat!("boule/", env!("CARGO_PKG_VERSION"));

pub const CONSENSUS_TOPIC: &str = "/boule/consensus/1.0.0";

pub const BLOCK_SYNC_PROTOCOL: &str = "/boule/blocksync/1.0.0";

pub const MAX_TRANSMIT_SIZE: usize = 4 * 1024 * 1024;

pub type BlockSync = request_response::cbor::Behaviour<Vec<u8>, ()>;

#[derive(Clone, Copy, Default)]
pub struct Limits {
    pub max_established_incoming: Option<u32>,

    pub max_established_outgoing: Option<u32>,
}

pub fn consensus_topic() -> IdentTopic {
    IdentTopic::new(CONSENSUS_TOPIC)
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gating: Toggle<allow_block_list::Behaviour<AllowedPeers>>,

    pub connection_limits: connection_limits::Behaviour,

    pub gossipsub: gossipsub::Behaviour,

    pub block_sync: BlockSync,

    pub identify: identify::Behaviour,
}

impl Behaviour {
    fn new(
        keypair: &Keypair,
        allowed_peers: Option<&[NodeId]>,
        limits: Limits,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::try_new(keypair, allowed_peers, limits).map_err(Into::into)
    }

    fn try_new(
        keypair: &Keypair,
        allowed_peers: Option<&[NodeId]>,
        limits: Limits,
    ) -> anyhow::Result<Self> {
        let gating = match allowed_peers {
            Some(ids) if !ids.is_empty() => {
                let mut b = allow_block_list::Behaviour::<AllowedPeers>::default();
                for id in ids {
                    b.allow_peer(peer_id_for(id).context("allowed_peers entry")?);
                }
                Toggle::from(Some(b))
            }
            _ => Toggle::from(None),
        };

        let connection_limits = connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_established_incoming(limits.max_established_incoming)
                .with_max_established_outgoing(limits.max_established_outgoing),
        );

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
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

        let block_sync = BlockSync::new(
            [(
                StreamProtocol::new(BLOCK_SYNC_PROTOCOL),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        let identify = identify::Behaviour::new(
            identify::Config::new(IDENTIFY_PROTOCOL.to_string(), keypair.public())
                .with_agent_version(AGENT_VERSION.to_string()),
        );
        Ok(Self {
            gating,
            connection_limits,
            gossipsub,
            block_sync,
            identify,
        })
    }
}

pub fn build_swarm(
    keypair: Keypair,
    idle_connection_timeout: Duration,
    allowed_peers: Option<Vec<NodeId>>,
    limits: Limits,
) -> anyhow::Result<Swarm<Behaviour>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            tls::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|kp| Behaviour::new(kp, allowed_peers.as_deref(), limits))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(idle_connection_timeout))
        .build();
    Ok(swarm)
}
