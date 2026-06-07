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

/// Identify protocol name advertised on the wire.
pub const IDENTIFY_PROTOCOL: &str = "/boule/id/1.0.0";
/// Agent version advertised via identify.
pub const AGENT_VERSION: &str = concat!("boule/", env!("CARGO_PKG_VERSION"));
/// The single gossipsub topic all consensus broadcast traffic flows over.
pub const CONSENSUS_TOPIC: &str = "/boule/consensus/1.0.0";
/// Addressed point-to-point protocol for block-sync / `send_to` traffic.
pub const BLOCK_SYNC_PROTOCOL: &str = "/boule/blocksync/1.0.0";

/// Maximum gossipsub message size (#862).
///
/// gossipsub's default `max_transmit_size` is **64 KiB**, but a consensus
/// `Proposal` carries the full EVM execution payload (every tx, JSON-hex
/// encoded) inline, so a busy block easily exceeds 64 KiB. Past that limit
/// `gossipsub.publish` returns `MessageTooLarge` and the proposal is dropped —
/// the leader can't propagate full blocks, the EL falls behind, and throughput
/// collapses (~3x lower than the legacy overlay; root cause of #862). The
/// legacy custom overlay framed consensus messages up to its 1 MiB
/// `DEFAULT_MAX_FRAME_LEN`; match that ceiling with headroom (a 30M-gas block
/// of simple transfers is ~0.36 MiB JSON-hex; leave room for fuller/contract
/// blocks and QC overhead). The block-sync (request-response/cbor) path already
/// defaults to a 1 MiB cap, so only gossipsub needs raising.
pub const MAX_TRANSMIT_SIZE: usize = 4 * 1024 * 1024;

/// The block-sync behaviour type: request = opaque consensus payload bytes,
/// response = empty ack. Consensus does its own request/response correlation
/// via two independent `send_to`s, so this protocol only needs to *deliver*
/// to a specific peer (the ack just satisfies request-response's req/resp
/// shape).
pub type BlockSync = request_response::cbor::Behaviour<Vec<u8>, ()>;

/// Connection-count caps for the libp2p backend (#544), mapped from
/// `[p2p.limits]`. `None` = unbounded.
#[derive(Clone, Copy, Default)]
pub struct Limits {
    /// Cap on established inbound connections.
    pub max_established_incoming: Option<u32>,
    /// Cap on established outbound connections.
    pub max_established_outgoing: Option<u32>,
}

/// The gossipsub topic handle for [`CONSENSUS_TOPIC`].
pub fn consensus_topic() -> IdentTopic {
    IdentTopic::new(CONSENSUS_TOPIC)
}

/// The boule libp2p behaviour. Grows one field per migration phase.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Connection gating (#844/#836). When `allowed_peers` is configured
    /// (validator isolation), only those peers may connect — every other
    /// inbound/outbound connection is refused at the transport. When unset
    /// (open / sentry node) the toggle is disabled and all peers are allowed.
    pub gating: Toggle<allow_block_list::Behaviour<AllowedPeers>>,
    /// Connection-count caps (#544), mapped from `[p2p.limits]`.
    pub connection_limits: connection_limits::Behaviour,
    /// Consensus broadcast (votes / proposals / timeouts) over one topic.
    pub gossipsub: gossipsub::Behaviour,
    /// Addressed point-to-point delivery for block-sync / `send_to` (#843).
    pub block_sync: BlockSync,
    /// Peer protocol/version exchange + observed-address reporting.
    pub identify: identify::Behaviour,
}

impl Behaviour {
    /// Builder for `SwarmBuilder::with_behaviour` — boxes the error so the
    /// builder's `R: TryIntoBehaviour` bound resolves with a concrete
    /// `Error` type. `allowed_peers = Some(non-empty)` enables validator
    /// isolation (allow-list gating); `None`/empty leaves the node open.
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

        // Signed messages + Strict validation: every received message must
        // carry a valid signature, source PeerId, and sequence number, so
        // `message.source` is the cryptographically-verified publisher — a
        // stronger authenticated-sender guarantee than the custom overlay's
        // unsigned `originator` field.
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            // Don't silently drop full-block Proposals — see MAX_TRANSMIT_SIZE (#862).
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

/// Build a tokio-driven libp2p [`Swarm`] keyed by `keypair`.
///
/// Transport: tcp + TLS 1.3 (mutual auth, the peer's Ed25519 key is its
/// identity — the same trust model as boule's custom transport) + yamux.
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
