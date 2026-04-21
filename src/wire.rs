use crate::gossip::GossipMessage;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum WireMessage {
    Gossip(GossipMessage),
}
