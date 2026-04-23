use crate::gossip::GossipMessage;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum WireMessage {
    Gossip(GossipMessage),
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    #[test]
    fn gossip_variant_round_trips_through_json() {
        let original = WireMessage::Gossip(GossipMessage {
            content: "payload".into(),
            expiry: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        });

        let bytes = serde_json::to_vec(&original).unwrap();
        let decoded: WireMessage = serde_json::from_slice(&bytes).unwrap();

        let WireMessage::Gossip(msg) = decoded;
        assert_eq!(msg.content, "payload");
        assert_eq!(msg.expiry.timestamp(), 1_700_000_000);
    }

    #[test]
    fn round_trip_preserves_content_hash() {
        // The hash is what the store keys on, so serde must not perturb it.
        let original = GossipMessage {
            content: "canary".into(),
            expiry: Utc.timestamp_opt(1_700_000_000, 123_456_789).unwrap(),
        };
        let wire = WireMessage::Gossip(original.clone());

        let bytes = serde_json::to_vec(&wire).unwrap();
        let WireMessage::Gossip(back) = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(back.content_hash(), original.content_hash());
    }

    #[test]
    fn unknown_variant_is_rejected() {
        let junk = br#"{"Unknown":{"x":1}}"#;
        assert!(serde_json::from_slice::<WireMessage>(junk).is_err());
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        assert!(serde_json::from_slice::<WireMessage>(b"not json").is_err());
    }
}
