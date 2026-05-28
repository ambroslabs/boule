//! Read-only snapshot of consensus-internal state for the
//! `GET /consensus/status` HTTP endpoint.
//!
//! # Shape and purpose
//!
//! The snapshot is a plain-data struct that captures the fields a human
//! operator needs to answer the common "what is this node doing right
//! now?" questions during testnet debugging:
//!
//! - Which view is the node in? Is it the current leader?
//! - What is the highest QC / lock the node has observed?
//! - Are vote-buckets or timeout-buckets close to quorum?
//! - Is there a proposal parked waiting for a missing parent?
//! - Which peers does the consensus layer currently talk to?
//!
//! # Encoding conventions
//!
//! - **Block hashes** are hex-encoded (32 bytes → 64 hex chars). Block
//!   hashes are content digests, not identities, so hex (a stable
//!   byte-for-byte representation) is the right choice. Base58 is
//!   reserved for [`NodeId`](boule::identity::NodeId).
//! - **NodeIds** are base58, matching
//!   [`boule::identity::node_id_to_base58`] — the convention used
//!   everywhere else the node surfaces a NodeId (logs, `/peers`).
//!
//! # Publication model
//!
//! `ConsensusNode` builds a
//! fresh [`ConsensusStatus`] at the end of each event-loop iteration
//! and publishes it through a [`tokio::sync::watch`] channel. The HTTP
//! handler holds the receiver and returns the latest value; this is a
//! snapshot-and-publish pattern with zero hot-path contention. If the
//! event loop hasn't ticked yet, the initial value published at startup
//! is returned (all counters zero).

use serde::{Deserialize, Serialize};

use super::{Height, View};

/// The `locked` block (HotStuff two-chain lock) as of the snapshot
/// instant. See [`crate::hotstuff::state::Locked`] for the
/// safety-core representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedStatus {
    pub view: View,
    pub height: Height,
    /// 32-byte block hash, hex-encoded.
    pub block_hash: String,
}

/// Summary of the highest-view QC the node has observed. `height` is
/// looked up in `pending_blocks` and may be `None` for a QC whose
/// block is no longer retained (post-commit pruning — a future
/// enhancement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcStatus {
    pub view: View,
    pub height: Option<Height>,
    /// 32-byte block hash, hex-encoded.
    pub block_hash: String,
}

/// Partial QC the leader is accumulating. `signers` is the current
/// distinct-signer count; `quorum` is the threshold needed to seal the
/// QC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteBucketStatus {
    pub view: View,
    /// 32-byte block hash the votes in this bucket are for, hex-encoded.
    pub block_hash: String,
    pub signers: usize,
    pub quorum: usize,
}

/// Partial timeout certificate. Same "signers / quorum" shape as
/// [`VoteBucketStatus`] but keyed only by view (timeout votes are not
/// tied to a specific block).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutBucketStatus {
    pub view: View,
    pub signers: usize,
    pub quorum: usize,
}

/// A proposal the safety core is holding onto while it waits for the
/// parent block to arrive via the block-sync sub-protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedProposalStatus {
    /// 32-byte hash of the proposal's own block, hex-encoded.
    pub block_hash: String,
    /// 32-byte hash of the missing parent, hex-encoded.
    pub parent_hash: String,
    pub view: View,
}

/// Cumulative count of cap- or `gc_below`-driven evictions across the
/// four bounded consensus caches (`vote_bucket`, `parked_proposals`,
/// `pending_blocks`, `timeout_buckets`). Surfaced so an operator
/// watching the status endpoint can spot a sustained flood pressuring
/// any one cache without having to grep tracing logs.
///
/// Counters are monotonic for the lifetime of the node — they reset on
/// restart but never decrement during a run. A non-zero value is not
/// itself a fault: eviction under load is the intended behaviour and
/// is logged at INFO, not WARN. Sustained growth (especially
/// concentrated on one cache) does indicate either a Byzantine flood
/// or a misconfigured cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CacheEvictionStatus {
    /// `vote_bucket` entries dropped — both cap-based on insert and
    /// `gc_below` sweeps on `PacemakerAdvance` contribute.
    pub vote_buckets: u64,
    /// `parked_proposals` entries dropped under cap pressure.
    pub parked_proposals: u64,
    /// `pending_blocks` entries dropped under cap pressure. The
    /// on-commit `retain(height > committed)` prune does not
    /// contribute — only forced cap evictions.
    pub pending_blocks: u64,
    /// `timeout_buckets` entries dropped under cap pressure. The
    /// on-TC-formation `retain(v > view)` prune does not
    /// contribute — only forced cap evictions.
    pub timeout_buckets: u64,
}

/// Cumulative count of drops on the production drop-on-full back-pressure
/// paths. In short,
/// these are paths where a sender would otherwise have to choose between
/// blocking forever (wedging consensus) and dropping silently (causing
/// hard-to-diagnose request loss). The drop is the right behaviour;
/// surfacing the counter is what makes the back-pressure visible
/// instead of invisible.
///
/// Counters are monotonic for the lifetime of the node and reset on
/// restart. A small non-zero value is not itself a fault — gossip and
/// peer-list pushes have multiple delivery paths and tolerate isolated
/// drops — but sustained growth points at a wedged peer connection or
/// an undersized per-peer queue (#163 design notes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackpressureStatus {
    /// Drops from
    /// `boule_transport_tcp::overlay::gossip::sink::OverlaySink::send_to`'s
    /// `try_send` falling back on `Full`. Used by the gossip overlay's
    /// peer-list publisher and the overlay run loop's per-peer
    /// unicasts. Always zero on a node configured for mesh-mode
    /// overlay (no gossip sink in play).
    pub gossip_sink_overflow_total: u64,
    /// Drops from the per-peer outbound `write_tx.try_send` in the p2p
    /// manager — both `SendTo` and `Broadcast` paths feed the same
    /// counter. Each increment is one frame that didn't make it onto a
    /// peer's write channel because it was at capacity (the
    /// must-deliver-or-disconnect path's drop side). Closed-channel
    /// failures are not counted (manager-shutdown noise).
    #[serde(default)]
    pub peer_outbound_overflow_total: u64,
    /// Drops from the block-sync responder's per-peer outstanding-
    /// request cap (#498). Each increment is one `RequestBlock` the
    /// responder declined to serve because the issuing peer already
    /// had `BLOCK_SYNC_OUTSTANDING_PER_PEER` requests in flight at
    /// this node. Defense-in-depth above the per-peer rate limiter
    /// (#134) — the rate limiter caps inbound RPS, the credit window
    /// caps concurrent serves. Synchronous serving today means the
    /// counter is moved by the cap only under genuinely concurrent
    /// dispatch (e.g. a future async responder); on the synchronous
    /// run-loop path the count never exceeds 1 and this counter
    /// stays at zero. Closed-channel failures are not counted.
    #[serde(default)]
    pub block_sync_serve_drops_total: u64,
    /// Drops from the per-peer outbound bytes/sec cap (#553). Each
    /// increment is one egress frame the rate limiter declined to
    /// hand to the transport because the recipient peer's outbound
    /// bucket was empty — typically a `BlockRangeResponse` that
    /// would have amplified a tiny incoming `BlockRangeRequest` into
    /// hundreds of KB on the wire. Sustained growth points at a
    /// Byzantine peer pulling more egress out of the responder than
    /// `outbound_bytes_per_sec` allows, or at an under-sized
    /// outbound bucket throttling honest catch-up.
    #[serde(default)]
    pub p2p_egress_byte_drops_total: u64,
}

/// One entry in a validator's signing-key history. `v_eff` is the view
/// at which `pubkey` became the validator's active signing key; the
/// genesis entry's `v_eff` is `0`. Sibling of
/// [`crate::validator_key_history::PersistedKeyEntry`] but
/// with the pubkey rendered as base58 so the JSON shape matches the
/// rest of `ConsensusStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationEntry {
    pub v_eff: View,
    /// base58-encoded [`NodeId`](boule::identity::NodeId).
    pub pubkey: String,
}

/// One validator's full signing-key timeline as seen by the local node
/// (#314). Surfaces what each replica believes about every validator's
/// active key plus every rotation it has applied, so an oncall operator
/// can answer "is the cluster in agreement on the active signing key
/// for validator V?" by diffing this field across `/consensus/status`
/// responses from different replicas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyStatus {
    /// base58-encoded stable identifier — the validator's genesis
    /// pubkey, or whatever pubkey it was added under via reconfig.
    /// Stable across rotations.
    pub stable_id: String,
    /// base58-encoded current active signing key — equal to
    /// `entries.last().pubkey` and surfaced as a top-level field for
    /// quick "what key should I see signing right now?" lookups.
    pub active_pubkey: String,
    /// One entry per `(v_eff, pubkey)` boundary in the validator's
    /// history, in chronological order. `entries[0]` is always the
    /// genesis entry (`v_eff = 0` for genesis-seeded validators, or the
    /// reconfig view at which the validator was added).
    pub entries: Vec<RotationEntry>,
}

/// A snapshot of a consensus node's live state, returned by
/// `GET /consensus/status`.
///
/// Fields are public so callers can match against specific paths in
/// tests. Serialization is driven by `serde`; the JSON shape is the
/// public contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// This node's base58-encoded [`NodeId`](boule::identity::NodeId).
    pub node_id: String,
    /// `"leader(view=N)"` when this node is the round-robin leader for
    /// the current view; otherwise `"replica"`.
    pub self_role: String,
    pub current_view: View,
    pub last_voted_view: View,
    pub last_committed_height: Height,
    pub last_committed_view: View,
    pub locked: Option<LockedStatus>,
    pub high_qc: Option<QcStatus>,
    /// Vote buckets whose view falls within `current_view ± 4`. The
    /// bound keeps the payload small under a Byzantine flood of
    /// future-view votes.
    pub vote_buckets: Vec<VoteBucketStatus>,
    /// Timeout-vote buckets within `current_view ± 4`.
    pub timeout_buckets: Vec<TimeoutBucketStatus>,
    pub parked_proposals: Vec<ParkedProposalStatus>,
    pub pending_blocks_count: usize,
    /// Consensus-layer view of connected peers (not the raw p2p
    /// manager's peer map). Base58-encoded [`NodeId`](boule::identity::NodeId)s.
    pub peers_connected: Vec<String>,
    /// Every validator in the committee, base58-encoded and sorted in
    /// the order used for round-robin leader rotation.
    pub validator_set: Vec<String>,
    /// Every validator the local key history knows about (#314), with
    /// each one's full rotation timeline. Sorted by `stable_id` for a
    /// deterministic JSON shape. Includes validators that have left
    /// the active set — the key history retains them so spanning votes
    /// from their tenure stay verifiable.
    #[serde(default)]
    pub validator_keys: Vec<ValidatorKeyStatus>,
    pub mempool_size: usize,
    /// Cumulative cache-eviction counters across the four bounded
    /// consensus caches. See [`CacheEvictionStatus`].
    #[serde(default)]
    pub cache_evictions: CacheEvictionStatus,
    /// Cumulative count of commands the local
    /// `boule_node::consensus_node::block_builder::MempoolBlockBuilder` dropped
    /// because `StateMachine::apply` returned `Err` (decode error,
    /// bad command kind, or app-level rejection — issue #376). The
    /// commands themselves still ride the proposed block; replicas
    /// hit the same deterministic failure and the commitment
    /// converges. Monotonic for the lifetime of the node — resets on
    /// restart but never decrements during a run. A non-zero value
    /// is not itself a fault (a single malformed mempool entry
    /// counts), but sustained growth is a signal worth surfacing.
    #[serde(default)]
    pub dropped_commands: u64,
    /// Cumulative count of vote-equivocation incidents detected by the
    /// safety core (audit finding 3-1, issue #409): a single stable
    /// validator id contributing votes for two distinct `block_hash`
    /// values at the same view. Each incident corresponds to one
    /// [`crate::hotstuff::step::Action::EquivocationEvidence`]
    /// emitted by the safety core; the integration layer increments
    /// this counter and logs the event at WARN. Monotonic for the
    /// lifetime of the node — resets on restart but never decrements
    /// during a run. A non-zero value indicates a Byzantine voter is
    /// detectable on the wire; future slashing pipelines will consume
    /// the same evidence.
    #[serde(default)]
    pub equivocations_detected: u64,
    /// Cumulative count of proposal-equivocation incidents detected by
    /// the safety core (audit finding L5-1): a single stable validator
    /// id contributing proposals for two distinct `block_hash` values
    /// at the same view. Each incident corresponds to one
    /// [`crate::hotstuff::step::Action::ProposalEquivocationEvidence`]
    /// emitted by the safety core; the integration layer increments
    /// this counter and logs the event at WARN. Sibling of
    /// [`Self::equivocations_detected`] — a separate counter so
    /// proposer-side and voter-side Byzantine activity stay
    /// independently observable. Monotonic for the lifetime of the
    /// node — resets on restart but never decrements during a run. A
    /// non-zero value indicates a Byzantine leader is detectable on
    /// the wire; future slashing pipelines will consume the same
    /// evidence.
    #[serde(default)]
    pub proposal_equivocations_detected: u64,
    /// Cumulative drop counts on the production drop-on-full
    /// back-pressure paths. See [`BackpressureStatus`].
    #[serde(default)]
    pub backpressure: BackpressureStatus,
}

/// How far on either side of `current_view` to include in the bucket
/// summaries. Kept module-public so the node builder and the unit tests
/// agree.
pub const BUCKET_VIEW_WINDOW: u64 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_status() -> ConsensusStatus {
        ConsensusStatus {
            node_id: "DmX44PdK8JNVZUkbLTpD3W5ngmVnWBGyYrmFhh2Mkdb4".to_string(),
            self_role: "leader(view=157)".to_string(),
            current_view: View(157),
            last_voted_view: View(156),
            last_committed_height: Height(156),
            last_committed_view: View(157),
            locked: Some(LockedStatus {
                view: View(155),
                height: Height(154),
                block_hash: "aa".repeat(32),
            }),
            high_qc: Some(QcStatus {
                view: View(156),
                height: Some(Height(155)),
                block_hash: "bb".repeat(32),
            }),
            vote_buckets: vec![VoteBucketStatus {
                view: View(158),
                block_hash: "cc".repeat(32),
                signers: 2,
                quorum: 3,
            }],
            timeout_buckets: vec![TimeoutBucketStatus {
                view: View(159),
                signers: 1,
                quorum: 3,
            }],
            parked_proposals: vec![ParkedProposalStatus {
                block_hash: "dd".repeat(32),
                parent_hash: "ee".repeat(32),
                view: View(158),
            }],
            pending_blocks_count: 3,
            peers_connected: vec![
                "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX".to_string(),
                "BHx4E18joU7w95zGkJwuCJ6RY8HMZC394aezTXTES5yA".to_string(),
            ],
            validator_set: vec![
                "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX".to_string(),
                "BHx4E18joU7w95zGkJwuCJ6RY8HMZC394aezTXTES5yA".to_string(),
                "DmX44PdK8JNVZUkbLTpD3W5ngmVnWBGyYrmFhh2Mkdb4".to_string(),
            ],
            validator_keys: vec![
                ValidatorKeyStatus {
                    stable_id: "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX".to_string(),
                    active_pubkey: "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX".to_string(),
                    entries: vec![RotationEntry {
                        v_eff: View(0),
                        pubkey: "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX".to_string(),
                    }],
                },
                ValidatorKeyStatus {
                    stable_id: "BHx4E18joU7w95zGkJwuCJ6RY8HMZC394aezTXTES5yA".to_string(),
                    active_pubkey: "RotatedKeyExampleBase58XXXXXXXXXXXXXXXXXXXXXX".to_string(),
                    entries: vec![
                        RotationEntry {
                            v_eff: View(0),
                            pubkey: "BHx4E18joU7w95zGkJwuCJ6RY8HMZC394aezTXTES5yA".to_string(),
                        },
                        RotationEntry {
                            v_eff: View(120),
                            pubkey: "RotatedKeyExampleBase58XXXXXXXXXXXXXXXXXXXXXX".to_string(),
                        },
                    ],
                },
            ],
            mempool_size: 0,
            cache_evictions: CacheEvictionStatus {
                vote_buckets: 7,
                parked_proposals: 3,
                pending_blocks: 1,
                timeout_buckets: 0,
            },
            dropped_commands: 11,
            equivocations_detected: 2,
            proposal_equivocations_detected: 4,
            backpressure: BackpressureStatus {
                gossip_sink_overflow_total: 5,
                peer_outbound_overflow_total: 9,
                block_sync_serve_drops_total: 2,
                p2p_egress_byte_drops_total: 13,
            },
        }
    }

    #[test]
    fn serializes_to_json_with_expected_key_paths() {
        let status = sample_status();
        let json = serde_json::to_value(&status).unwrap();

        // Top-level scalar fields.
        assert_eq!(
            json["node_id"],
            "DmX44PdK8JNVZUkbLTpD3W5ngmVnWBGyYrmFhh2Mkdb4"
        );
        assert_eq!(json["self_role"], "leader(view=157)");
        assert_eq!(json["current_view"], 157);
        assert_eq!(json["last_voted_view"], 156);
        assert_eq!(json["last_committed_height"], 156);
        assert_eq!(json["last_committed_view"], 157);
        assert_eq!(json["pending_blocks_count"], 3);
        assert_eq!(json["mempool_size"], 0);

        // Nested `locked`.
        assert_eq!(json["locked"]["view"], 155);
        assert_eq!(json["locked"]["height"], 154);
        assert_eq!(json["locked"]["block_hash"], "aa".repeat(32));

        // Nested `high_qc`.
        assert_eq!(json["high_qc"]["view"], 156);
        assert_eq!(json["high_qc"]["height"], 155);
        assert_eq!(json["high_qc"]["block_hash"], "bb".repeat(32));

        // Bucket arrays.
        assert_eq!(json["vote_buckets"][0]["view"], 158);
        assert_eq!(json["vote_buckets"][0]["signers"], 2);
        assert_eq!(json["vote_buckets"][0]["quorum"], 3);

        assert_eq!(json["timeout_buckets"][0]["view"], 159);
        assert_eq!(json["timeout_buckets"][0]["signers"], 1);

        assert_eq!(json["parked_proposals"][0]["view"], 158);
        assert_eq!(json["parked_proposals"][0]["block_hash"], "dd".repeat(32));

        // Peers + validator set.
        assert_eq!(json["peers_connected"].as_array().unwrap().len(), 2);
        assert_eq!(json["validator_set"].as_array().unwrap().len(), 3);

        // Validator-key history (#314): one entry per known validator,
        // each with its own rotation timeline.
        assert_eq!(json["validator_keys"].as_array().unwrap().len(), 2);
        assert_eq!(
            json["validator_keys"][0]["stable_id"],
            "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX"
        );
        assert_eq!(
            json["validator_keys"][0]["active_pubkey"],
            "B3CRZ1KHU3cvFUPbPtWq8v9aaqC6eexaQqqjMrDrXgNX"
        );
        assert_eq!(
            json["validator_keys"][0]["entries"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(json["validator_keys"][0]["entries"][0]["v_eff"], 0);
        assert_eq!(
            json["validator_keys"][1]["stable_id"],
            "BHx4E18joU7w95zGkJwuCJ6RY8HMZC394aezTXTES5yA"
        );
        assert_eq!(
            json["validator_keys"][1]["entries"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(json["validator_keys"][1]["entries"][1]["v_eff"], 120);
        assert_eq!(
            json["validator_keys"][1]["active_pubkey"],
            json["validator_keys"][1]["entries"][1]["pubkey"]
        );

        // Cache-eviction counters surface as a nested object.
        assert_eq!(json["cache_evictions"]["vote_buckets"], 7);
        assert_eq!(json["cache_evictions"]["parked_proposals"], 3);
        assert_eq!(json["cache_evictions"]["pending_blocks"], 1);
        assert_eq!(json["cache_evictions"]["timeout_buckets"], 0);

        // Block-builder dropped-command counter (#376).
        assert_eq!(json["dropped_commands"], 11);

        // Vote-equivocation counter (audit 3-1, #409).
        assert_eq!(json["equivocations_detected"], 2);

        // Proposal-equivocation counter (audit L5-1).
        assert_eq!(json["proposal_equivocations_detected"], 4);

        // Back-pressure overflow counters (#163 / #486 / #498 / #553).
        assert_eq!(json["backpressure"]["gossip_sink_overflow_total"], 5);
        assert_eq!(json["backpressure"]["peer_outbound_overflow_total"], 9);
        assert_eq!(json["backpressure"]["block_sync_serve_drops_total"], 2);
        assert_eq!(json["backpressure"]["p2p_egress_byte_drops_total"], 13);
    }

    #[test]
    fn block_hashes_are_64_hex_chars() {
        // Guard against accidental base58 / base64 encoding of block hashes.
        let status = sample_status();
        let json = serde_json::to_value(&status).unwrap();
        let hash = json["locked"]["block_hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "block_hash must be hex: {hash}",
        );
    }

    #[test]
    fn roundtrips_through_json() {
        let status = sample_status();
        let bytes = serde_json::to_vec(&status).unwrap();
        let decoded: ConsensusStatus = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn optional_fields_serialize_as_null_when_absent() {
        let mut s = sample_status();
        s.locked = None;
        s.high_qc = None;
        let json = serde_json::to_value(&s).unwrap();
        assert!(json["locked"].is_null());
        assert!(json["high_qc"].is_null());
    }

    #[test]
    fn initial_zeroed_snapshot_serializes() {
        // The status published before the event loop ticks must be
        // serializable as-is, so the endpoint never 500s in the
        // "just-booted" window the integration test cares about.
        let s = ConsensusStatus {
            node_id: String::new(),
            self_role: "replica".to_string(),
            current_view: View::ZERO,
            last_voted_view: View::ZERO,
            last_committed_height: Height::ZERO,
            last_committed_view: View::ZERO,
            locked: None,
            high_qc: None,
            vote_buckets: Vec::new(),
            timeout_buckets: Vec::new(),
            parked_proposals: Vec::new(),
            pending_blocks_count: 0,
            peers_connected: Vec::new(),
            validator_set: Vec::new(),
            validator_keys: Vec::new(),
            mempool_size: 0,
            cache_evictions: CacheEvictionStatus::default(),
            dropped_commands: 0,
            equivocations_detected: 0,
            proposal_equivocations_detected: 0,
            backpressure: BackpressureStatus::default(),
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["current_view"], 0);
        assert_eq!(json["last_committed_height"], 0);
        assert!(json["locked"].is_null());
        assert!(json["vote_buckets"].as_array().unwrap().is_empty());
        assert!(json["validator_keys"].as_array().unwrap().is_empty());
        assert_eq!(json["cache_evictions"]["vote_buckets"], 0);
        assert_eq!(json["cache_evictions"]["parked_proposals"], 0);
        assert_eq!(json["cache_evictions"]["pending_blocks"], 0);
        assert_eq!(json["cache_evictions"]["timeout_buckets"], 0);
        assert_eq!(json["dropped_commands"], 0);
        assert_eq!(json["equivocations_detected"], 0);
        assert_eq!(json["proposal_equivocations_detected"], 0);
    }
}
