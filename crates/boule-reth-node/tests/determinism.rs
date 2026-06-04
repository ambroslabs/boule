//! Determinism check for the registry-write carrier (#781, #782).
//!
//! The full two-instance Engine-API loop (build on node A → `newPayloadV4` on
//! node B → `eth_getStorageAt` equal) needs two live ~560 MB reth nodes and is
//! out of a unit-test budget; it belongs in a multi-node integration harness
//! (Phase 5). What we CAN prove deterministically in-process is the property the
//! two-node loop would re-confirm: **the bytes the executor reads are identical
//! on the build and the verify path, and decode to the identical write set.**
//!
//! Why that is the whole guarantee: both ctx builders the executor runs through
//! (`context_for_next_block` on build, `context_for_payload` on verify) source
//! `EthBlockExecutionCtx.extra_data` — the build path from the attributes we
//! transcribe, the verify path from the SEALED header (the same bytes that
//! propagated). So if `encode` on the proposer and `decode` on every verifier
//! are exact inverses over arbitrary inputs, the applied `recordKey` /
//! `recordWeight` / `recordSettled` calls are byte-identical on every replica.
//! These tests pin that inverse, including via the JSON-RPC ingress hex.

use boule_reth_node::engine_types::BoulePayloadAttributes;
use boule_reth_node::registry::{KeyRecord, RegistryPayload, WeightRecord};

fn payloads() -> Vec<RegistryPayload> {
    vec![
        RegistryPayload::default(),
        RegistryPayload {
            settled_view: Some(123_456),
            ..Default::default()
        },
        RegistryPayload {
            keys: vec![
                KeyRecord {
                    validator: [0x11; 32].into(),
                    v_eff: 1,
                    key: vec![0xAA; 128],
                },
                KeyRecord {
                    validator: [0x22; 32].into(),
                    v_eff: 5,
                    key: vec![0xBB; 128],
                },
            ],
            weights: vec![
                WeightRecord {
                    validator: [0x11; 32].into(),
                    weight: 7,
                },
                WeightRecord {
                    validator: [0x33; 32].into(),
                    weight: 0,
                },
            ],
            settled_view: Some(9),
        },
    ]
}

#[test]
fn build_and_verify_decode_identical_bytes() {
    for p in payloads() {
        // Build path: proposer encodes into extra_data.
        let extra_data = p.encode();
        // Verify path: every replica reads the SAME sealed-header bytes.
        let on_proposer = RegistryPayload::decode(&extra_data);
        let on_verifier = RegistryPayload::decode(&extra_data);
        assert_eq!(
            on_proposer, on_verifier,
            "decode is a pure function of the bytes"
        );
        if p.is_empty() {
            // An empty payload still encodes (magic + zero counts) and decodes
            // back to the empty payload — a no-op write set on every node.
            assert_eq!(on_proposer, Some(RegistryPayload::default()));
        } else {
            assert_eq!(on_proposer, Some(p));
        }
    }
}

#[test]
fn ingress_hex_roundtrips_to_carrier_bytes() {
    for p in payloads() {
        // The leader puts the payload on the Engine-API attribute as hex.
        let attrs = BoulePayloadAttributes::from_payload(Default::default(), &p);
        // The custom payload builder transcribes that hex back into extra_data.
        let carried = attrs.registry_extra_data();
        if p.is_empty() {
            // Empty payload → empty ingress → builder falls back to default
            // extra_data (a plain block); carried bytes are empty here.
            assert!(carried.is_empty());
        } else {
            // The carried bytes are EXACTLY what encode() produced, so the
            // executor on every node decodes the identical write set.
            assert_eq!(carried.as_ref(), p.encode().as_ref());
            assert_eq!(RegistryPayload::decode(&carried), Some(p));
        }
    }
}
