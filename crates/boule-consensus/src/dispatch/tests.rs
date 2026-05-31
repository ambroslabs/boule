use rcgen::KeyPair as RcgenKeyPair;
use rcgen::PKCS_ED25519;
use zeroize::Zeroizing;

use super::*;
use crate::bls_key_history::BlsKeyHistory;
use crate::hotstuff::qc::{TimeoutVote, Vote};
use crate::hotstuff::step::Event as SafetyEvent;
use crate::hotstuff::{NewView, Proposal, QuorumCertificate};
use crate::pacemaker;
use crate::replication::block::Block;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::ValidatorSet;
use boule_core::crypto::signed::{ChainId, NodeSigner, Signed, Signer};
use boule_core::identity::NodeIdentity;

fn fresh_signer() -> NodeSigner {
    let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
    let identity = NodeIdentity {
        pkcs8_der: Zeroizing::new(kp.serialize_der()),
    };
    NodeSigner::from_identity(&identity).unwrap()
}

fn genesis() -> Block {
    Block::genesis([0u8; 32], [0; 32])
}

fn sample_qc() -> QuorumCertificate {
    QuorumCertificate::new(0, genesis().hash(), 4)
}

fn make_vs_with_signers(signers: &[&NodeSigner]) -> ValidatorSet {
    let ids: Vec<crate::validator_set::ValidatorId> = signers
        .iter()
        .map(|s| crate::validator_set::ValidatorId::from_genesis_pubkey(s.node_id()))
        .collect();
    ValidatorSet::new(ids)
}

/// Test helper: build a [`ValidatorKeyHistory`] that mirrors the
/// boundaries of `set_history` with no rotations applied. This is
/// what every test in this module wants by default — the production
/// path will mutate the key history when rotation txs commit
/// (#260), but the ingress-layer tests below all set up their
/// histories by hand.
fn key_history_for(set_history: &ValidatorSetHistory) -> ValidatorKeyHistory {
    ValidatorKeyHistory::from_set_history(set_history)
}

/// Convenience: mirror of [`key_history_for`] for tests that have a
/// single static [`ValidatorSet`] rather than a history.
fn key_history_from_set(vs: &ValidatorSet) -> ValidatorKeyHistory {
    ValidatorKeyHistory::new(vs.iter().copied())
}

/// Test-only sugar: invoke [`ingress`] with the validator set
/// pinned at genesis and a key history mirroring it. Most ingress
/// tests don't care about reconfiguration boundaries — they just
/// want "this `vs` is the only validator set the verifier should
/// know about."
fn ingress_with_genesis_set(
    from: NodeId,
    bytes: &[u8],
    vs: &ValidatorSet,
) -> Result<Vec<Dispatch>, IngressError> {
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(vs);
    ingress(from, bytes, &history, &key_history, &ChainId::TEST)
}

// ── ingress: Proposal ────────────────────────────────────────────────────

#[test]
fn ingress_proposal_happy_path() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let proposal = Proposal {
        block: genesis(),
        justify: sample_qc(),
    };
    let signed = Signed::sign(proposal.clone(), &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 3);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::ProposalReceived(_))
    ));
    assert!(matches!(
        dispatches[1],
        Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(View(0)))
    ));
    assert!(matches!(
        dispatches[2],
        Dispatch::Pacemaker(pacemaker::Event::OnQc(View(0)))
    ));
}

/// #436: a Proposal whose `justify.view` is fresher than the proposal
/// view shape used in the happy-path test must surface the justify
/// view as a pacemaker `OnQc` event. Without this, a replica still at
/// view V whose `OnQc(V)` got lost would drop a follow-up proposal at
/// V+1 (the future-view rule on `OnProposalReceived`) and wedge until
/// its timer fires — even though the proposal carries proof of a QC at
/// V that should advance it immediately.
#[test]
fn ingress_proposal_emits_on_qc_at_justify_view() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    // Proposal at view 6 with a justify QC at view 5.
    let mut justify = QuorumCertificate::new(5, [0xAB; 32], 1);
    justify.add_signature(0, [0x11; 64]);
    let parent = genesis();
    let header = crate::replication::block::BlockHeader {
        parent_hash: parent.hash(),
        height: Height(1),
        view: View(6),
        proposer: signer.node_id(),
        state_commitment: [0; 32],
        commands_commitment: Block::commands_commitment(&[]),
        validator_history_commitment: [0; 32],
        committed_height: Height::ZERO,
        committed_state_root: [0; 32],
    };
    let block = Block {
        header,
        commands: vec![],
    };
    let proposal = Proposal { block, justify };
    let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 3);
    assert!(matches!(
        dispatches[1],
        Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(View(6)))
    ));
    assert!(
        matches!(
            dispatches[2],
            Dispatch::Pacemaker(pacemaker::Event::OnQc(View(5)))
        ),
        "expected OnQc(justify.view = 5), got {:?}",
        dispatches[2]
    );
}

#[test]
fn ingress_proposal_unknown_signer_rejected() {
    let signer = fresh_signer();
    let other = fresh_signer();
    let vs = make_vs_with_signers(&[&other]); // signer not in VS

    let proposal = Proposal {
        block: genesis(),
        justify: sample_qc(),
    };
    let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
    assert!(matches!(err, IngressError::UnknownSigner(_)));
}

#[test]
fn ingress_proposal_bad_signature_rejected() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let proposal = Proposal {
        block: genesis(),
        justify: sample_qc(),
    };
    let mut signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    signed.sig[0] ^= 0xFF; // corrupt the signature

    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
    assert!(matches!(err, IngressError::InvalidSignature(_)));
}

// ── ingress: Vote ────────────────────────────────────────────────────────

#[test]
fn ingress_vote_happy_path() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let vote = Vote {
        view: View(3),
        block_hash: [0xAB; 32],
    };
    let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

// ── ingress: NewView ─────────────────────────────────────────────────────

#[test]
fn ingress_new_view_emits_pacemaker_on_qc() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let mut high_qc = QuorumCertificate::new(7, [0xCD; 32], 1);
    high_qc.add_signature(0, [0x11; 64]);
    let nv = NewView { high_qc };
    let signed = Signed::sign(nv, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::NewView(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 2);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::NewViewReceived(_))
    ));
    assert!(matches!(
        dispatches[1],
        Dispatch::Pacemaker(pacemaker::Event::OnQc(View(7)))
    ));
}

// ── ingress: TimeoutVote ────────────────────────────────────────────────

#[test]
fn ingress_timeout_vote_happy_path() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let tv = TimeoutVote {
        view: View(7),
        high_qc: Some(sample_qc()),
    };
    let signed = Signed::sign(tv, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        dispatches[0],
        Dispatch::TimeoutVote {
            high_qc_trusted: true,
            ..
        }
    ));
}

#[test]
fn ingress_timeout_vote_unknown_signer_rejected() {
    let signer = fresh_signer();
    let other = fresh_signer();
    let vs = make_vs_with_signers(&[&other]);

    let tv = TimeoutVote {
        view: View(3),
        high_qc: None,
    };
    let signed = Signed::sign(tv, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
    assert!(matches!(err, IngressError::UnknownSigner(_)));
}

#[test]
fn ingress_timeout_vote_bad_signature_rejected() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let tv = TimeoutVote {
        view: View(1),
        high_qc: None,
    };
    let mut signed = Signed::sign(tv, &signer, &ChainId::TEST).unwrap();
    signed.sig[0] ^= 0xFF;
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
    assert!(matches!(err, IngressError::InvalidSignature(_)));
}

// ── ingress: BlockRequest / BlockResponse ────────────────────────────────

#[test]
fn ingress_block_request_no_signature_needed() {
    let from = [0x01u8; 32];
    let hash = [0xBBu8; 32];
    let vs = ValidatorSet::new(vec![]); // empty VS — block requests bypass auth
    let wire = WireMessage::BlockRequest(hash);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        &dispatches[0],
        Dispatch::ServeBlock { hash: h, to } if h == &[0xBBu8; 32] && to == &from,
    ));
}

#[test]
fn ingress_block_response_happy_path() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let from = signer.node_id();
    let block = genesis();
    let requested_hash = block.hash();
    let payload = crate::wire::BlockResponsePayload {
        requested_hash,
        block: Some(block),
    };
    let signed = Signed::sign(payload, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::BlockResponse(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        &dispatches[0],
        Dispatch::ReceiveBlock {
            requested_hash: rh,
            block: Some(_),
            from: f,
        } if rh == &requested_hash && f == &from,
    ));
}

#[test]
fn ingress_block_response_unknown_signer_rejected() {
    let signer = fresh_signer();
    let other = fresh_signer();
    let vs = make_vs_with_signers(&[&other]); // signer not in VS
    let payload = crate::wire::BlockResponsePayload {
        requested_hash: [0xAB; 32],
        block: None,
    };
    let signed = Signed::sign(payload, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::BlockResponse(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
    assert!(matches!(err, IngressError::UnknownSigner(_)));
}

#[test]
fn ingress_block_response_bad_signature_rejected() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let payload = crate::wire::BlockResponsePayload {
        requested_hash: [0xAB; 32],
        block: None,
    };
    let mut signed = Signed::sign(payload, &signer, &ChainId::TEST).unwrap();
    signed.sig[0] ^= 0xFF;
    let wire = WireMessage::BlockResponse(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
    assert!(matches!(err, IngressError::InvalidSignature(_)));
}

#[test]
fn ingress_garbage_bytes_returns_decode_error() {
    let from = [0x01u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let err = ingress_with_genesis_set(from, &[0xFFu8; 16], &vs).unwrap_err();
    assert!(matches!(err, IngressError::Decode(_)));
}

// ── egress_safety ────────────────────────────────────────────────────────

#[test]
fn egress_broadcast_encodes_signed_proposal() {
    let signer = fresh_signer();
    let qc = sample_qc();

    let proposal = Proposal {
        block: genesis(),
        justify: qc.clone(),
    };
    let action =
        crate::hotstuff::step::Action::Broadcast(crate::hotstuff::ConsensusMsg::Proposal(proposal));

    let out = egress_safety(&action, &signer, None, &ChainId::TEST)
        .unwrap()
        .unwrap();
    let Outbound::Broadcast(payload) = out else {
        panic!("expected Broadcast");
    };
    let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
    assert!(matches!(decoded, WireMessage::Proposal(_)));
}

#[test]
fn egress_persist_returns_none() {
    let signer = fresh_signer();
    use crate::hotstuff::step::StateUpdate;
    let action = crate::hotstuff::step::Action::Persist(StateUpdate::VotedInView { view: View(1) });
    let out = egress_safety(&action, &signer, None, &ChainId::TEST).unwrap();
    assert!(out.is_none());
}

#[test]
fn egress_commit_returns_none() {
    let signer = fresh_signer();
    let action = crate::hotstuff::step::Action::Commit(genesis());
    let out = egress_safety(&action, &signer, None, &ChainId::TEST).unwrap();
    assert!(out.is_none());
}

#[test]
fn egress_request_block_yields_send_to() {
    let signer = fresh_signer();
    let hash = [0xAAu8; 32];
    let peer: NodeId = [0x33u8; 32];
    let action = crate::hotstuff::step::Action::RequestBlock {
        hash,
        peer,
        expected_height: Height(41),
        reason: crate::hotstuff::step::BlockSyncReason::UnknownParentOnProposal,
    };
    let out = egress_safety(&action, &signer, None, &ChainId::TEST)
        .unwrap()
        .unwrap();
    let Outbound::SendTo { to, payload } = out else {
        panic!("expected SendTo");
    };
    assert_eq!(to, peer);
    let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
    assert!(matches!(decoded, WireMessage::BlockRequest(_)));
}

// ── egress round-trip: signed payloads are verifiable ────────────────────

#[test]
fn egress_broadcast_proposal_is_verifiable() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let proposal = Proposal {
        block: genesis(),
        justify: sample_qc(),
    };
    let action = crate::hotstuff::step::Action::Broadcast(crate::hotstuff::ConsensusMsg::Proposal(
        proposal.clone(),
    ));
    let Outbound::Broadcast(payload) = egress_safety(&action, &signer, None, &ChainId::TEST)
        .unwrap()
        .unwrap()
    else {
        panic!("expected Broadcast");
    };

    // Run through ingress — should succeed.
    let dispatches = ingress_with_genesis_set(signer.node_id(), &payload, &vs).unwrap();
    assert_eq!(dispatches.len(), 3);
    match &dispatches[0] {
        Dispatch::Safety(SafetyEvent::ProposalReceived(s)) => {
            assert_eq!(s.inner().payload.block, proposal.block);
        }
        other => panic!("unexpected first dispatch: {other:?}"),
    }
}

// ── Snapshot wire protocol (#228) ─────────────────────────────────────

fn sample_quorum_qc(vs_len: usize, block_hash: [u8; 32]) -> QuorumCertificate {
    let mut qc = QuorumCertificate::new(0, block_hash, vs_len);
    for i in 0..crate::hotstuff::qc::quorum_size(vs_len) {
        qc.add_signature(i, [0u8; 64]);
    }
    qc
}

fn sample_manifest_for_dispatch() -> SnapshotManifest {
    use crate::replication::block::{Block, BlockHeader};
    let vs = ValidatorSet::new(vec![
        crate::validator_set::ValidatorId::from_genesis_pubkey([1u8; 32]),
        crate::validator_set::ValidatorId::from_genesis_pubkey([2u8; 32]),
        crate::validator_set::ValidatorId::from_genesis_pubkey([3u8; 32]),
        crate::validator_set::ValidatorId::from_genesis_pubkey([4u8; 32]),
    ]);
    let parent_hash = Block::genesis([0u8; 32], [0; 32]).hash();
    let commands: Vec<bytes::Bytes> = Vec::new();
    let block = Block {
        header: BlockHeader {
            parent_hash,
            height: Height(42),
            view: View(7),
            proposer: [0u8; 32],
            state_commitment: [0xCD; 32],
            commands_commitment: Block::commands_commitment(&commands),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        },
        commands,
    };
    let qc = sample_quorum_qc(vs.len(), block.hash());
    let payload = b"chunky payload".repeat(8);
    let chunks = crate::replication::snapshot::chunk_snapshot(&payload, 32);
    let chunk_hashes: Vec<[u8; 32]> = chunks.iter().map(|(_, h)| *h).collect();
    SnapshotManifest::build_for_test_genesis_histories(
        block,
        &vs,
        32,
        chunk_hashes,
        qc,
        1_700_000_000,
    )
}

#[test]
fn ingress_snapshot_manifest_request_no_signature_needed() {
    let from = [0x01u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let wire = WireMessage::SnapshotManifestRequest { height: Some(1234) };
    let bytes = postcard::to_stdvec(&wire).unwrap();
    let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        &dispatches[0],
        Dispatch::ServeSnapshotManifest { height: Some(1234), to } if to == &from,
    ));
}

#[test]
fn ingress_snapshot_manifest_request_latest_round_trips() {
    let from = [0x02u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let wire = WireMessage::SnapshotManifestRequest { height: None };
    let bytes = postcard::to_stdvec(&wire).unwrap();
    let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
    assert!(matches!(
        &dispatches[0],
        Dispatch::ServeSnapshotManifest { height: None, to } if to == &from,
    ));
}

#[test]
fn ingress_snapshot_manifest_response_carries_manifest() {
    let from = [0x03u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let manifest = sample_manifest_for_dispatch();
    let wire = WireMessage::SnapshotManifestResponse(Some(manifest.clone()));
    let bytes = postcard::to_stdvec(&wire).unwrap();
    let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    match &dispatches[0] {
        Dispatch::ReceiveSnapshotManifest {
            manifest: Some(m),
            from: f,
        } => {
            assert_eq!(m, &manifest);
            assert_eq!(f, &from);
        }
        other => panic!("unexpected dispatch: {other:?}"),
    }
}

#[test]
fn ingress_snapshot_chunk_request_carries_height_and_index() {
    let from = [0x04u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let wire = WireMessage::SnapshotChunkRequest {
        height: 555,
        chunk_idx: 7,
    };
    let bytes = postcard::to_stdvec(&wire).unwrap();
    let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
    assert!(matches!(
        &dispatches[0],
        Dispatch::ServeSnapshotChunk { height: Height(555), chunk_idx: 7, to } if to == &from,
    ));
}

#[test]
fn ingress_snapshot_chunk_response_carries_payload() {
    let from = [0x05u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let payload = bytes::Bytes::from_static(b"hello chunk");
    let wire = WireMessage::SnapshotChunkResponse {
        height: 99,
        chunk_idx: 3,
        payload: Some(payload.clone()),
    };
    let bytes_vec = postcard::to_stdvec(&wire).unwrap();
    let dispatches = ingress_with_genesis_set(from, &bytes_vec, &vs).unwrap();
    match &dispatches[0] {
        Dispatch::ReceiveSnapshotChunk {
            height: Height(99),
            chunk_idx: 3,
            payload: Some(p),
            from: f,
        } => {
            assert_eq!(p.as_ref(), payload.as_ref());
            assert_eq!(f, &from);
        }
        other => panic!("unexpected dispatch: {other:?}"),
    }
}

#[test]
fn snapshot_wire_round_trip_postcard_stable() {
    // Encode/decode each new wire message; bytes round-trip and
    // first-byte tag matches the layout pinned by
    // `wire_tag_layout_locked` in p2p::limits.
    let manifest = sample_manifest_for_dispatch();
    let cases: Vec<WireMessage> = vec![
        WireMessage::SnapshotManifestRequest { height: None },
        WireMessage::SnapshotManifestRequest { height: Some(42) },
        WireMessage::SnapshotManifestResponse(None),
        WireMessage::SnapshotManifestResponse(Some(manifest.clone())),
        WireMessage::SnapshotChunkRequest {
            height: 1,
            chunk_idx: 0,
        },
        WireMessage::SnapshotChunkResponse {
            height: 1,
            chunk_idx: 0,
            payload: None,
        },
        WireMessage::SnapshotChunkResponse {
            height: 1,
            chunk_idx: 0,
            payload: Some(bytes::Bytes::from_static(b"abc")),
        },
    ];
    for msg in cases {
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }
}

#[test]
fn egress_snapshot_manifest_response_round_trips_via_ingress() {
    let from = [0x66u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let manifest = sample_manifest_for_dispatch();
    let out = egress_snapshot_manifest_response(Some(manifest.clone()), from);
    let Outbound::SendTo { to, payload } = out else {
        panic!("expected SendTo");
    };
    assert_eq!(to, from);
    let dispatches = ingress_with_genesis_set(from, &payload, &vs).unwrap();
    match &dispatches[0] {
        Dispatch::ReceiveSnapshotManifest {
            manifest: Some(m), ..
        } => {
            assert_eq!(m, &manifest);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn snapshot_chunk_response_fits_under_max_frame_bytes_at_1mib() {
    // Frame-size budget: a 1 MiB chunk plus the
    // `SnapshotChunkResponse` envelope must comfortably fit
    // inside the consensus protocol's `MAX_FRAME_BYTES` cap so
    // production-default chunks never get truncated mid-flight.
    // Use a 1 MiB payload whose entropy defeats any compression
    // assumption: postcard does no compression, so we're really
    // just checking framing overhead.
    let payload = bytes::Bytes::from(vec![0xA5u8; 1024 * 1024]);
    let wire = WireMessage::SnapshotChunkResponse {
        height: 0xDEAD_BEEF,
        chunk_idx: u32::MAX,
        payload: Some(payload),
    };
    let encoded = postcard::to_stdvec(&wire).unwrap();
    let max = crate::wire::MAX_FRAME_BYTES;
    assert!(
        encoded.len() < max,
        "encoded SnapshotChunkResponse ({} bytes) must fit under MAX_FRAME_BYTES ({}) at 1 MiB chunks",
        encoded.len(),
        max,
    );
    // The envelope adds at most a few bytes (tag + varints +
    // length prefix). Lock that the overhead is trivially small,
    // so a future change that bloats the envelope without
    // reducing the chunk size hits this test before it hits the
    // wire frame cap.
    let overhead = encoded.len() - 1024 * 1024;
    assert!(
        overhead < 64,
        "envelope overhead grew unexpectedly: {overhead} bytes",
    );
}

#[test]
fn egress_block_request_ingress_roundtrip() {
    let from = [0x01u8; 32];
    let vs = ValidatorSet::new(vec![]);
    let hash = [0xCCu8; 32];
    let peer: NodeId = [0x22u8; 32];

    let out = egress_block_request(hash, peer);
    let Outbound::SendTo { to, payload } = out else {
        panic!("expected SendTo");
    };
    assert_eq!(to, peer);

    let dispatches = ingress_with_genesis_set(from, &payload, &vs).unwrap();
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        &dispatches[0],
        Dispatch::ServeBlock { hash: h, to: t } if h == &[0xCCu8; 32] && t == &from,
    ));
}

// ── ingress: ValidatorSetHistory boundary semantics (#249) ───────────────

/// A vote at view `v_eff`, signed by a validator that is **only** in
/// the new (post-boundary) set, must verify against the
/// post-boundary set — not against the genesis set.
#[test]
fn vote_at_v_eff_verifies_against_post_boundary_set() {
    let old_signer = fresh_signer();
    let new_signer = fresh_signer();
    let old_set = make_vs_with_signers(&[&old_signer]);
    let new_set = make_vs_with_signers(&[&old_signer, &new_signer]);

    let v_eff: View = View(5);
    let mut history = ValidatorSetHistory::from_genesis(old_set);
    history.insert_boundary(v_eff, new_set).unwrap();

    let vote = Vote {
        view: v_eff,
        block_hash: [0xAB; 32],
    };
    let signed = Signed::sign(vote, &new_signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    // Succeeds against the history that contains the boundary.
    let key_history = key_history_for(&history);
    let dispatches = ingress(
        new_signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

/// The same vote rejected when the history is missing the boundary —
/// the post-boundary signer is not yet a member at any view.
#[test]
fn vote_at_v_eff_rejected_without_boundary() {
    let old_signer = fresh_signer();
    let new_signer = fresh_signer();
    let old_set = make_vs_with_signers(&[&old_signer]);

    let history_without_boundary = ValidatorSetHistory::from_genesis(old_set);
    let key_history = key_history_for(&history_without_boundary);

    let vote = Vote {
        view: View(5),
        block_hash: [0xAB; 32],
    };
    let signed = Signed::sign(vote, &new_signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress(
        new_signer.node_id(),
        &bytes,
        &history_without_boundary,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap_err();
    assert!(
        matches!(err, IngressError::UnknownSigner(_)),
        "expected UnknownSigner, got {err:?}"
    );
}

/// A vote at view `v_eff - 1` must still verify against the **old**
/// set even after the new boundary exists — historical messages do
/// not get retroactively re-validated against the newer committee.
#[test]
fn vote_before_boundary_verifies_against_pre_boundary_set() {
    let old_signer = fresh_signer();
    let new_signer = fresh_signer();
    let old_set = make_vs_with_signers(&[&old_signer]);
    // Critically, `new_set` does *not* contain `old_signer`.
    let new_set = make_vs_with_signers(&[&new_signer]);

    let v_eff: View = View(10);
    let mut history = ValidatorSetHistory::from_genesis(old_set);
    history.insert_boundary(v_eff, new_set).unwrap();
    let key_history = key_history_for(&history);

    let vote = Vote {
        view: v_eff - 1,
        block_hash: [0xCD; 32],
    };
    let signed = Signed::sign(vote, &old_signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        old_signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

/// A proposal at the boundary view: the proposer is a post-boundary
/// member only. Verification picks the right set.
#[test]
fn proposal_at_v_eff_verifies_against_post_boundary_set() {
    let old_signer = fresh_signer();
    let new_signer = fresh_signer();
    let old_set = make_vs_with_signers(&[&old_signer]);
    let new_set = make_vs_with_signers(&[&old_signer, &new_signer]);

    let v_eff: View = View(7);
    let mut history = ValidatorSetHistory::from_genesis(old_set);
    history.insert_boundary(v_eff, new_set).unwrap();
    let key_history = key_history_for(&history);

    // Build a block at the boundary view; the proposer is the
    // post-boundary-only validator.
    let parent = genesis();
    let header = crate::replication::block::BlockHeader {
        parent_hash: parent.hash(),
        height: parent.header.height + 1,
        view: v_eff,
        proposer: new_signer.node_id(),
        state_commitment: [0u8; 32],
        commands_commitment: Block::commands_commitment(&[]),
        validator_history_commitment: [0; 32],
        committed_height: Height::ZERO,
        committed_state_root: [0; 32],
    };
    let block = Block {
        header,
        commands: vec![],
    };

    let proposal = Proposal {
        block,
        justify: sample_qc(),
    };
    let signed = Signed::sign(proposal, &new_signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        new_signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::ProposalReceived(_))
    ));
}

// ── ingress: NewView high_qc cross-boundary semantics (#250) ─────────────

/// A NewView straddling a reconfig boundary: high_qc.view = v_eff - 1
/// (still under the old set), envelope signer is in the old set,
/// high_qc bitmap shape matches the old set. Must be accepted —
/// historical messages do not get retroactively re-validated against
/// the newer committee.
#[test]
fn new_view_with_pre_boundary_high_qc_under_old_set_accepted() {
    let old_a = fresh_signer();
    let old_b = fresh_signer();
    let new_only = fresh_signer();
    let old_set = make_vs_with_signers(&[&old_a, &old_b]);
    let new_set = make_vs_with_signers(&[&old_a, &old_b, &new_only]);

    let v_eff: View = View(5);
    let mut history = ValidatorSetHistory::from_genesis(old_set.clone());
    history.insert_boundary(v_eff, new_set).unwrap();
    let key_history = key_history_for(&history);

    // high_qc minted at view v_eff - 1 against the *old* set.
    let mut high_qc = QuorumCertificate::new(v_eff - 1, [0xAB; 32], old_set.len());
    for i in 0..old_set.len() {
        high_qc.add_signature(i, [0xCC; 64]);
    }
    assert!(high_qc.is_well_formed(&old_set));

    let nv = NewView { high_qc };
    let signed = Signed::sign(nv, &old_a, &ChainId::TEST).unwrap();
    let wire = WireMessage::NewView(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        old_a.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert_eq!(dispatches.len(), 2);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::NewViewReceived(_))
    ));
    assert!(matches!(
        dispatches[1],
        Dispatch::Pacemaker(pacemaker::Event::OnQc(v)) if v == v_eff - 1
    ));
}

/// A NewView claiming a pre-boundary high_qc.view but whose high_qc
/// bitmap is sized against the *new* (post-boundary) set: rejected
/// with `MalformedHighQc`. The new set is larger here, so the bitmap
/// length doesn't match `set_at(high_qc.view) = old_set` and
/// well-formedness fails.
#[test]
fn new_view_with_high_qc_minted_against_new_set_rejected_at_pre_boundary_view() {
    let old_a = fresh_signer();
    let old_b = fresh_signer();
    let new_only = fresh_signer();
    let old_set = make_vs_with_signers(&[&old_a, &old_b]);
    let new_set = make_vs_with_signers(&[&old_a, &old_b, &new_only]);

    let v_eff: View = View(5);
    let mut history = ValidatorSetHistory::from_genesis(old_set.clone());
    history.insert_boundary(v_eff, new_set.clone()).unwrap();
    let key_history = key_history_for(&history);

    // high_qc minted against the *new* (larger) set, but claimed at
    // a pre-boundary view. The bitmap length will be `new_set.len()`,
    // which doesn't match `set_at(v_eff - 1) = old_set`.
    let mut high_qc = QuorumCertificate::new(v_eff - 1, [0xAB; 32], new_set.len());
    for i in 0..new_set.len() {
        high_qc.add_signature(i, [0xDD; 64]);
    }
    assert!(high_qc.is_well_formed(&new_set));
    assert!(!high_qc.is_well_formed(&old_set));

    // Envelope signer must verify first; pick someone in the old set
    // so we exercise the high_qc check rather than the signer check.
    let nv = NewView { high_qc };
    let signed = Signed::sign(nv, &old_a, &ChainId::TEST).unwrap();
    let wire = WireMessage::NewView(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress(
        old_a.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap_err();
    assert!(
        matches!(err, IngressError::MalformedHighQc { view } if view == v_eff - 1),
        "expected MalformedHighQc at v_eff - 1, got {err:?}",
    );
}

/// Sanity: the existing single-set `ingress_new_view_emits_pacemaker_on_qc`
/// test exercises the genesis-only path. Mirror that here with an
/// explicit history of length 1, so a regression in the well-formedness
/// check catches both flavors.
#[test]
fn new_view_under_genesis_only_history_round_trips() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_for(&history);

    let mut high_qc = QuorumCertificate::new(7, [0xCD; 32], vs.len());
    high_qc.add_signature(0, [0x11; 64]);
    let nv = NewView { high_qc };
    let signed = Signed::sign(nv, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::NewView(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert_eq!(dispatches.len(), 2);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::NewViewReceived(_))
    ));
    assert!(matches!(
        dispatches[1],
        Dispatch::Pacemaker(pacemaker::Event::OnQc(View(7)))
    ));
}

// ── ingress: ValidatorKeyHistory rotation semantics (#259 part 2) ────────
//
// Each test below builds a single-validator setup so the failure
// mode is unambiguous — every rejection is about which key the
// verifier accepts at which view, not about whether the validator
// happens to be in the set. Multi-validator interactions are
// covered by the sim-level tests in #260 / #261.

use crate::validator_rotation::ValidatorKeyRotation;

/// Helper: build a key history that mirrors `vs` and then applies a
/// rotation for `validator` to `new_pubkey` taking effect at
/// `v_eff`. The rotation is committed at `commit_view = v_eff - 2`
/// (the minimum allowed by `V_EFF_MIN_DELAY`).
fn key_history_with_rotation(
    vs: &ValidatorSet,
    validator: NodeId,
    new_pubkey: NodeId,
    v_eff: impl Into<View>,
) -> ValidatorKeyHistory {
    let v_eff = v_eff.into();
    let mut kh = key_history_from_set(vs);
    // Reverse-index lookup must succeed for the test setup —
    // always rotate from a validator that's actually in `vs`.
    kh.apply_rotation(
        &ValidatorKeyRotation {
            validator,
            new_pubkey,
            v_eff,
            new_bls_pubkey: None,
            new_bls_pop: None,
        },
        v_eff - View(2),
    )
    .expect("test rotation must apply cleanly");
    kh
}

/// After a rotation takes effect at `v_eff`, a vote at view `v_eff`
/// signed by the *new* key is accepted: the verifier resolves the
/// new pubkey to the validator's stable id and confirms it's the
/// active key for that view.
///
/// Also pins the #394 fix: the resolved stable
/// [`ValidatorId`](crate::validator_set::ValidatorId)
/// is stamped on the [`Verified`] envelope, with bytes equal to
/// the validator's *original* (genesis) pubkey — not the wire
/// signer's freshly-rotated pubkey. The safety core consumes the
/// stamped id directly, so the bitmap-index lookup hits the
/// validator's bitmap slot regardless of how many rotations have
/// happened since.
#[test]
fn vote_after_rotation_signed_with_new_key_accepted() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    let vote = Vote {
        view: View(100),
        block_hash: [0xAB; 32],
    };
    let signed = Signed::sign(vote, &new, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        new.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    let SafetyEvent::VoteReceived(variant) = (match &dispatches[0] {
        Dispatch::Safety(ev) => ev.clone(),
        other => panic!("expected Dispatch::Safety(VoteReceived), got {other:?}"),
    }) else {
        panic!("expected SafetyEvent::VoteReceived, got something else");
    };

    // Wire signer is the rotated `new` pubkey; stamped id is the
    // pre-rotation stable id (genesis pubkey of `old`). The
    // pre-#394 derivation `from_genesis_pubkey(signed.signer)`
    // would have stamped `new.node_id()` — verifying that the
    // stamped bytes are NOT the wire bytes is the load-bearing
    // assertion this test contributes over the existing
    // accept-or-reject coverage.
    let stamped = variant.verified().signer_validator_id();
    let expected = crate::validator_set::ValidatorId::from_genesis_pubkey(old.node_id());
    assert_eq!(
        stamped, expected,
        "Verified envelope must stamp the resolved stable ValidatorId (#394)",
    );
    assert_ne!(
        stamped.into_node_id(),
        new.node_id(),
        "stamped id must NOT be the rotated wire pubkey — pre-#394 derivation",
    );
    assert!(
        history
            .set_at(100)
            .for_view(100)
            .index_of(&stamped)
            .is_some(),
        "stamped id must index into the validator set so the safety core's \
         bitmap lookup succeeds",
    );
}

/// Spanning vote: a late vote for a *pre-rotation* view, signed by
/// the old key. Must still verify even though the validator's
/// current key has changed — old QCs stay verifiable forever, and
/// in-flight votes for older views can't be retroactively invalidated
/// by a rotation that happened later.
#[test]
fn spanning_vote_pre_rotation_view_signed_with_old_key_accepted() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    // Vote for a view *before* the rotation's v_eff, signed by the
    // pre-rotation key.
    let vote = Vote {
        view: View(50),
        block_hash: [0xCD; 32],
    };
    let signed = Signed::sign(vote, &old, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        old.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

/// A vote at view `>= v_eff` signed by the *old* key is rejected:
/// the validator has rotated and the old key is no longer the
/// active signing key at that view. Without this check, a
/// compromised old key could continue to vote indefinitely.
#[test]
fn vote_after_rotation_signed_with_stale_old_key_rejected() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    // View at/after v_eff, but signed under the now-stale old key.
    let vote = Vote {
        view: View(100),
        block_hash: [0xEF; 32],
    };
    let signed = Signed::sign(vote, &old, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress(
        old.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap_err();
    assert!(
        matches!(err, IngressError::UnknownSigner(_)),
        "expected UnknownSigner for stale-key vote, got {err:?}"
    );
}

/// A vote at view `< v_eff` signed by the *new* key is rejected:
/// the rotation hasn't taken effect at that view, so the new key
/// isn't yet the validator's authoritative signer. This prevents a
/// proposed-but-not-yet-effective key from being used early.
#[test]
fn vote_before_rotation_signed_with_future_new_key_rejected() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    // View before v_eff, signed by the future key.
    let vote = Vote {
        view: View(50),
        block_hash: [0x12; 32],
    };
    let signed = Signed::sign(vote, &new, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress(
        new.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap_err();
    assert!(
        matches!(err, IngressError::UnknownSigner(_)),
        "expected UnknownSigner for future-key vote, got {err:?}"
    );
}

/// A vote signed by an entirely unrelated pubkey — never associated
/// with any validator in the key history — is rejected with
/// `UnknownSigner`. This is the regression test that the
/// reverse-index lookup actually guards the gate.
#[test]
fn vote_signed_by_unrelated_key_rejected() {
    let old = fresh_signer();
    let attacker = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);

    let vote = Vote {
        view: View(5),
        block_hash: [0x77; 32],
    };
    let signed = Signed::sign(vote, &attacker, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress(
        attacker.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap_err();
    assert!(matches!(err, IngressError::UnknownSigner(_)));
}

/// Every ingress arm goes through the same `verify_signer_at`
/// helper, but the test above only exercises Vote. Mirror it for
/// Proposal, NewView, and TimeoutVote so a regression in any one
/// arm is caught — the post-rotation key is accepted in all four.
#[test]
fn proposal_after_rotation_signed_with_new_key_accepted() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    let parent = genesis();
    let header = crate::replication::block::BlockHeader {
        parent_hash: parent.hash(),
        height: parent.header.height + 1,
        view: View(100),
        proposer: new.node_id(),
        state_commitment: [0u8; 32],
        commands_commitment: Block::commands_commitment(&[]),
        validator_history_commitment: [0; 32],
        committed_height: Height::ZERO,
        committed_state_root: [0; 32],
    };
    let proposal = Proposal {
        block: Block {
            header,
            commands: vec![],
        },
        justify: sample_qc(),
    };
    let signed = Signed::sign(proposal, &new, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        new.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::ProposalReceived(_))
    ));
}

#[test]
fn timeout_vote_after_rotation_signed_with_new_key_accepted() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    let tv = TimeoutVote {
        view: View(100),
        high_qc: None,
    };
    let signed = Signed::sign(tv, &new, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        new.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(dispatches[0], Dispatch::TimeoutVote { .. }));
}

/// NewView at view >= v_eff signed by the new key: signer check
/// against `set_at(high_qc.view)` succeeds via the reverse index.
/// Use a high_qc.view at the rotation point to keep the test focused
/// on the key-history check (not the high_qc bitmap, which uses
/// the old set size for both pre- and post-rotation since the
/// validator set itself didn't change).
#[test]
fn new_view_after_rotation_signed_with_new_key_accepted() {
    let old = fresh_signer();
    let new = fresh_signer();
    let vs = make_vs_with_signers(&[&old]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

    let mut high_qc = QuorumCertificate::new(100, [0xCD; 32], vs.len());
    high_qc.add_signature(0, [0x11; 64]);
    let nv = NewView { high_qc };
    let signed = Signed::sign(nv, &new, &ChainId::TEST).unwrap();
    let wire = WireMessage::NewView(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        new.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert_eq!(dispatches.len(), 2);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::NewViewReceived(_))
    ));
}

/// A validator that was removed via reconfig at `v_eff` cannot
/// vote at views >= v_eff even if the verifier still has their
/// pubkey in the key history (the history retains every validator
/// forever for spanning-vote support). The set-membership check
/// rejects them.
#[test]
fn vote_from_removed_validator_after_v_eff_rejected() {
    let kept = fresh_signer();
    let removed = fresh_signer();
    let old_set = make_vs_with_signers(&[&kept, &removed]);
    let new_set = make_vs_with_signers(&[&kept]); // removed gone

    let v_eff: View = View(5);
    let mut history = ValidatorSetHistory::from_genesis(old_set);
    history.insert_boundary(v_eff, new_set).unwrap();
    let key_history = key_history_for(&history);

    // Vote at view >= v_eff signed by the removed validator.
    let vote = Vote {
        view: v_eff,
        block_hash: [0xAB; 32],
    };
    let signed = Signed::sign(vote, &removed, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let err = ingress(
        removed.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap_err();
    assert!(matches!(err, IngressError::UnknownSigner(_)));

    // Spanning vote at view < v_eff is still accepted — the
    // validator was authoritative back then.
    let vote = Vote {
        view: v_eff - 1,
        block_hash: [0xCD; 32],
    };
    let signed = Signed::sign(vote, &removed, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress(
        removed.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

// ── ingress: QC aggregate verification (#332) ────────────────────────────

/// Build a 4-validator setup, hand-fold real Vote signatures into a
/// QC over `(view, block_hash)`, and return the bundle the
/// verification tests below use.
fn build_real_ed25519_qc(
    view: View,
    block_hash: BlockHash,
) -> (Vec<NodeSigner>, ValidatorSet, QuorumCertificate) {
    let signers: Vec<NodeSigner> = (0..4).map(|_| fresh_signer()).collect();
    let vs = ValidatorSet::new(
        signers
            .iter()
            .map(|s| crate::validator_set::ValidatorId::from_genesis_pubkey(s.node_id()))
            .collect(),
    );

    let vote = Vote { view, block_hash };
    let mut qc = QuorumCertificate::new(view, block_hash, vs.len());
    // Fold the first 3 validators' signatures (n=4 → quorum=3) in
    // sorted-NodeId order to match the bitmap layout the verifier
    // assumes.
    for stable_id in vs.iter().take(quorum_size_for_n(vs.len())) {
        let signer = signers
            .iter()
            .find(|s| s.node_id() == stable_id.into_node_id())
            .unwrap();
        let signed = Signed::sign(vote.clone(), signer, &ChainId::TEST).unwrap();
        let idx = vs.index_of(stable_id).unwrap();
        qc.add_signature(idx, signed.sig);
    }
    (signers, vs, qc)
}

fn quorum_size_for_n(n: usize) -> usize {
    // Mirror crate::hotstuff::qc::quorum_size: ceil(2n/3).
    n.div_ceil(3) * 2 - if n % 3 == 0 { 1 } else { 0 }
}

#[test]
fn ingress_with_verify_accepts_real_ed25519_qc_inside_proposal() {
    let view: View = View(5);
    let block_hash = [0x55; 32];
    let (signers, vs, qc) = build_real_ed25519_qc(view, block_hash);
    let leader = &signers[0];

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);

    // Build a proposal at the next view that justifies on this QC.
    // #325 PR C: stamp the post-block validator_history_commitment
    // so the proposal-receive verifier accepts it. The block has
    // no reconfig/rotation commands, so post-block == pre-block ==
    // the v1 hash over the genesis-time histories.
    let mut block = Block {
        header: crate::replication::block::BlockHeader {
            parent_hash: block_hash,
            height: Height(1),
            view: view + 1,
            proposer: leader.node_id(),
            state_commitment: [0; 32],
            commands_commitment: [0; 32],
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        },
        commands: vec![],
    };
    block.header.validator_history_commitment =
        crate::history_commitment::compute_post_block_commitment(
            &block,
            &history,
            &key_history,
            None,
            &ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            crate::reconfig::MIN_V_EFF_DELAY,
        );
    let proposal = Proposal { block, justify: qc };
    let signed = Signed::sign(proposal, leader, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let dispatches = ingress_with_qc_verification(
        leader.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("real Ed25519 QC must verify under the genesis pubkeys");
    assert_eq!(dispatches.len(), 3);
}

/// PR C of #325: a Byzantine leader stamps a `Proposal` with a
/// `validator_history_commitment` that doesn't match the
/// post-block hash any honest follower would compute. The
/// proposal-receive verifier must reject before any safety-core
/// event fires, with a `InvalidValidatorHistoryCommitment`
/// error. Bisect-confirmed by removing the
/// `verify_proposal_history_commitment_if_requested` call from
/// the Proposal ingress arm — the test then sees the proposal
/// dispatched and `expect_err` panics.
#[test]
fn ingress_with_verify_rejects_forged_validator_history_commitment_inside_proposal() {
    let view: View = View(5);
    let block_hash = [0x55; 32];
    let (signers, vs, qc) = build_real_ed25519_qc(view, block_hash);
    let leader = &signers[0];

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);

    // The block's validator_history_commitment is filled with a
    // distinctive sentinel that no honest replica would ever
    // compute over genesis-time histories with no commands. The
    // QC justify is real, so the QC verifier passes — the only
    // remaining gate is the proposal-receive history-commitment
    // verifier (#325 PR C).
    let forged_commitment: [u8; 32] = [0xDE; 32];
    let block = Block {
        header: crate::replication::block::BlockHeader {
            parent_hash: block_hash,
            height: Height(1),
            view: view + 1,
            proposer: leader.node_id(),
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
            validator_history_commitment: forged_commitment,
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        },
        commands: vec![],
    };
    let proposal = Proposal { block, justify: qc };
    let signed = Signed::sign(proposal, leader, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let err = ingress_with_qc_verification(
        leader.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("forged validator_history_commitment must be rejected at ingress");
    assert!(
        matches!(
            err,
            IngressError::InvalidValidatorHistoryCommitment {
                height: Height(1),
                view: View(6),
                claimed,
                ..
            } if claimed == forged_commitment
        ),
        "expected InvalidValidatorHistoryCommitment with the forged sentinel, got {err:?}",
    );
}

#[test]
fn ingress_with_verify_rejects_tampered_ed25519_qc_inside_proposal() {
    let view: View = View(5);
    let block_hash = [0x55; 32];
    let (signers, vs, mut qc) = build_real_ed25519_qc(view, block_hash);
    let leader = &signers[0];

    // Tamper the first signature inside the QC.
    if let crate::hotstuff::qc::QcSignatures::Ed25519Collected(sigs) = &mut qc.signatures {
        sigs[0][0] ^= 0xFF;
    }

    let block = Block {
        header: crate::replication::block::BlockHeader {
            parent_hash: block_hash,
            height: Height(1),
            view: view + 1,
            proposer: leader.node_id(),
            state_commitment: [0; 32],
            commands_commitment: [0; 32],
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        },
        commands: vec![],
    };
    let proposal = Proposal { block, justify: qc };
    let signed = Signed::sign(proposal, leader, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let err = ingress_with_qc_verification(
        leader.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("tampered QC must be rejected");
    assert!(matches!(
        err,
        IngressError::InvalidQcAggregate {
            view: View(5),
            scheme: "ed25519_collected"
        }
    ));
}

#[test]
fn ingress_with_verify_rejects_tampered_ed25519_qc_inside_newview() {
    let view: View = View(7);
    let block_hash = [0x77; 32];
    let (signers, vs, mut high_qc) = build_real_ed25519_qc(view, block_hash);
    let messenger = &signers[1];

    if let crate::hotstuff::qc::QcSignatures::Ed25519Collected(sigs) = &mut high_qc.signatures {
        sigs[1][3] ^= 0xAA;
    }

    let nv = NewView { high_qc };
    let signed = Signed::sign(nv, messenger, &ChainId::TEST).unwrap();
    let wire = WireMessage::NewView(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let err = ingress_with_qc_verification(
        messenger.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("tampered high_qc must be rejected");
    assert!(matches!(
        err,
        IngressError::InvalidQcAggregate {
            view: View(7),
            scheme: "ed25519_collected"
        }
    ));
}

/// Happy path for the TimeoutVote piggyback verifier (issue #321):
/// a real, properly-aggregated `high_qc` rides along on a timeout
/// vote and ingress flags it as trusted so `on_timeout_vote` will
/// fold it into the bucket's `best_high_qc`.
#[test]
fn ingress_with_verify_accepts_real_ed25519_qc_inside_timeout_vote_piggyback() {
    let qc_view: View = View(4);
    let block_hash = [0x44; 32];
    let (signers, vs, qc) = build_real_ed25519_qc(qc_view, block_hash);
    let voter = &signers[0];

    // Timeout vote at a *later* view than its piggybacked QC — the
    // typical pattern: the voter is timing out at the current view
    // and reporting the freshest QC they've seen so far.
    let tv = TimeoutVote {
        view: qc_view + 3,
        high_qc: Some(qc),
    };
    let signed = Signed::sign(tv, voter, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let dispatches = ingress_with_qc_verification(
        voter.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("real Ed25519 piggyback must verify under the genesis pubkeys");
    assert_eq!(dispatches.len(), 1);
    assert!(
        matches!(
            dispatches[0],
            Dispatch::TimeoutVote {
                high_qc_trusted: true,
                ..
            }
        ),
        "real piggyback must be flagged trusted, got {:?}",
        dispatches[0]
    );
}

/// Defence-in-depth for the TimeoutVote piggyback verifier (issue
/// #321): a Byzantine voter attaches a tampered aggregate to a
/// genuine timeout vote. The envelope is still emitted (suppressing
/// the timeout signal would let an attacker mute honest replicas
/// by attaching garbage), but `high_qc_trusted` is `false`, so
/// `on_timeout_vote` will not adopt the forged QC into
/// `bucket.best_high_qc` — closing the TC self-NewView loopback
/// laundering vector.
#[test]
fn ingress_with_verify_drops_tampered_ed25519_qc_inside_timeout_vote_piggyback() {
    let qc_view: View = View(4);
    let block_hash = [0x44; 32];
    let (signers, vs, mut qc) = build_real_ed25519_qc(qc_view, block_hash);
    let voter = &signers[0];

    // Tamper one byte of the first signature in the aggregate. The
    // bitmap and signature count remain consistent, so this slips
    // past `is_well_formed` and only fails at `verify_aggregate`.
    if let crate::hotstuff::qc::QcSignatures::Ed25519Collected(sigs) = &mut qc.signatures {
        sigs[0][0] ^= 0xFF;
    }

    let tv = TimeoutVote {
        view: qc_view + 3,
        high_qc: Some(qc),
    };
    let signed = Signed::sign(tv, voter, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let dispatches = ingress_with_qc_verification(
        voter.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("envelope must still be accepted even when the piggyback is forged");
    assert_eq!(dispatches.len(), 1);
    match &dispatches[0] {
        Dispatch::TimeoutVote {
            signed: emitted,
            high_qc_trusted,
        } => {
            assert!(!high_qc_trusted, "tampered piggyback must not be trusted");
            assert_eq!(
                emitted.payload.view,
                qc_view + 3,
                "the timeout vote envelope must reach the integration layer unchanged",
            );
        }
        other => panic!("expected Dispatch::TimeoutVote, got {other:?}"),
    }
}

/// Structural malformation of the piggyback (bitmap shape doesn't
/// match the validator set authoritative at `high_qc.view`) takes
/// the same drop-piggyback-keep-envelope branch as a tampered
/// aggregate. This ensures the `is_well_formed` gate inside
/// `verify_high_qc_piggyback` actually runs — without it, a stray
/// bitmap could panic the aggregate verifier (or pass the wrong
/// number of pubkeys through).
#[test]
fn ingress_with_verify_drops_malformed_high_qc_in_timeout_vote_piggyback() {
    let qc_view: View = View(4);
    let block_hash = [0x44; 32];
    let (signers, vs, qc) = build_real_ed25519_qc(qc_view, block_hash);
    let voter = &signers[0];

    // Construct a wrongly-sized QC for the same view — the bitmap
    // is 1 bit wide rather than `vs.len()` (= 4) bits. Real-set
    // ingress will see a bitmap-set-mismatch on `is_well_formed`.
    let mut malformed = QuorumCertificate::new(qc_view, block_hash, 1);
    malformed.add_signature(0, [0u8; 64]);
    // Sanity: the aggregate from the real QC also exists, but we
    // don't reuse its sigs — the verifier never gets that far.
    drop(qc);

    let tv = TimeoutVote {
        view: qc_view + 3,
        high_qc: Some(malformed),
    };
    let signed = Signed::sign(tv, voter, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let dispatches = ingress_with_qc_verification(
        voter.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("envelope must still be accepted even when the piggyback is malformed");
    assert!(
        matches!(
            dispatches[0],
            Dispatch::TimeoutVote {
                high_qc_trusted: false,
                ..
            }
        ),
        "malformed piggyback must clear high_qc_trusted, got {:?}",
        dispatches[0]
    );
}

/// `high_qc: None` is the common pre-genesis-seed case: a peer
/// timing out before they've seen any QC. Verification is vacuous
/// and `high_qc_trusted` is `true`. Codifying this so a future
/// refactor doesn't accidentally flip `None`-piggyback flagging.
#[test]
fn ingress_with_verify_emits_high_qc_trusted_for_timeout_vote_with_no_piggyback() {
    let voter = fresh_signer();
    let vs = make_vs_with_signers(&[&voter]);

    let tv = TimeoutVote {
        view: View(9),
        high_qc: None,
    };
    let signed = Signed::sign(tv, &voter, &ChainId::TEST).unwrap();
    let wire = WireMessage::TimeoutVote(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let dispatches = ingress_with_qc_verification(
        voter.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .unwrap();
    assert!(matches!(
        dispatches[0],
        Dispatch::TimeoutVote {
            high_qc_trusted: true,
            ..
        }
    ));
}

#[test]
fn ingress_with_verify_accepts_genesis_empty_qc_inside_proposal() {
    // The view-1 leader proposes with an empty justify == genesis QC.
    // That QC has no signers; the verifier must let it through
    // unchanged or no chain ever boots.
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    // #325 PR C: stamp the genesis block's
    // validator_history_commitment so the proposal-receive
    // verifier matches. Genesis has no commands, so the post-block
    // hash equals the v1 hash of the genesis-time histories.
    let mut block = genesis();
    block.header.validator_history_commitment =
        crate::history_commitment::compute_post_block_commitment(
            &block,
            &history,
            &key_history,
            None,
            &ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            crate::reconfig::MIN_V_EFF_DELAY,
        );
    let proposal = Proposal {
        block,
        justify: sample_qc(),
    };
    let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let dispatches = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("genesis QC (no signers) must pass aggregate verification");
    assert_eq!(dispatches.len(), 3);
}

/// Audit finding 7-4 (issue #418): a Byzantine peer ships a Proposal
/// whose `justify` is a "genesis-shaped" QC — `view == 0`, no signers
/// — but over an attacker-chosen `block_hash` that is not the real
/// genesis. The genesis-skip in `verify_qc_if_requested` would have
/// otherwise let it past aggregate verification (placeholder sigs
/// can't be verified anyway). Ingress must reject the malformed
/// envelope at the boundary rather than relying on the safety core's
/// parent-walk to refuse to extend the chain downstream.
#[test]
fn ingress_with_verify_rejects_view_zero_qc_over_non_genesis_block_hash() {
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);

    // Forged "genesis QC": view 0 with no signers, but the block_hash
    // is an attacker-chosen value, not the real genesis hash. This
    // shape passes the `view == 0 || signer_count() == 0` skip and
    // would slip through without the new check.
    let forged_block_hash = [0xDE; 32];
    assert_ne!(
        forged_block_hash,
        genesis().hash(),
        "test fixture is meaningful only when the forged hash is not the real genesis",
    );
    let forged_justify = QuorumCertificate::new(0, forged_block_hash, vs.len());

    let proposal = Proposal {
        block: genesis(),
        justify: forged_justify,
    };
    let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let err = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("forged view-0 QC over non-genesis block_hash must be rejected at ingress");
    assert!(
        matches!(
            err,
            IngressError::InvalidQcAggregate {
                view: View::ZERO,
                scheme: "ed25519_collected",
            }
        ),
        "expected InvalidQcAggregate at view 0, got {err:?}",
    );
}

#[test]
fn ingress_with_verify_rejects_bls_qc_on_ed25519_chain() {
    // A QC carrying the BLS variant arriving on an Ed25519 chain is
    // a structural mismatch — reject before pairing-check.
    let view: View = View(3);
    let block_hash = [0x33; 32];
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    // Build a real-shaped BLS QC so it survives is_well_formed:
    // sign with a real BLS key and fold the partial in normally.
    // The dispatch-layer scheme mismatch (Ed25519 chain receiving
    // a BLS QC) is what we're exercising, not bytes-level forgery.
    let mut ikm = [0u8; 32];
    ikm[0] = 0xAB;
    let (sk, _pk) = boule_core::crypto::sig_scheme::BlsAggregated::keygen(&ikm).unwrap();
    let real_partial =
        boule_core::crypto::sig_scheme::BlsAggregated::sign_partial(&sk, b"x").unwrap();
    let mut bls_qc = QuorumCertificate::new_bls(view, block_hash, vs.len());
    bls_qc.add_bls_partial(0, real_partial);

    let block = Block {
        header: crate::replication::block::BlockHeader {
            parent_hash: block_hash,
            height: Height(1),
            view: view + 1,
            proposer: signer.node_id(),
            state_commitment: [0; 32],
            commands_commitment: [0; 32],
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        },
        commands: vec![],
    };
    let proposal = Proposal {
        block,
        justify: bls_qc,
    };
    let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };
    let err = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("BLS QC on Ed25519 chain must be rejected");
    assert!(matches!(
        err,
        IngressError::InvalidQcAggregate {
            scheme: "ed25519_collected",
            ..
        }
    ));
}

// ── ingress: BLS partial on Vote (#354 step 1) ───────────────────────────

/// Build a BLS-keyed signer pair: an Ed25519 NodeSigner for the
/// envelope plus a BLS keypair registered against that signer's
/// NodeId. Returns `(ed25519_signer, bls_secret, bls_pubkey)`.
fn fresh_bls_signer(
    seed: u8,
) -> (
    NodeSigner,
    boule_core::crypto::sig_scheme::BlsSecretKey,
    boule_core::crypto::sig_scheme::BlsPublicKey,
) {
    let signer = fresh_signer();
    let mut ikm = [0u8; 32];
    ikm.fill(seed);
    let (sk, pk) = boule_core::crypto::sig_scheme::BlsAggregated::keygen(&ikm).unwrap();
    (signer, sk, pk)
}

/// Signed vote + valid BLS partial under `bls_sk` over the canonical
/// Vote pre-image.
fn make_signed_vote_with_bls_partial(
    signer: &NodeSigner,
    bls_sk: &boule_core::crypto::sig_scheme::BlsSecretKey,
    view: View,
    block_hash: BlockHash,
) -> (Signed<Vote>, boule_core::crypto::sig_scheme::BlsPartialSig) {
    let vote = Vote { view, block_hash };
    let preimage_bytes =
        boule_core::crypto::signed::preimage::<Vote>(&vote, &ChainId::TEST).unwrap();
    let partial =
        boule_core::crypto::sig_scheme::BlsAggregated::sign_partial(bls_sk, &preimage_bytes)
            .unwrap();
    let signed = Signed::sign(vote, signer, &ChainId::TEST).unwrap();
    (signed, partial)
}

#[test]
fn ingress_vote_on_bls_chain_accepts_valid_bls_partial() {
    let (signer, bls_sk, bls_pk) = fresh_bls_signer(0x11);
    let vs = make_vs_with_signers(&[&signer]);
    let view: View = View(5);
    let block_hash = [0xAA; 32];

    let (signed, partial) = make_signed_vote_with_bls_partial(&signer, &bls_sk, view, block_hash);
    let wire = WireMessage::Vote(signed, Some(partial));
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk)]);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::BlsAggregated,
        bls_key_history: Some(&bls_history),
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };

    let dispatches = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("valid BLS partial must pass ingress on a BLS chain");
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

#[test]
fn ingress_vote_on_bls_chain_rejects_missing_bls_partial() {
    let (signer, _bls_sk, bls_pk) = fresh_bls_signer(0x22);
    let vs = make_vs_with_signers(&[&signer]);
    let view: View = View(4);
    let block_hash = [0xBB; 32];

    // Vote with no BLS partial attached (None).
    let vote = Vote { view, block_hash };
    let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, None);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk)]);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::BlsAggregated,
        bls_key_history: Some(&bls_history),
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };

    let err = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("missing BLS partial on BLS chain must be rejected");
    let expected_signer = signer.node_id();
    assert!(matches!(
        err,
        IngressError::InvalidBlsPartial { view: View(4), signer: s } if s == expected_signer,
    ));
}

#[test]
fn ingress_vote_on_bls_chain_rejects_tampered_bls_partial() {
    let (signer, bls_sk, bls_pk) = fresh_bls_signer(0x33);
    let vs = make_vs_with_signers(&[&signer]);
    let view: View = View(6);
    let block_hash = [0xCC; 32];

    let (signed, mut partial) =
        make_signed_vote_with_bls_partial(&signer, &bls_sk, view, block_hash);
    partial[10] ^= 0xFF;
    let wire = WireMessage::Vote(signed, Some(partial));
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk)]);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::BlsAggregated,
        bls_key_history: Some(&bls_history),
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };

    let err = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("tampered BLS partial must be rejected");
    assert!(matches!(
        err,
        IngressError::InvalidBlsPartial { view: View(6), .. }
    ));
}

#[test]
fn ingress_vote_on_bls_chain_rejects_partial_signed_by_wrong_key() {
    // Voter's NodeId is the legitimate one, the envelope's Ed25519
    // sig is real, but the BLS partial was produced under some
    // other validator's BLS secret. Aggregating it would later make
    // the QC fail `verify_aggregate_bls`, so we reject up-front.
    let (signer, _bls_sk_a, bls_pk_a) = fresh_bls_signer(0x44);
    let (_, bls_sk_b, _bls_pk_b) = fresh_bls_signer(0x45);
    let vs = make_vs_with_signers(&[&signer]);
    let view: View = View(8);
    let block_hash = [0xDD; 32];

    let (signed, _) = make_signed_vote_with_bls_partial(&signer, &bls_sk_b, view, block_hash);
    let preimage_bytes =
        boule_core::crypto::signed::preimage::<Vote>(&signed.payload, &ChainId::TEST).unwrap();
    let partial =
        boule_core::crypto::sig_scheme::BlsAggregated::sign_partial(&bls_sk_b, &preimage_bytes)
            .unwrap();
    let wire = WireMessage::Vote(signed, Some(partial));
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    // History only knows the legitimate signer's pubkey (pk_a), but
    // the partial was produced under sk_b — verify_partial under
    // pk_a must reject.
    let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk_a)]);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::BlsAggregated,
        bls_key_history: Some(&bls_history),
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };

    let err = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("partial signed under the wrong BLS key must be rejected");
    assert!(matches!(
        err,
        IngressError::InvalidBlsPartial { view: View(8), .. }
    ));
}

#[test]
fn ingress_vote_on_ed25519_chain_ignores_bls_partial_field() {
    // On an Ed25519 chain, the optional BLS partial is metadata —
    // present or absent, valid or junk, ingress accepts the vote.
    // (The QC verifier only consults the inner Ed25519 sig.)
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let view: View = View(9);
    let block_hash = [0xEE; 32];

    // Ship a junk BLS partial alongside the vote — it must be ignored.
    let vote = Vote { view, block_hash };
    let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Vote(signed, Some([0xFFu8; 96]));
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::Ed25519Collected,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };

    let dispatches = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect("Ed25519 chain must ignore the optional BLS partial field");
    assert_eq!(dispatches.len(), 1);
    assert!(matches!(
        dispatches[0],
        Dispatch::Safety(SafetyEvent::VoteReceived(_))
    ));
}

#[test]
fn ingress_vote_on_bls_chain_rejects_when_bls_history_absent() {
    // Defense-in-depth: a BLS chain misconfigured to ship
    // `QcVerification::Verify` without a `bls_key_history` must not
    // silently let votes through. The verifier rejects because it
    // can't resolve the signer's historical BLS pubkey.
    let (signer, bls_sk, _bls_pk) = fresh_bls_signer(0x55);
    let vs = make_vs_with_signers(&[&signer]);
    let view: View = View(11);
    let block_hash = [0x11; 32];

    let (signed, partial) = make_signed_vote_with_bls_partial(&signer, &bls_sk, view, block_hash);
    let wire = WireMessage::Vote(signed, Some(partial));
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    let qc_verify = QcVerification::Verify {
        scheme: SignatureSchemeChoice::BlsAggregated,
        bls_key_history: None,
        min_v_eff_delay: crate::reconfig::MIN_V_EFF_DELAY,
        genesis_hash: genesis().hash(),
    };

    let err = ingress_with_qc_verification(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &qc_verify,
        &ChainId::TEST,
    )
    .expect_err("BLS chain without bls_key_history must reject");
    assert!(matches!(
        err,
        IngressError::InvalidBlsPartial { view: View(11), .. }
    ));
}

#[test]
fn ingress_vote_with_skip_does_not_validate_bls_partial() {
    // The Skip policy means tests construct QCs with placeholder
    // bytes — it must also tolerate junk BLS partials on Vote
    // frames. Document that tightening this would break the
    // existing test fixtures.
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);

    let vote = Vote {
        view: View(2),
        block_hash: [0x77; 32],
    };
    let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
    // Junk BLS partial — would not verify under any pubkey.
    let wire = WireMessage::Vote(signed, Some([0u8; 96]));
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs)
        .expect("Skip policy must not exercise BLS partial verification");
    assert_eq!(dispatches.len(), 1);
}

#[test]
fn ingress_with_skip_lets_invalid_aggregate_through() {
    // The default ingress path is `Skip` to preserve existing test
    // fixtures that construct QCs with placeholder bytes. Document
    // that behaviour explicitly so a future change doesn't tighten
    // it without us noticing.
    let signer = fresh_signer();
    let vs = make_vs_with_signers(&[&signer]);
    let mut bogus_qc = QuorumCertificate::new(0, sample_qc().block_hash, vs.len());
    bogus_qc.add_signature(0, [0xCC; 64]); // not a real Ed25519 sig
    let proposal = Proposal {
        block: genesis(),
        justify: bogus_qc,
    };
    let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
    let wire = WireMessage::Proposal(signed);
    let bytes = postcard::to_stdvec(&wire).unwrap();

    let history = ValidatorSetHistory::from_genesis(vs.clone());
    let key_history = key_history_from_set(&vs);
    // Default ingress → QcVerification::Skip → no aggregate check.
    let dispatches = ingress(
        signer.node_id(),
        &bytes,
        &history,
        &key_history,
        &ChainId::TEST,
    )
    .expect("Skip policy must not exercise aggregate verification");
    assert_eq!(dispatches.len(), 3);
}
