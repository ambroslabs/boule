//! Cross-layer invariant: the `WireMessage` postcard variant indices
//! (defined in `boule-consensus`) must stay in lockstep with
//! `MessageKind::from_wire_tag` (defined in `boule-transport`). The two
//! live in different crates now, so the check lives here in `boule-node`
//! where both are visible. Moved out of `boule-transport::limits` when
//! the crate split landed.

use boule::crypto::signed::Signed;
use boule_consensus::wire::{BlockResponsePayload, WireMessage};
use boule_transport::limits::MessageKind;

#[test]
fn wire_tag_layout_locked() {
    let req = WireMessage::BlockRequest([0u8; 32]);
    let bytes = postcard::to_allocvec(&req).expect("encode");
    assert_eq!(bytes[0], 4, "BlockRequest must serialize at tag 4");

    let resp = WireMessage::BlockResponse(Signed {
        payload: BlockResponsePayload {
            requested_hash: [0u8; 32],
            block: None,
        },
        signer: [0u8; 32],
        sig: [0u8; 64],
    });
    let bytes = postcard::to_allocvec(&resp).expect("encode");
    assert_eq!(bytes[0], 5, "BlockResponse must serialize at tag 5");

    let req = WireMessage::SnapshotManifestRequest { height: None };
    let bytes = postcard::to_allocvec(&req).expect("encode");
    assert_eq!(
        bytes[0], 6,
        "SnapshotManifestRequest must serialize at tag 6"
    );

    let resp = WireMessage::SnapshotManifestResponse(None);
    let bytes = postcard::to_allocvec(&resp).expect("encode");
    assert_eq!(
        bytes[0], 7,
        "SnapshotManifestResponse must serialize at tag 7"
    );

    let req = WireMessage::SnapshotChunkRequest {
        height: 0,
        chunk_idx: 0,
    };
    let bytes = postcard::to_allocvec(&req).expect("encode");
    assert_eq!(bytes[0], 8, "SnapshotChunkRequest must serialize at tag 8");

    let resp = WireMessage::SnapshotChunkResponse {
        height: 0,
        chunk_idx: 0,
        payload: None,
    };
    let bytes = postcard::to_allocvec(&resp).expect("encode");
    assert_eq!(bytes[0], 9, "SnapshotChunkResponse must serialize at tag 9");

    let req = WireMessage::BlockRangeRequest {
        from_height: boule_consensus::Height(0),
        to_height: boule_consensus::Height(0),
    };
    let bytes = postcard::to_allocvec(&req).expect("encode");
    assert_eq!(bytes[0], 10, "BlockRangeRequest must serialize at tag 10");

    let resp = WireMessage::BlockRangeResponse(Signed {
        payload: boule_consensus::wire::BlockRangeResponsePayload {
            from_height: boule_consensus::Height(0),
            to_height: boule_consensus::Height(0),
            blocks: Vec::new(),
        },
        signer: [0u8; 32],
        sig: [0u8; 64],
    });
    let bytes = postcard::to_allocvec(&resp).expect("encode");
    assert_eq!(bytes[0], 11, "BlockRangeResponse must serialize at tag 11");

    for (tag, kind) in [
        (0, MessageKind::Proposal),
        (1, MessageKind::Vote),
        (2, MessageKind::NewView),
        (3, MessageKind::TimeoutVote),
        (4, MessageKind::RequestBlock),
        (5, MessageKind::ReceiveBlock),
        (6, MessageKind::SnapshotManifestRequest),
        (7, MessageKind::SnapshotManifestResponse),
        (8, MessageKind::SnapshotChunkRequest),
        (9, MessageKind::SnapshotChunkResponse),
        (10, MessageKind::BlockRangeRequest),
        (11, MessageKind::BlockRangeResponse),
    ] {
        assert_eq!(MessageKind::from_wire_tag(tag), Some(kind));
    }
    assert_eq!(MessageKind::from_wire_tag(12), None);
    assert_eq!(MessageKind::from_wire_tag(0xFF), None);
}
