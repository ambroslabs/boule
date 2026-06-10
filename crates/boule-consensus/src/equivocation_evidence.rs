use bytes::Bytes;

use crate::dispatch::EquivocationProof;

pub const EVIDENCE_TAG: &[u8; 6] = b"EVDNC\0";

pub const MAX_EVIDENCE_AGE_VIEWS: u64 = 1024;

pub fn encode_evidence(proof: &EquivocationProof) -> Bytes {
    let body =
        postcard::to_stdvec(proof).expect("postcard encoding of EquivocationProof cannot fail");
    let mut out = Vec::with_capacity(EVIDENCE_TAG.len() + body.len());
    out.extend_from_slice(EVIDENCE_TAG);
    out.extend_from_slice(&body);
    Bytes::from(out)
}

pub fn is_evidence_payload(bytes: &[u8]) -> bool {
    bytes.starts_with(EVIDENCE_TAG)
}

pub fn decode_evidence(bytes: &[u8]) -> anyhow::Result<EquivocationProof> {
    let body = bytes
        .strip_prefix(EVIDENCE_TAG.as_slice())
        .ok_or_else(|| anyhow::anyhow!("missing evidence tag prefix"))?;
    postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed EquivocationProof: {e}"))
}
