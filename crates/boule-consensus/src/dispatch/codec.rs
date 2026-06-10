use bytes::Bytes;

use crate::wire::WireMessage;

pub(super) fn decode(bytes: &[u8]) -> Result<WireMessage, postcard::Error> {
    postcard::from_bytes(bytes)
}

pub(super) fn encode(msg: &WireMessage) -> Result<Bytes, postcard::Error> {
    postcard::to_stdvec(msg).map(Bytes::from)
}
