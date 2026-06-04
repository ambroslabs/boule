//! The **boule → custom-EL registry-write payload** and its `extra_data` codec
//! (#781, A1 Phase 1) — the *production* (build-path) half of the EL-applied
//! registry write path.
//!
//! `boule-reth-node` (the custom EL, #788) applies `recordKey` / `recordWeight`
//! / `recordSettled` as **system calls** at the block boundary, decoding the
//! `(keys, weights, settledView)` write set from the sealed header `extra_data`.
//! For that to happen the leader must put the same write set onto the Engine-API
//! `forkchoiceUpdatedV3` payload attributes as the custom `registryPayload`
//! field (a `0x`-prefixed hex string), which the EL's custom payload builder
//! transcribes into `extra_data`. **This module produces those bytes**, from the
//! authoritative consensus deltas the [`RethApplication`](crate::RethApplication)
//! already computes (committed BLS-key rotations, seated-weight changes, and the
//! conservative settled frontier).
//!
//! ## Why a second copy of the codec
//!
//! `boule-reth-node` is a **standalone workspace** (excluded from boule's root
//! workspace — its reth-SDK dependency tree is huge), so `boule-reth` cannot
//! depend on it as a crate. The wire format is therefore mirrored here and pinned
//! to the EL's `boule_reth_node::registry::RegistryPayload::encode` **byte-for-
//! byte** by the golden vectors in the tests below: the field order, the magic /
//! version / flags bytes, and the per-record big-endian layout must match exactly
//! or the EL would decode a different (or no) write set and the registry would
//! diverge from consensus. The format is documented on
//! `boule_reth_node::registry::RegistryPayload::encode`; the canonical layout is:
//!
//! ```text
//! magic[4]="BLR1" | version[1]=1 | flags[1] | [settled_view u64 BE if flag&1] |
//! key_count u32 BE   | { validator[32] | v_eff u64 BE | key[128] } * |
//! weight_count u32 BE | { validator[32] | weight u64 BE } *
//! ```
//!
//! An empty write set (no keys, no weights, no settled view) encodes to *no*
//! payload at all (an empty `registryPayload` string), so a plain block carries
//! the EL's default `extra_data` and applies no registry write — the common case.

use boule_consensus::View;
use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;

use crate::registry::RecordKey;

/// 4-byte magic prefixing a boule registry payload in `extra_data`. Must equal
/// `boule_reth_node::registry::MAGIC` — the EL decodes only blobs with this
/// prefix (anything else is a clean no-op block).
pub const MAGIC: [u8; 4] = *b"BLR1";

/// Wire-format version byte (after the magic). Must equal
/// `boule_reth_node::registry::VERSION`.
pub const VERSION: u8 = 1;

/// EIP-2537 uncompressed BLS12-381 G1 pubkey length the EL expects for each key
/// record (matches `Registry.sol`'s `key.length == 128`). Must equal
/// `boule_reth_node::registry::BLS_KEY_LEN`.
pub const BLS_KEY_LEN: usize = 128;

/// The authoritative per-block registry write set the leader carries to the EL:
/// the BLS-key rotations and seated-weight changes to mirror this block, plus the
/// conservative settled frontier to advance to. Mirrors
/// `boule_reth_node::registry::RegistryPayload` (the EL-side decode target).
///
/// An empty payload (no keys, no weights, `settled_view == None`) carries no
/// `registryPayload` attribute, so the EL builds a plain block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryPayload {
    /// BLS-key rotations that became effective this block — the same
    /// [`RecordKey`]s the tx-write path mirrors via `recordKey`
    /// ([`crate::registry::record_key_for_rotation`]).
    pub keys: Vec<RecordKey>,
    /// Seated validator-weight changes — one entry per genuinely-changed
    /// validator (the [`ValidatorUpdate`]s the staking/slashing read path
    /// produced), `weight == 0` meaning removed.
    pub weights: Vec<(NodeId, u64)>,
    /// The conservative settled view to advance the frontier to (#767), or
    /// `None` to leave it unchanged this block.
    pub settled_view: Option<View>,
}

impl RegistryPayload {
    /// Build from the deltas the [`RethApplication`](crate::RethApplication)
    /// already computes: the committed BLS-key rotations (as [`RecordKey`]s, in
    /// the EL's 128-byte EIP-2537 form), the seated-weight changes (as
    /// [`ValidatorUpdate`]s), and the conservative settled view. The caller is
    /// responsible for passing `keys` / `weights` in a **consensus-canonical
    /// order** (the same on every replica), so the encoded bytes — and therefore
    /// the EL's applied write set — are identical across nodes.
    pub fn new(
        keys: Vec<RecordKey>,
        weights: &[ValidatorUpdate],
        settled_view: Option<View>,
    ) -> Self {
        Self {
            keys,
            weights: weights.iter().map(|u| (u.node_id, u.weight)).collect(),
            settled_view,
        }
    }

    /// True when there is nothing to mirror — the codec maps this to *no*
    /// `registryPayload` attribute, so the EL builds a plain block.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.weights.is_empty() && self.settled_view.is_none()
    }

    /// Deterministically encode into the `extra_data` bytes the EL decodes (see
    /// the module docs for the layout). MUST stay byte-identical to
    /// `boule_reth_node::registry::RegistryPayload::encode` — the golden vectors
    /// in the tests pin it.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.keys.len() * 168 + self.weights.len() * 40);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);

        let mut flags = 0u8;
        if self.settled_view.is_some() {
            flags |= 0b0000_0001;
        }
        out.push(flags);

        if let Some(view) = self.settled_view {
            out.extend_from_slice(&view.0.to_be_bytes());
        }

        out.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for k in &self.keys {
            out.extend_from_slice(&k.validator);
            out.extend_from_slice(&k.v_eff.0.to_be_bytes());
            debug_assert_eq!(k.key128.len(), BLS_KEY_LEN);
            out.extend_from_slice(&k.key128);
        }

        out.extend_from_slice(&(self.weights.len() as u32).to_be_bytes());
        for (validator, weight) in &self.weights {
            out.extend_from_slice(validator);
            out.extend_from_slice(&weight.to_be_bytes());
        }

        out
    }

    /// The Engine-API `registryPayload` attribute value: a `0x`-prefixed hex
    /// string of [`encode`](Self::encode), or the **empty string** when there is
    /// nothing to mirror (so a plain block carries no payload). The custom EL's
    /// `BoulePayloadAttributes` (in `boule-reth-node`) hex-decodes this back into
    /// `extra_data`.
    pub fn to_attribute_hex(&self) -> String {
        if self.is_empty() {
            String::new()
        } else {
            format!("0x{}", hex::encode(self.encode()))
        }
    }

    /// Decode a sealed block's `extra_data` back into the write set it carried —
    /// the inverse of [`encode`](Self::encode), mirroring
    /// `boule_reth_node::registry::RegistryPayload::decode` byte-for-byte. Returns
    /// [`None`] for any blob that is not a well-formed boule registry payload
    /// (wrong magic, wrong version, truncated, or trailing garbage), exactly as
    /// the EL no-ops a non-boule block.
    ///
    /// boule uses this to learn which seated-weight deltas a *committed* block
    /// already mirrored through the EL, so it can drop them from the pending-weight
    /// buffer (Part B of #791): the build path carries pending deltas in
    /// `extra_data`, and `commit` reconciles against the committed block's
    /// `extra_data` so no delta is carried twice and none leaks. (`keys`/
    /// `settled_view` are reconstructed for completeness but boule only consults
    /// the weights.)
    pub fn decode(extra_data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(extra_data);
        if c.take(4)? != MAGIC {
            return None;
        }
        if c.take(1)?[0] != VERSION {
            return None;
        }
        let flags = c.take(1)?[0];

        let settled_view = if flags & 0b0000_0001 != 0 {
            Some(View::new(u64::from_be_bytes(c.take(8)?.try_into().ok()?)))
        } else {
            None
        };

        let key_count = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let validator: NodeId = c.take(32)?.try_into().ok()?;
            let v_eff = View::new(u64::from_be_bytes(c.take(8)?.try_into().ok()?));
            let key128: [u8; BLS_KEY_LEN] = c.take(BLS_KEY_LEN)?.try_into().ok()?;
            keys.push(RecordKey {
                validator,
                v_eff,
                key128,
            });
        }

        let weight_count = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
        let mut weights = Vec::with_capacity(weight_count);
        for _ in 0..weight_count {
            let validator: NodeId = c.take(32)?.try_into().ok()?;
            let weight = u64::from_be_bytes(c.take(8)?.try_into().ok()?);
            weights.push((validator, weight));
        }

        // Reject trailing garbage so encode/decode is exactly bijective.
        if !c.is_empty() {
            return None;
        }

        Some(Self {
            keys,
            weights,
            settled_view,
        })
    }
}

/// A minimal forward-only byte cursor for [`RegistryPayload::decode`] (no extra
/// dep), mirroring the EL decoder's cursor.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Take exactly `n` bytes, or [`None`] if fewer remain (truncated input).
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rk(b: u8, v_eff: u64, key_byte: u8) -> RecordKey {
        RecordKey {
            validator: [b; 32],
            v_eff: View::new(v_eff),
            key128: [key_byte; 128],
        }
    }

    fn vu(b: u8, weight: u64) -> ValidatorUpdate {
        ValidatorUpdate {
            node_id: [b; 32],
            weight,
        }
    }

    /// The empty write set carries no attribute (a plain block).
    #[test]
    fn empty_payload_has_no_attribute() {
        let p = RegistryPayload::default();
        assert!(p.is_empty());
        assert_eq!(p.to_attribute_hex(), "");
    }

    /// A settled-view-only payload (the common per-block case) encodes the
    /// magic + version + the set flag + the 8-byte big-endian view + two zero
    /// counts. Pinned byte-for-byte to the EL codec.
    #[test]
    fn settled_only_golden_bytes() {
        let p = RegistryPayload {
            settled_view: Some(View::new(0x2A)),
            ..Default::default()
        };
        let bytes = p.encode();
        let mut want = Vec::new();
        want.extend_from_slice(b"BLR1"); // magic
        want.push(0x01); // version
        want.push(0x01); // flags: settled set
        want.extend_from_slice(&42u64.to_be_bytes()); // settled_view
        want.extend_from_slice(&0u32.to_be_bytes()); // key_count
        want.extend_from_slice(&0u32.to_be_bytes()); // weight_count
        assert_eq!(bytes, want);
        // 4 + 1 + 1 + 8 + 4 + 4 = 22 bytes.
        assert_eq!(bytes.len(), 22);
    }

    /// A full payload's golden byte layout: keys then weights, each field in the
    /// fixed order and big-endian encoding the EL decoder expects.
    #[test]
    fn full_payload_golden_bytes() {
        let p = RegistryPayload::new(
            vec![rk(0x11, 7, 0xAB), rk(0x22, 9, 0xCD)],
            &[vu(0x11, 100), vu(0x33, 0)],
            Some(View::new(42)),
        );
        let bytes = p.encode();

        let mut want = Vec::new();
        want.extend_from_slice(b"BLR1");
        want.push(0x01); // version
        want.push(0x01); // flags: settled set
        want.extend_from_slice(&42u64.to_be_bytes());
        want.extend_from_slice(&2u32.to_be_bytes()); // 2 keys
        // key 0
        want.extend_from_slice(&[0x11; 32]);
        want.extend_from_slice(&7u64.to_be_bytes());
        want.extend_from_slice(&[0xAB; 128]);
        // key 1
        want.extend_from_slice(&[0x22; 32]);
        want.extend_from_slice(&9u64.to_be_bytes());
        want.extend_from_slice(&[0xCD; 128]);
        want.extend_from_slice(&2u32.to_be_bytes()); // 2 weights
        // weight 0
        want.extend_from_slice(&[0x11; 32]);
        want.extend_from_slice(&100u64.to_be_bytes());
        // weight 1
        want.extend_from_slice(&[0x33; 32]);
        want.extend_from_slice(&0u64.to_be_bytes());

        assert_eq!(bytes, want);
        // 6 header + 8 settled + 4 + 2*(32+8+128) + 4 + 2*(32+8)
        assert_eq!(bytes.len(), 6 + 8 + 4 + 2 * 168 + 4 + 2 * 40);
    }

    /// The attribute hex is the `0x`-prefixed lowercase hex of the encoded bytes.
    #[test]
    fn attribute_hex_is_prefixed_encode() {
        let p = RegistryPayload {
            settled_view: Some(View::new(1)),
            ..Default::default()
        };
        let hex = p.to_attribute_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex, format!("0x{}", hex::encode(p.encode())));
        // Round-trips back to the same bytes when the EL hex-decodes it.
        let decoded = hex::decode(hex.trim_start_matches("0x")).unwrap();
        assert_eq!(decoded, p.encode());
    }

    /// `new` maps each `ValidatorUpdate` to a `(node_id, weight)` pair in order,
    /// and threads keys + settled view through unchanged.
    #[test]
    fn new_maps_updates_to_weight_pairs() {
        let p = RegistryPayload::new(
            vec![rk(0x01, 3, 0x07)],
            &[vu(0x0a, 5), vu(0x0b, 0)],
            Some(View::new(9)),
        );
        assert_eq!(p.keys, vec![rk(0x01, 3, 0x07)]);
        assert_eq!(p.weights, vec![([0x0a; 32], 5), ([0x0b; 32], 0)]);
        assert_eq!(p.settled_view, Some(View::new(9)));
        assert!(!p.is_empty());
    }

    /// **The cross-crate determinism pin.** This golden byte vector is exactly
    /// what `boule_reth_node::registry::RegistryPayload::decode` must accept and
    /// decode back to the matching write set. It is the EL's
    /// `tests/determinism.rs` "settled_view: 123_456" case, and the expected
    /// bytes are spelled out field-by-field (matching the EL codec's documented
    /// layout) rather than reusing `encode`, so a drift in *either* side's
    /// encoding is caught: this fails here, and the EL's own round-trip test
    /// fails there. See the PR / the live-drive test, which feeds exactly these
    /// bytes through the real EL and confirms the registry reflects the write.
    #[test]
    fn matches_el_codec_golden_vectors() {
        let a = RegistryPayload {
            settled_view: Some(View::new(123_456)),
            ..Default::default()
        };
        let mut want = Vec::new();
        want.extend_from_slice(b"BLR1"); // magic
        want.push(0x01); // version
        want.push(0x01); // flags: settled set
        want.extend_from_slice(&123_456u64.to_be_bytes()); // settled_view BE
        want.extend_from_slice(&0u32.to_be_bytes()); // key_count
        want.extend_from_slice(&0u32.to_be_bytes()); // weight_count
        assert_eq!(a.encode(), want);
        // The literal hex, pinned for an at-a-glance cross-check against the EL:
        // 424c5231 | 01 | 01 | 000000000001e240 | 00000000 | 00000000.
        assert_eq!(
            hex::encode(a.encode()),
            "424c52310101000000000001e2400000000000000000",
        );
        assert_eq!(a.encode().len(), 22);
    }

    /// `decode` is the exact inverse of `encode` for a full payload — the
    /// reconciliation Part B relies on (commit decodes a committed block's
    /// `extra_data` to drop the weights it already mirrored).
    #[test]
    fn decode_roundtrips_full_payload() {
        let p = RegistryPayload::new(
            vec![rk(0x11, 7, 0xAB), rk(0x22, 9, 0xCD)],
            &[vu(0x11, 100), vu(0x33, 0)],
            Some(View::new(42)),
        );
        assert_eq!(RegistryPayload::decode(&p.encode()), Some(p));
    }

    /// Empty, settled-only, and weights-only payloads all round-trip.
    #[test]
    fn decode_roundtrips_edge_payloads() {
        for p in [
            RegistryPayload {
                settled_view: Some(View::new(5)),
                ..Default::default()
            },
            RegistryPayload::new(vec![], &[vu(0x0a, 7), vu(0x0b, 0)], None),
            RegistryPayload::new(vec![rk(0x01, 3, 0x07)], &[], None),
        ] {
            assert_eq!(RegistryPayload::decode(&p.encode()), Some(p));
        }
    }

    /// A non-boule / malformed `extra_data` decodes to `None` (a clean no-op),
    /// matching the EL decoder so reconciliation drops nothing for a plain block.
    #[test]
    fn decode_rejects_non_boule_and_malformed() {
        assert_eq!(RegistryPayload::decode(b"reth/v2.2.0/linux"), None);
        assert_eq!(RegistryPayload::decode(&[]), None);
        assert_eq!(RegistryPayload::decode(b"BLR1"), None); // truncated
        let mut bytes = RegistryPayload::new(vec![], &[vu(1, 1)], None).encode();
        bytes.push(0xFF); // trailing garbage
        assert_eq!(RegistryPayload::decode(&bytes), None);
    }
}
