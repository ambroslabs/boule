use boule_consensus::View;
use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;

use crate::registry::RecordKey;

pub const MAGIC: [u8; 4] = *b"BLR1";

pub const VERSION: u8 = 1;

pub const BLS_KEY_LEN: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryPayload {
    pub keys: Vec<RecordKey>,

    pub weights: Vec<(NodeId, u64)>,

    pub settled_view: Option<View>,
}

impl RegistryPayload {
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

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.weights.is_empty() && self.settled_view.is_none()
    }

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

    pub fn to_attribute_hex(&self) -> String {
        if self.is_empty() {
            String::new()
        } else {
            format!("0x{}", hex::encode(self.encode()))
        }
    }

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

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

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
