use alloy_primitives::{Address, B256, Bytes, address};
use alloy_sol_types::{SolCall, sol};

pub const SYSTEM_ADDRESS: Address = address!("0xfffffffffffffffffffffffffffffffffffffffe");

pub const REGISTRY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000b12");

pub const MAGIC: [u8; 4] = *b"BLR1";

pub const VERSION: u8 = 1;

pub const BLS_KEY_LEN: usize = 128;

pub const MAX_EXTRA_DATA: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub validator: B256,
    pub v_eff: u64,

    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightRecord {
    pub validator: B256,
    pub weight: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryPayload {
    pub keys: Vec<KeyRecord>,
    pub weights: Vec<WeightRecord>,

    pub settled_view: Option<u64>,
}

impl RegistryPayload {
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.weights.is_empty() && self.settled_view.is_none()
    }

    pub fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(6 + self.keys.len() * 168 + self.weights.len() * 40);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);

        let mut flags = 0u8;
        if self.settled_view.is_some() {
            flags |= 0b0000_0001;
        }
        out.push(flags);

        if let Some(view) = self.settled_view {
            out.extend_from_slice(&view.to_be_bytes());
        }

        out.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for k in &self.keys {
            out.extend_from_slice(k.validator.as_slice());
            out.extend_from_slice(&k.v_eff.to_be_bytes());
            out.extend_from_slice(&k.key);
        }

        out.extend_from_slice(&(self.weights.len() as u32).to_be_bytes());
        for w in &self.weights {
            out.extend_from_slice(w.validator.as_slice());
            out.extend_from_slice(&w.weight.to_be_bytes());
        }

        Bytes::from(out)
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
            Some(u64::from_be_bytes(c.take(8)?.try_into().ok()?))
        } else {
            None
        };

        let key_count = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let validator = B256::from_slice(c.take(32)?);
            let v_eff = u64::from_be_bytes(c.take(8)?.try_into().ok()?);
            let key = c.take(BLS_KEY_LEN)?.to_vec();
            keys.push(KeyRecord {
                validator,
                v_eff,
                key,
            });
        }

        let weight_count = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
        let mut weights = Vec::with_capacity(weight_count);
        for _ in 0..weight_count {
            let validator = B256::from_slice(c.take(32)?);
            let weight = u64::from_be_bytes(c.take(8)?.try_into().ok()?);
            weights.push(WeightRecord { validator, weight });
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

sol!(
    function recordKey(bytes32 validator, uint64 vEff, bytes key);
    function recordWeight(bytes32 validator, uint64 newWeight);
    function recordSettled(uint64 viewNum);
);

pub fn record_key_calldata(rec: &KeyRecord) -> Vec<u8> {
    recordKeyCall {
        validator: rec.validator,
        vEff: rec.v_eff,
        key: rec.key.clone().into(),
    }
    .abi_encode()
}

pub fn record_weight_calldata(rec: &WeightRecord) -> Vec<u8> {
    recordWeightCall {
        validator: rec.validator,
        newWeight: rec.weight,
    }
    .abi_encode()
}

pub fn record_settled_calldata(view: u64) -> Vec<u8> {
    recordSettledCall { viewNum: view }.abi_encode()
}
