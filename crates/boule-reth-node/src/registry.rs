//! The boule **registry write payload** — the authoritative
//! `(keys, weights, settledView)` consensus computes each block — and its
//! `extra_data` codec, plus the three system-call appliers
//! (`recordKey` / `recordWeight` / `recordSettled`) the custom executor runs at
//! the block boundary.
//!
//! ## Determinism
//!
//! The whole correctness story rests on **the executor reading the identical
//! bytes on the build and the verify path**. Both paths feed the sealed header's
//! `extra_data` into `EthBlockExecutionCtx.extra_data` (build:
//! attrs → `NextBlockEnvAttributes.extra_data` → header; verify: sealed header →
//! ctx — see `crates/.../evm` in reth v2.2.0). So the codec here is the single
//! source of truth: encode once on the proposer, decode byte-identically on
//! every verifier, apply the same three writes. No private key, no nonce, no
//! proposer trust — the EIP-4788 model (#777, #782).
//!
//! ## Encoding decision (a vs b) — we use **(a)**
//!
//! We carry the **full** `(keys, weights, settledView)` preimage directly in
//! `extra_data`, and **relax reth's 32-byte `extra_data` cap** for boule's chain
//! (a custom `ConsensusBuilder`, see `consensus.rs`). We do NOT use a 32-byte
//! commitment + a body-channel preimage (option b), because validator **weight
//! is not re-derivable from block execution** (it lives consensus-side), so a
//! commitment would still need a full preimage channel — and a header field that
//! both ctx builders already plumb is strictly simpler than inventing a system
//! tx the verify executor must parse out of the block body. The cost of (a) is a
//! larger header; bounded by the seated validator count (see [`MAX_EXTRA_DATA`]).

use alloy_primitives::{Address, B256, Bytes, address};
use alloy_sol_types::{SolCall, sol};

/// EL-only system caller (no private key) — the EIP-4788 / withdrawals model.
/// The Registry predeploy gates its writers on this address (see
/// `contracts/Registry.sol`, the `SYSTEM`/`WRITER` change in Phase 2).
pub const SYSTEM_ADDRESS: Address = address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// The boule `Registry` predeploy address (mirror of `boule-reth`'s genesis
/// seed; see `crates/boule-reth/src/registry.rs`).
pub const REGISTRY_ADDRESS: Address = address!("0x00000000000000000000000000000000000b0011");

/// 4-byte magic prefixing a boule registry payload in `extra_data`. Anything
/// without this prefix (e.g. stock reth's client-version `extra_data`) decodes
/// to [`None`] and applies no write — so a non-boule block is a clean no-op.
pub const MAGIC: [u8; 4] = *b"BLR1";

/// Wire-format version byte (after the magic), so the codec can evolve.
pub const VERSION: u8 = 1;

/// EIP-2537 uncompressed BLS12-381 G1 pubkey length (matches `Registry.sol`'s
/// `key.length == 128` requirement the slashing predeploy relies on).
pub const BLS_KEY_LEN: usize = 128;

/// Upper bound we accept for an `extra_data` payload, and the cap we configure
/// the relaxed consensus validator with. Chosen to comfortably hold the per-block
/// registry deltas for a realistic seated set: each key entry is
/// `32 (validator) + 8 (vEff) + 128 (key)` bytes and each weight entry is
/// `32 + 8`, so e.g. ~200 simultaneous key rotations + weight updates fit well
/// under this. A header this size is paid only on blocks that carry rotations.
pub const MAX_EXTRA_DATA: usize = 64 * 1024;

/// One BLS-key rotation to mirror into the Registry: validator `id`'s key became
/// active from consensus view `v_eff`. Shape mirrors `Registry.recordKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub validator: B256,
    pub v_eff: u64,
    /// 128-byte EIP-2537 uncompressed G1 pubkey.
    pub key: Vec<u8>,
}

/// One weight update to mirror: validator `id`'s seated weight is now `weight`
/// (`0` == removed). Shape mirrors `Registry.recordWeight`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightRecord {
    pub validator: B256,
    pub weight: u64,
}

/// The authoritative per-block registry write set boule consensus computes:
/// the key rotations and weight changes to mirror this block, plus the
/// conservative settled frontier to advance to. An empty payload (no keys, no
/// weights, `settled_view == None`) means "no registry writes this block".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryPayload {
    pub keys: Vec<KeyRecord>,
    pub weights: Vec<WeightRecord>,
    /// The conservative settled view to advance the frontier to (#767), or
    /// `None` to leave it unchanged this block.
    pub settled_view: Option<u64>,
}

impl RegistryPayload {
    /// True when there is nothing to write — the codec maps this to *no*
    /// `extra_data` magic, so the block looks like a plain Ethereum block.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.weights.is_empty() && self.settled_view.is_none()
    }

    /// Deterministically encode into `extra_data` bytes:
    ///
    /// ```text
    /// magic[4] | version[1] | flags[1] | [settled_view u64 BE if flag] |
    /// key_count u32 BE | { validator[32] | v_eff u64 BE | key[128] } * |
    /// weight_count u32 BE | { validator[32] | weight u64 BE } *
    /// ```
    ///
    /// The field order and per-record byte layout are fixed, and the caller is
    /// responsible for passing `keys`/`weights` in a consensus-canonical order
    /// (same on every replica), so the bytes are identical across nodes.
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

    /// Decode an `extra_data` blob back into a payload. Returns [`None`] for any
    /// blob that is not a well-formed boule registry payload (wrong magic, wrong
    /// version, truncated, or a key not exactly [`BLS_KEY_LEN`] bytes) — a
    /// non-boule block applies no registry writes.
    ///
    /// This MUST be lossless against [`encode`](Self::encode): the round-trip is
    /// the determinism guarantee (build encodes, verify decodes the same bytes).
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

/// A minimal forward-only byte cursor for the decoder (no external dep).
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

// The Registry predeploy ABI — the three writers the EL applies as system calls.
// Signatures MUST match `crates/boule-reth/contracts/Registry.sol`.
sol!(
    function recordKey(bytes32 validator, uint64 vEff, bytes key);
    function recordWeight(bytes32 validator, uint64 newWeight);
    function recordSettled(uint64 viewNum);
);

/// ABI-encode the `recordKey(validator, vEff, key)` calldata.
pub fn record_key_calldata(rec: &KeyRecord) -> Vec<u8> {
    recordKeyCall {
        validator: rec.validator,
        vEff: rec.v_eff,
        key: rec.key.clone().into(),
    }
    .abi_encode()
}

/// ABI-encode the `recordWeight(validator, newWeight)` calldata.
pub fn record_weight_calldata(rec: &WeightRecord) -> Vec<u8> {
    recordWeightCall {
        validator: rec.validator,
        newWeight: rec.weight,
    }
    .abi_encode()
}

/// ABI-encode the `recordSettled(viewNum)` calldata.
pub fn record_settled_calldata(view: u64) -> Vec<u8> {
    recordSettledCall { viewNum: view }.abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RegistryPayload {
        RegistryPayload {
            keys: vec![
                KeyRecord {
                    validator: B256::repeat_byte(0x11),
                    v_eff: 7,
                    key: vec![0xAB; 128],
                },
                KeyRecord {
                    validator: B256::repeat_byte(0x22),
                    v_eff: 9,
                    key: vec![0xCD; 128],
                },
            ],
            weights: vec![
                WeightRecord {
                    validator: B256::repeat_byte(0x11),
                    weight: 100,
                },
                WeightRecord {
                    validator: B256::repeat_byte(0x33),
                    weight: 0,
                },
            ],
            settled_view: Some(42),
        }
    }

    #[test]
    fn roundtrips_full_payload() {
        let p = sample();
        let bytes = p.encode();
        // The build path and the verify path call `decode` on the SAME bytes;
        // this asserts that yields the identical payload (the determinism core).
        let back = RegistryPayload::decode(&bytes).expect("decode");
        assert_eq!(p, back);
    }

    #[test]
    fn roundtrips_empty_and_settled_only() {
        for p in [
            RegistryPayload::default(),
            RegistryPayload {
                settled_view: Some(5),
                ..Default::default()
            },
            RegistryPayload {
                keys: vec![KeyRecord {
                    validator: B256::ZERO,
                    v_eff: 0,
                    key: vec![0; 128],
                }],
                ..Default::default()
            },
        ] {
            assert_eq!(RegistryPayload::decode(&p.encode()), Some(p));
        }
    }

    #[test]
    fn non_boule_extra_data_is_none() {
        // Stock reth client-version extra_data, random bytes, empty: all no-ops.
        assert_eq!(RegistryPayload::decode(b"reth/v2.2.0/linux"), None);
        assert_eq!(RegistryPayload::decode(&[]), None);
        assert_eq!(RegistryPayload::decode(b"BLR1"), None); // truncated
    }

    #[test]
    fn rejects_trailing_garbage_and_truncation() {
        let mut bytes = sample().encode().to_vec();
        bytes.push(0xFF); // trailing byte
        assert_eq!(RegistryPayload::decode(&bytes), None);

        let bytes = sample().encode();
        assert_eq!(RegistryPayload::decode(&bytes[..bytes.len() - 1]), None);
    }

    #[test]
    fn empty_payload_is_empty() {
        assert!(RegistryPayload::default().is_empty());
        assert!(!sample().is_empty());
    }

    #[test]
    fn calldata_matches_abi_selectors() {
        // Solidity selectors from `Registry.sol` (keccak of the canonical sig).
        // recordKey(bytes32,uint64,bytes), recordWeight(bytes32,uint64),
        // recordSettled(uint64).
        let k = record_key_calldata(&KeyRecord {
            validator: B256::ZERO,
            v_eff: 1,
            key: vec![0; 128],
        });
        let w = record_weight_calldata(&WeightRecord {
            validator: B256::ZERO,
            weight: 1,
        });
        let s = record_settled_calldata(1);
        assert_eq!(&k[..4], &recordKeyCall::SELECTOR);
        assert_eq!(&w[..4], &recordWeightCall::SELECTOR);
        assert_eq!(&s[..4], &recordSettledCall::SELECTOR);
    }

    #[test]
    fn fits_a_realistic_seated_set_under_cap() {
        // 200 key rotations + 200 weight updates + settled view.
        let p = RegistryPayload {
            keys: (0..200)
                .map(|i| KeyRecord {
                    validator: B256::repeat_byte(i as u8),
                    v_eff: i,
                    key: vec![0xEE; 128],
                })
                .collect(),
            weights: (0..200)
                .map(|i| WeightRecord {
                    validator: B256::repeat_byte(i as u8),
                    weight: i,
                })
                .collect(),
            settled_view: Some(1_000),
        };
        assert!(
            p.encode().len() < MAX_EXTRA_DATA,
            "stays under the relaxed cap"
        );
        assert_eq!(RegistryPayload::decode(&p.encode()), Some(p));
    }
}
