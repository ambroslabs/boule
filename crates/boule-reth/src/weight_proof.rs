use alloy_consensus::{Eip658Value, Receipt, ReceiptEnvelope, TxType};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{B256, Bytes as AlloyBytes, Log, LogData};
use alloy_trie::{
    HashBuilder, Nibbles, proof::ProofRetainer, proof::verify_proof, root::adjust_index_for_rlp,
};
use anyhow::{Context, Result, bail};
use boule_core::identity::NodeId;
use serde_json::Value;

use boule_consensus::Height;
use boule_consensus::replication::block::BlockHash;

use crate::{slashing, staking};

pub const MAGIC: [u8; 4] = *b"WPR1";

pub const MAX_WEIGHT_PROOF_ANCHOR_LAG: u64 = 8;

pub const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightProof {
    pub node_id: NodeId,

    pub weight: u64,

    pub anchor_block: BlockHash,

    pub receipt_index: u32,

    pub receipt_2718: Vec<u8>,

    pub proof_nodes: Vec<Vec<u8>>,
}

pub type SourceResolver<'a> = dyn Fn(&BlockHash) -> Option<([u8; 32], Height)> + 'a;

impl WeightProof {
    pub fn generate_one(
        node_id: NodeId,
        weight: u64,
        anchor_block: BlockHash,
        source_receipts: &Value,
    ) -> Result<Option<Self>> {
        let receipts = parse_block_receipts(source_receipts)?;
        let Some(idx) = receipts
            .iter()
            .position(|r| receipt_has_log_for(r, &node_id))
        else {
            return Ok(None);
        };

        let encoded: Vec<Vec<u8>> = receipts.iter().map(|r| r.encoded_2718()).collect();
        let proof_nodes = build_receipt_proof(&encoded, idx)?;
        Ok(Some(WeightProof {
            node_id,
            weight,
            anchor_block,
            receipt_index: idx as u32,
            receipt_2718: encoded[idx].clone(),
            proof_nodes,
        }))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WeightProofSet {
    pub proofs: Vec<WeightProof>,
}

impl WeightProofSet {
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn generate(
        weights: &[(NodeId, u64)],
        anchor_block: BlockHash,
        source_receipts: &Value,
    ) -> Result<Self> {
        let mut proofs = Vec::new();
        for &(node_id, weight) in weights {
            if let Some(p) =
                WeightProof::generate_one(node_id, weight, anchor_block, source_receipts)?
            {
                proofs.push(p);
            }
        }
        Ok(Self { proofs })
    }

    pub fn verify_against_recent(
        &self,
        claimed_weights: &[(NodeId, u64)],
        carrier_height: Height,
        resolve: &SourceResolver<'_>,
    ) -> Result<()> {
        for claim in claimed_weights {
            let (node_id, weight) = *claim;

            let Some(p) = self.proofs.iter().find(|p| p.node_id == node_id) else {
                bail!(
                    "weight delta for {} (claimed {}) carries no receipt proof — a forged \
                     weight invented from nothing; refusing to vote (#797)",
                    hex::encode(node_id),
                    weight,
                );
            };
            if p.weight != weight {
                bail!(
                    "weight proof for {} claims weight {} but extra_data carries {}; \
                     refusing to vote (#797)",
                    hex::encode(node_id),
                    p.weight,
                    weight,
                );
            }

            let Some((root, src_height)) = resolve(&p.anchor_block) else {
                bail!(
                    "weight delta for {} (claimed {}) names source block {} the voter does not \
                     hold — a forged or too-far-back anchor; refusing to vote (#797)",
                    hex::encode(node_id),
                    weight,
                    hex::encode(p.anchor_block),
                );
            };

            if src_height.0 >= carrier_height.0
                || carrier_height.0 - src_height.0 > MAX_WEIGHT_PROOF_ANCHOR_LAG
            {
                bail!(
                    "weight delta for {} (claimed {}) anchors to height {} but the carrier is at \
                     {} (window {}); refusing to vote (#797)",
                    hex::encode(node_id),
                    weight,
                    src_height.0,
                    carrier_height.0,
                    MAX_WEIGHT_PROOF_ANCHOR_LAG,
                );
            }

            let logs = verify_one(p, B256::from(root))?;
            check_weight_consistent_with_logs(node_id, weight, &logs)?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&(self.proofs.len() as u32).to_be_bytes());
        for p in &self.proofs {
            out.extend_from_slice(&p.node_id);
            out.extend_from_slice(&p.weight.to_be_bytes());
            out.extend_from_slice(&p.anchor_block);
            out.extend_from_slice(&p.receipt_index.to_be_bytes());
            out.extend_from_slice(&(p.receipt_2718.len() as u32).to_be_bytes());
            out.extend_from_slice(&p.receipt_2718);
            out.extend_from_slice(&(p.proof_nodes.len() as u32).to_be_bytes());
            for node in &p.proof_nodes {
                out.extend_from_slice(&(node.len() as u32).to_be_bytes());
                out.extend_from_slice(node);
            }
        }
        out
    }

    pub fn is_weight_proof_command(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == MAGIC
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        if c.take(4)? != MAGIC {
            return None;
        }
        if c.take(1)?[0] != VERSION {
            return None;
        }
        let count = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
        let mut proofs = Vec::with_capacity(count);
        for _ in 0..count {
            let node_id: NodeId = c.take(32)?.try_into().ok()?;
            let weight = u64::from_be_bytes(c.take(8)?.try_into().ok()?);
            let anchor_block: BlockHash = c.take(32)?.try_into().ok()?;
            let receipt_index = u32::from_be_bytes(c.take(4)?.try_into().ok()?);
            let receipt_len = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
            let receipt_2718 = c.take(receipt_len)?.to_vec();
            let node_count = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
            let mut proof_nodes = Vec::with_capacity(node_count);
            for _ in 0..node_count {
                let node_len = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
                proof_nodes.push(c.take(node_len)?.to_vec());
            }
            proofs.push(WeightProof {
                node_id,
                weight,
                anchor_block,
                receipt_index,
                receipt_2718,
                proof_nodes,
            });
        }
        if !c.is_empty() {
            return None;
        }
        Some(Self { proofs })
    }
}

fn verify_one(p: &WeightProof, root: B256) -> Result<Vec<Log>> {
    let key = receipt_trie_key(p.receipt_index);
    let proof_iter: Vec<AlloyBytes> = p
        .proof_nodes
        .iter()
        .map(|n| AlloyBytes::copy_from_slice(n))
        .collect();
    verify_proof(root, key, Some(p.receipt_2718.clone()), proof_iter.iter()).map_err(|e| {
        anyhow::anyhow!(
            "receipt-trie inclusion proof failed for {} at index {} against the named source's \
             receiptsRoot: {e}; refusing to vote (#797)",
            hex::encode(p.node_id),
            p.receipt_index,
        )
    })?;

    let logs = decode_receipt_logs(&p.receipt_2718)?;
    let node_logs: Vec<Log> = logs
        .into_iter()
        .filter(|l| log_is_for(l, &p.node_id))
        .collect();
    if node_logs.is_empty() {
        bail!(
            "proven receipt for {} carries no staking/slashing log for that node; \
             refusing to vote (#797)",
            hex::encode(p.node_id),
        );
    }
    Ok(node_logs)
}

fn check_weight_consistent_with_logs(node_id: NodeId, weight: u64, logs: &[Log]) -> Result<()> {
    let mut deposit_sum: u128 = 0;
    let mut has_withdraw = false;
    let mut has_slash = false;
    for log in logs {
        match classify_log(log) {
            Some(LogKind::Deposit(amount)) => deposit_sum += amount as u128,
            Some(LogKind::Withdraw) => has_withdraw = true,
            Some(LogKind::Slashed) => has_slash = true,
            None => {}
        }
    }

    if has_slash {
        if weight != 0 {
            bail!(
                "weight proof for {}: a proven Slashed pins the seated weight to 0, but \
                 extra_data claims {}; refusing to vote (#797)",
                hex::encode(node_id),
                weight,
            );
        }
        return Ok(());
    }

    if has_withdraw {
        return Ok(());
    }

    if deposit_sum == 0 {
        return Ok(());
    }
    if (weight as u128) < deposit_sum {
        bail!(
            "weight proof for {}: proven deposits total {} but extra_data claims a smaller \
             seated weight {}; refusing to vote (#797)",
            hex::encode(node_id),
            deposit_sum,
            weight,
        );
    }
    Ok(())
}

fn receipt_trie_key(index: u32) -> Nibbles {
    let buf = alloy_rlp::encode_fixed_size(&(index as usize));
    Nibbles::unpack(&buf)
}

fn build_receipt_proof(encoded: &[Vec<u8>], target_index: usize) -> Result<Vec<Vec<u8>>> {
    let len = encoded.len();
    if target_index >= len {
        bail!("receipt index {target_index} out of range ({len} receipts)");
    }
    let target_key = receipt_trie_key(target_index as u32);
    let retainer = ProofRetainer::new(vec![target_key]);
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);

    for i in 0..len {
        let index = adjust_index_for_rlp(i, len);
        let key = receipt_trie_key(index as u32);
        hb.add_leaf(key, &encoded[index]);
    }
    let _root = hb.root();
    let proof_nodes = hb.take_proof_nodes();

    let nodes: Vec<Vec<u8>> = proof_nodes
        .matching_nodes_sorted(&target_key)
        .into_iter()
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    if nodes.is_empty() {
        bail!("failed to retain a receipt-inclusion proof for index {target_index}");
    }
    Ok(nodes)
}

fn parse_block_receipts(receipts: &Value) -> Result<Vec<ReceiptEnvelope>> {
    let arr = receipts
        .as_array()
        .context("eth_getBlockReceipts did not return an array")?;
    arr.iter().map(parse_one_receipt).collect()
}

fn parse_one_receipt(r: &Value) -> Result<ReceiptEnvelope> {
    let tx_type = match r["type"].as_str() {
        None => TxType::Legacy,
        Some(s) => match u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0) {
            0 => TxType::Legacy,
            1 => TxType::Eip2930,
            2 => TxType::Eip1559,
            3 => TxType::Eip4844,
            4 => TxType::Eip7702,
            other => bail!("unknown receipt tx type {other}"),
        },
    };
    let success = match r["status"].as_str() {
        Some(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0) != 0,

        None => true,
    };
    let cumulative_gas_used = r["cumulativeGasUsed"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .context("receipt cumulativeGasUsed")?;

    let mut logs = Vec::new();
    if let Some(log_arr) = r["logs"].as_array() {
        for l in log_arr {
            logs.push(parse_one_log(l)?);
        }
    }

    let receipt = Receipt {
        status: Eip658Value::Eip658(success),
        cumulative_gas_used,
        logs,
    };
    Ok(ReceiptEnvelope::from_typed(tx_type, receipt.with_bloom()))
}

fn parse_one_log(l: &Value) -> Result<Log> {
    let address = parse_address(l["address"].as_str().context("log address")?)?;
    let topics: Vec<B256> = l["topics"]
        .as_array()
        .context("log topics")?
        .iter()
        .map(|t| {
            let bytes = crate::engine::root_from_hex(t.as_str().context("topic hex")?)?;
            Ok(B256::from(bytes))
        })
        .collect::<Result<_>>()?;
    let data = l["data"].as_str().unwrap_or("0x");
    let data_bytes = hex::decode(data.trim_start_matches("0x")).context("log data hex")?;
    let log_data = LogData::new(topics, AlloyBytes::from(data_bytes))
        .context("log has more than the max topics")?;
    Ok(Log {
        address,
        data: log_data,
    })
}

fn parse_address(s: &str) -> Result<alloy_primitives::Address> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("address hex")?;
    let arr: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("address is not 20 bytes"))?;
    Ok(alloy_primitives::Address::from(arr))
}

fn decode_receipt_logs(receipt_2718: &[u8]) -> Result<Vec<Log>> {
    let mut slice = receipt_2718;
    let env = ReceiptEnvelope::decode_2718(&mut slice)
        .map_err(|e| anyhow::anyhow!("decoding proven receipt: {e}"))?;
    let logs = match &env {
        ReceiptEnvelope::Legacy(r)
        | ReceiptEnvelope::Eip2930(r)
        | ReceiptEnvelope::Eip1559(r)
        | ReceiptEnvelope::Eip4844(r)
        | ReceiptEnvelope::Eip7702(r) => r.receipt.logs.clone(),
    };
    Ok(logs)
}

fn log_is_for(log: &Log, node_id: &NodeId) -> bool {
    classify_log(log).is_some() && log_node_id(log) == Some(*node_id)
}

fn log_node_id(log: &Log) -> Option<NodeId> {
    log.data.topics().get(1).map(|t| t.0)
}

enum LogKind {
    Deposit(u64),
    Withdraw,
    Slashed,
}

fn classify_log(log: &Log) -> Option<LogKind> {
    let topic0 = log.data.topics().first()?;
    let topic0_hex = format!("0x{}", hex::encode(topic0.0));
    let addr_hex = format!("0x{}", hex::encode(log.address.0.0));
    let is_staking = addr_hex.eq_ignore_ascii_case(staking::STAKING_ADDRESS);
    let is_slashing = addr_hex.eq_ignore_ascii_case(slashing::SLASHING_ADDRESS);

    if is_staking && topic0_hex.eq_ignore_ascii_case(staking::DEPOSIT_TOPIC) {
        Some(LogKind::Deposit(data_word_to_u64(&log.data.data)))
    } else if is_staking && topic0_hex.eq_ignore_ascii_case(staking::WITHDRAW_TOPIC) {
        Some(LogKind::Withdraw)
    } else if is_slashing && topic0_hex.eq_ignore_ascii_case(slashing::SLASHED_TOPIC) {
        Some(LogKind::Slashed)
    } else {
        None
    }
}

fn receipt_has_log_for(r: &ReceiptEnvelope, node_id: &NodeId) -> bool {
    let logs = match r {
        ReceiptEnvelope::Legacy(rr)
        | ReceiptEnvelope::Eip2930(rr)
        | ReceiptEnvelope::Eip1559(rr)
        | ReceiptEnvelope::Eip4844(rr)
        | ReceiptEnvelope::Eip7702(rr) => &rr.receipt.logs,
    };
    logs.iter().any(|l| log_is_for(l, node_id))
}

fn data_word_to_u64(data: &[u8]) -> u64 {
    if data.len() < 8 {
        let mut buf = [0u8; 8];
        buf[8 - data.len()..].copy_from_slice(data);
        return u64::from_be_bytes(buf);
    }

    let split = data.len() - 8;
    if data[..split].iter().any(|&b| b != 0) {
        return u64::MAX;
    }
    u64::from_be_bytes(data[split..].try_into().unwrap())
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
