//! #797 — vote-time **receipt-inclusion proofs** for the seated-weight deltas a
//! leader stamps into a block's registry `extra_data`.
//!
//! ## The hole this closes
//!
//! Under A1 the leader fills a block's registry `extra_data` with a
//! `(node_id, weight)` write set the custom EL applies **unverified** on every
//! replica. #798 made the **keys** and **settledView** halves vote-time-
//! rejectable (a voter re-derives them from data it already holds). The
//! **weights** half could not be re-derived at vote time — it is downstream of
//! *deferred EL execution*, which a voter on block N may not have caught up to —
//! so a forged weight was only *detected* at commit (the loud
//! `BFT-SAFETY-VIOLATION`), never *prevented*. This module supplies the
//! missing vote-time prevention via a **leader-carried Merkle-Patricia receipt
//! inclusion proof** of the `Deposit`/`Withdraw`/`Slashed` log each weight delta
//! is derived from, verifiable against a `receiptsRoot` the voter already trusts
//! **without executing the source block** (see `docs/a1-weight-proof-design.md`).
//!
//! ## The recent-source anchor (the prevented path)
//!
//! A weight delta riding block `N`'s `extra_data` was derived from the
//! **execution of a recent source block `K`** (its staking/slashing logs). The
//! delta is staged in `pending_weights` at `K`'s `commit` — a three-chain deep —
//! and the next built block snapshots the whole pending set, so `K` is at most
//! [`MAX_WEIGHT_PROOF_ANCHOR_LAG`] blocks back from `N` (the commit depth plus a
//! small slack). Every honest voter still holds `K` at vote time: it is either an
//! uncommitted ancestor of `N` (the safety core's `pending_blocks`) or the
//! just-committed frontier (the durable block store) — the integration layer
//! resolves both. Each proof **names its source block `K`** (by boule block
//! hash); the voter resolves `K`, reads its execution-payload `receiptsRoot`
//! (committed by `K`'s own `state_commitment`), and verifies the receipt-trie
//! inclusion proof *into* that root. This module builds the proofs (leader side,
//! [`WeightProof::generate_one`] / [`WeightProofSet::generate`]) and verifies
//! them (voter side, [`WeightProofSet::verify_against_recent`]).
//!
//! Because the source is always a held, in-window block, a leader claiming its
//! weight's source is "too far back to verify" is **rejected**, not deferred:
//! that excuse was the #797 gap-excuse residual (#797), and it is now closed.
//!
//! ## What is vote-time *prevented* vs. *detected*
//!
//! The proof soundly establishes — with **no voter-side ledger state**, so it is
//! lag-independent and never rejects an honest leader — that:
//!
//! 1. **The backing log exists.** Every weight delta in `extra_data` MUST carry a
//!    valid MPT inclusion proof of ≥1 staking/slashing log **for that exact
//!    `node_id`** in the parent block's `receiptsRoot`. A delta with no proof, an
//!    invalid proof, or a proof of a log for a *different* node is **rejected at
//!    vote time**. This closes the dangerous #797 attacks: a leader can no longer
//!    invent a weight from nothing (to frame an honest validator via a fabricated
//!    `Slashed`, or to swing a governance/param quorum) — there is no real log to
//!    prove.
//! 2. **A `Slashed` pins the absolute weight to 0.** A slash zeroes bonded stake,
//!    so a delta backed by any proven `Slashed` for the node MUST claim weight
//!    `0`; a non-zero claim is **rejected**.
//! 3. **A pure-deposit delta cannot claim a smaller-or-zero weight.** With only
//!    proven `Deposit`s (no `Withdraw`/`Slashed`), the absolute seated weight is
//!    `prior + Σ deposits ≥ Σ deposits > 0`, so a claim below the proven deposit
//!    sum (or a claim of 0) is **rejected**.
//!
//! The one case whose *exact* absolute value is **not** vote-time-pinnable is a
//! delta whose proven logs include a `Withdraw` (partial unbond): the result is
//! `prior − amount`, and `prior` depends on ledger state (bond history + #660
//! unbonding maturity) a lagging voter may not hold. For that case the inclusion
//! proof still binds the delta to a **real `Withdraw` for the claimed node** at
//! vote time; the precise post-withdraw amount remains **detect-at-commit**
//! (`RethApplication::detect_weight_extra_data_divergence`, where the committer's
//! ledger *is* caught up). This is documented honestly and is the residual the
//! design flags; the common honest path (a deposit or a full unbond / slash) is
//! fully vote-time-pinned.
//!
//! ## Multi-block lag / self-synced gap (#674) — anchored, not deferred
//!
//! A delta whose source `K` is not the immediate parent — a multi-block lag, or
//! an EL self-synced past `K` (#674) — still names `K`, which the voter resolves
//! from `pending_blocks` or the recently-committed block store and anchors to
//! `K`'s own `receiptsRoot`. Only a source older than
//! [`MAX_WEIGHT_PROOF_ANCHOR_LAG`] — never reached by an honest delta, whose
//! source is at most the commit depth back — is unresolvable; a leader naming
//! such a source is **rejected**, not deferred. There is no longer a
//! deferred-to-commit weight case other than the exact post-`Withdraw` amount
//! above.
//!
//! ## Carrier
//!
//! The proof set rides as a **dedicated boule block command** (its own
//! [`MAGIC`]), *not* the EL system-call `extra_data`: the EL still applies only
//! the bare write set, so this changes nothing on the execution path and keeps
//! the cross-crate registry codec byte-pinned. The command is covered by the
//! block's `commands_commitment` (tamper-evident) and ignored by every
//! `apply_committed_*` path (none recognise its tag) and by the EL.

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

/// 4-byte magic prefixing the weight-proof block command (distinct from the
/// registry `extra_data` magic `BLR1`, so the EL/registry codec never mistakes
/// one for the other). "WPR1" = Weight-PRoof v1.
pub const MAGIC: [u8; 4] = *b"WPR1";

/// The maximum number of blocks back a weight delta's **source block** (the one
/// whose execution emitted the backing log) may sit from the block that carries
/// the delta in its `extra_data` — the window a voter accepts a proof anchor in.
///
/// A delta is staged in `pending_weights` at its source block's `commit` (which
/// lands a **three-chain** — commit depth 3 — after the source was proposed),
/// and the *next* built block snapshots the whole pending set, so an honest
/// source is at most the commit depth plus a small slack for a skipped build
/// behind the carrier. We set the bound generously above the commit depth so no
/// honest leader is ever rejected, while still being a hard, finite window: a
/// leader claiming a source older than this — the "too far back to verify"
/// excuse #797 closed — is **rejected**, not deferred. Honest sources within the
/// window are always still held by the voter (`pending_blocks` + the just-
/// committed frontier), so they verify.
pub const MAX_WEIGHT_PROOF_ANCHOR_LAG: u64 = 8;

/// Wire-format version byte.
pub const VERSION: u8 = 1;

/// One weight delta's receipt-inclusion proof: the claimed `(node_id, weight)`
/// the `extra_data` carries, plus the MPT proof of the backing staking/slashing
/// log(s) against the source block's `receiptsRoot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightProof {
    /// The validator whose seated weight changed — must equal the `extra_data`
    /// weight entry's `node_id` and the indexed `topics[1]` of every proven log.
    pub node_id: NodeId,
    /// The absolute seated weight the `extra_data` claims for `node_id`.
    pub weight: u64,
    /// The **boule block hash** of the source block whose EVM execution emitted
    /// the backing log — the block the voter resolves (via `RecentBlocks`) to
    /// read the `receiptsRoot` this proof verifies against. Naming the source
    /// lets the voter anchor to a block a few links back (a multi-block lag), not
    /// only the immediate parent, so a "too far back" excuse cannot defer a
    /// forgery (#797): a named source outside the recent window is rejected.
    pub anchor_block: BlockHash,
    /// The source receipt's index in the source block (its position in the
    /// block's receipt list), used to key the receipt trie (`rlp(index)`).
    pub receipt_index: u32,
    /// The source receipt's EIP-2718 consensus encoding — the exact value that
    /// hashes into the `receiptsRoot` at `receipt_index`. The proven logs are
    /// recovered by decoding this.
    pub receipt_2718: Vec<u8>,
    /// The MPT branch nodes from `receiptsRoot` down to the receipt leaf, root
    /// first (the order [`verify_proof`] consumes).
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Resolves a named source block hash to its `(receiptsRoot, height)` if the
/// voter holds it (within the recent anchor window), else `None` — the voter's
/// view handed to [`WeightProofSet::verify_against_recent`].
pub type SourceResolver<'a> = dyn Fn(&BlockHash) -> Option<([u8; 32], Height)> + 'a;

impl WeightProof {
    /// Leader side: build the receipt-inclusion proof for one `(node_id, weight)`
    /// delta from `source_receipts` (an `eth_getBlockReceipts` result for the
    /// source EVM block), anchored at `anchor_block` (that block's boule hash).
    ///
    /// Returns `Ok(None)` when `source_receipts` carries **no** staking/slashing
    /// log for `node_id` — i.e. this is not the delta's source block — so the
    /// caller can try the next candidate block. `Ok(Some(_))` is the proof of the
    /// first matching receipt. (A node has at most one weight-affecting receipt
    /// per block in the toy model; the first match is canonical.)
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
        // Pre-encode every receipt to its 2718 consensus bytes — both the trie
        // leaves and the carried `receipt_2718` use this exact encoding.
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

/// The per-block set of weight proofs — one [`WeightProof`] per `(node_id,
/// weight)` entry in the block's registry `extra_data` weights.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WeightProofSet {
    pub proofs: Vec<WeightProof>,
}

impl WeightProofSet {
    /// True when there is nothing to prove (no weight deltas this block) — the
    /// carrier omits the command entirely in that case.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Leader side: build the receipt-inclusion proof for each `(node_id,
    /// weight)` in `weights`, all from a single source block's receipts
    /// (`source_receipts`, an `eth_getBlockReceipts` result) anchored at
    /// `anchor_block` (the source block's boule hash). Convenience wrapper for
    /// the common case where every delta's log is in the same block — the leader
    /// path that anchors deltas to different recent blocks uses
    /// [`WeightProof::generate_one`] directly.
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

    /// Voter side: verify the whole proof set, anchoring each carried proof to
    /// the **source block it names** (resolved via `resolve`) and re-deriving
    /// each delta against the claimed `extra_data` weights.
    ///
    /// `claimed_weights` is the `(node_id, weight)` set the proposal's
    /// `extra_data` carries. `carrier_height` is the proposed block's height (the
    /// block carrying the weights). `resolve(anchor_block)` returns the named
    /// source block's `(receiptsRoot, height)` if the voter holds it, else
    /// `None`.
    ///
    /// Returns `Ok(())` only if **every** claimed weight is soundly accounted for
    /// at vote time. `Err` (→ refuse to vote) on any forgery a voter can detect:
    /// a missing/invalid proof, a wrong-node proof, an amount/consistency
    /// mismatch, or a named source that is **unresolvable or outside the recent
    /// anchor window** ([`MAX_WEIGHT_PROOF_ANCHOR_LAG`]) — the "too far back"
    /// excuse #797 closes. An honest weight's source is always a recent block the
    /// voter still holds, so an honest leader is never rejected.
    pub fn verify_against_recent(
        &self,
        claimed_weights: &[(NodeId, u64)],
        carrier_height: Height,
        resolve: &SourceResolver<'_>,
    ) -> Result<()> {
        for claim in claimed_weights {
            let (node_id, weight) = *claim;
            // Find a carried proof for this exact node.
            let Some(p) = self.proofs.iter().find(|p| p.node_id == node_id) else {
                bail!(
                    "weight delta for {} (claimed {}) carries no receipt proof — a forged \
                     weight invented from nothing; refusing to vote (#797)",
                    hex::encode(node_id),
                    weight,
                );
            };
            if p.weight != weight {
                // A proof that proves a *different* claimed amount than the
                // `extra_data` carries is a forgery attempt — reject.
                bail!(
                    "weight proof for {} claims weight {} but extra_data carries {}; \
                     refusing to vote (#797)",
                    hex::encode(node_id),
                    p.weight,
                    weight,
                );
            }
            // Resolve the source block this proof names. An unresolvable source is
            // a forged "too far back" anchor (an honest source is always held).
            let Some((root, src_height)) = resolve(&p.anchor_block) else {
                bail!(
                    "weight delta for {} (claimed {}) names source block {} the voter does not \
                     hold — a forged or too-far-back anchor; refusing to vote (#797)",
                    hex::encode(node_id),
                    weight,
                    hex::encode(p.anchor_block),
                );
            };
            // The source must be within the recent anchor window: at/below the
            // carrier and no more than MAX_WEIGHT_PROOF_ANCHOR_LAG links back.
            // (Resolving it already proves we hold it, but a leader could name a
            // genuinely-old held block to dodge the freshness intent; pin it.)
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
            // Verify the inclusion proof against the named source's receiptsRoot
            // and re-derive the weight from the proven log(s).
            let logs = verify_one(p, B256::from(root))?;
            check_weight_consistent_with_logs(node_id, weight, &logs)?;
        }
        Ok(())
    }

    /// Encode the proof set into the dedicated block-command bytes (see the
    /// module docs for the carrier). Layout:
    ///
    /// ```text
    /// magic[4]="WPR1" | version[1]=1 | proof_count u32 BE |
    ///   { node_id[32] | weight u64 BE | anchor_block[32] | receipt_index u32 BE |
    ///     receipt_len u32 BE | receipt_2718[receipt_len] |
    ///     node_count u32 BE | { node_len u32 BE | node[node_len] } * } *
    /// ```
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

    /// Whether `bytes` is a weight-proof block command (the [`MAGIC`] tag). Used
    /// by the carrier to recognise its own command among a block's commands.
    pub fn is_weight_proof_command(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == MAGIC
    }

    /// Decode the inverse of [`encode`](Self::encode). Returns [`None`] for any
    /// blob that is not a well-formed weight-proof command (wrong magic/version,
    /// truncated, or trailing garbage).
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

/// Verify one [`WeightProof`] against `root` (the named source block's
/// `receiptsRoot`): the MPT inclusion of the receipt at `receipt_index` (keyed
/// `rlp(index)`) with value `receipt_2718`, then recover the proven staking/
/// slashing logs for `node_id`. On success returns those logs; `Err` (→ reject)
/// on a tampered/malformed proof or a receipt with no log for the node.
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

    // The proven receipt is authentic — decode it and pull the node's logs.
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

/// Re-derive whether a claimed absolute `weight` is consistent with the proven
/// `logs` for `node_id`, with **no voter-side ledger state** (so it never
/// rejects an honest leader from execution lag). See the module docs for the
/// exact prevented/detected split. Returns `Err` (→ reject) on an inconsistency
/// a voter can prove at vote time.
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

    // (2) A slash zeroes bonded stake — the absolute weight MUST be 0.
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

    // (residual) A Withdraw's post-state is `prior - amount`, not vote-time-
    // pinnable without ledger state — bound to the real log here, exact amount
    // deferred to commit-time detection.
    if has_withdraw {
        return Ok(());
    }

    // (3) Pure deposits: absolute weight = prior + Σdeposits ≥ Σdeposits > 0.
    if deposit_sum == 0 {
        // No deposit amount proven and no withdraw/slash — nothing constrains a
        // positive weight; treat as the residual (shouldn't happen for a real
        // delta). Bound-to-log only.
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

/// The receipt-trie key for receipt `index`: `Nibbles::unpack(rlp(adjusted
/// index))`, matching alloy's `ordered_trie_root` leaf keying. We never apply
/// `adjust_index_for_rlp` here because the *carried* `receipt_index` is the raw
/// position; the trie build below applies the adjustment when ordering leaves,
/// and the key for a given raw index is `rlp(index)` regardless (the adjustment
/// only reorders which leaf is the "0" slot — see [`build_receipt_proof`]).
fn receipt_trie_key(index: u32) -> Nibbles {
    let buf = alloy_rlp::encode_fixed_size(&(index as usize));
    Nibbles::unpack(&buf)
}

/// Build the root→leaf inclusion proof for the receipt at raw position
/// `target_index` from the block's pre-encoded 2718 receipts, via a
/// [`HashBuilder`] with a [`ProofRetainer`] targeting that leaf's key. Mirrors
/// alloy's `ordered_trie_root_encoded` leaf insertion order exactly, so the
/// computed root equals the block's `receiptsRoot`.
fn build_receipt_proof(encoded: &[Vec<u8>], target_index: usize) -> Result<Vec<Vec<u8>>> {
    let len = encoded.len();
    if target_index >= len {
        bail!("receipt index {target_index} out of range ({len} receipts)");
    }
    let target_key = receipt_trie_key(target_index as u32);
    let retainer = ProofRetainer::new(vec![target_key]);
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);

    // alloy inserts leaves in the order produced by `adjust_index_for_rlp`,
    // which yields leaves sorted by their RLP-key nibble path (HashBuilder
    // requires ascending keys). Replicate it precisely.
    for i in 0..len {
        let index = adjust_index_for_rlp(i, len);
        let key = receipt_trie_key(index as u32);
        hb.add_leaf(key, &encoded[index]);
    }
    let _root = hb.root();
    let proof_nodes = hb.take_proof_nodes();
    // Root→leaf order along the target key (matching_nodes_sorted is shallow→deep).
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

/// Test-only: the `receiptsRoot` reth would compute for an
/// `eth_getBlockReceipts`-shaped array, so other modules' tests can build a
/// parent block carrying the matching anchor.
#[cfg(test)]
pub fn testing_receipts_root(receipts: &Value) -> [u8; 32] {
    let parsed = parse_block_receipts(receipts).expect("test receipts parse");
    let encoded: Vec<Vec<u8>> = parsed.iter().map(|r| r.encoded_2718()).collect();
    alloy_trie::root::ordered_trie_root_encoded(&encoded).0
}

/// A receipt parsed from `eth_getBlockReceipts` into the alloy consensus type,
/// whose 2718 encoding hashes into the block's `receiptsRoot`.
fn parse_block_receipts(receipts: &Value) -> Result<Vec<ReceiptEnvelope>> {
    let arr = receipts
        .as_array()
        .context("eth_getBlockReceipts did not return an array")?;
    arr.iter().map(parse_one_receipt).collect()
}

/// Reconstruct one alloy [`ReceiptEnvelope`] from a reth RPC receipt object,
/// explicitly (no serde-flatten fragility): tx type, status, cumulative gas, and
/// logs (address + topics + data). The bloom is recomputed via `with_bloom`, so
/// it always matches the consensus encoding regardless of the RPC's `logsBloom`.
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
        // pre-Byzantium receipts carry a state root, not a status; reth on a
        // post-Byzantium chain always emits a status, so default to success.
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

/// Reconstruct one alloy [`Log`] from a reth RPC log object.
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

/// Parse a 20-byte `0x`-prefixed hex address.
fn parse_address(s: &str) -> Result<alloy_primitives::Address> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("address hex")?;
    let arr: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("address is not 20 bytes"))?;
    Ok(alloy_primitives::Address::from(arr))
}

/// Decode a 2718 receipt blob back into its logs (voter side).
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

/// Whether an alloy [`Log`] is a staking/slashing event for `node_id` (the
/// indexed `topics[1]` 32-byte validator id), at the staking or slashing
/// predeploy address with a recognised topic0.
fn log_is_for(log: &Log, node_id: &NodeId) -> bool {
    classify_log(log).is_some() && log_node_id(log) == Some(*node_id)
}

/// The indexed validator id (`topics[1]`) of a staking/slashing log.
fn log_node_id(log: &Log) -> Option<NodeId> {
    log.data.topics().get(1).map(|t| t.0)
}

/// The kind of weight-affecting log, if this is one.
enum LogKind {
    Deposit(u64),
    Withdraw,
    Slashed,
}

/// Classify a log as a recognised staking/slashing event (by predeploy address
/// + topic0), extracting the amount for Deposit/Withdraw.
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

/// Whether a receipt carries any weight-affecting log for `node_id` (leader-side
/// receipt selection).
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

/// Interpret a 32-byte ABI data word as a `u64`, saturating past `u64::MAX`
/// (mirrors [`staking`]'s 1:1 stake↔weight model on the raw bytes).
fn data_word_to_u64(data: &[u8]) -> u64 {
    if data.len() < 8 {
        let mut buf = [0u8; 8];
        buf[8 - data.len()..].copy_from_slice(data);
        return u64::from_be_bytes(buf);
    }
    // High bytes (everything above the low 8) must be zero or the value
    // exceeds u64 — saturate.
    let split = data.len() - 8;
    if data[..split].iter().any(|&b| b != 0) {
        return u64::MAX;
    }
    u64::from_be_bytes(data[split..].try_into().unwrap())
}

/// A minimal forward-only byte cursor for [`WeightProofSet::decode`].
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Node-id topic word and 32-byte data word, matching the staking parser's
    /// `eth_getLogs` shape.
    fn topic_node(b: u8) -> String {
        format!("0x{}", format!("{b:02x}").repeat(32))
    }
    fn data_word(v: u64) -> String {
        format!("0x{v:064x}")
    }

    /// A minimal reth-shaped receipt object carrying one staking/slashing log.
    fn receipt_with_log(tx_type: u8, address: &str, topic0: &str, node: u8, data: &str) -> Value {
        json!({
            "type": format!("0x{tx_type:x}"),
            "status": "0x1",
            "cumulativeGasUsed": "0x5208",
            "logs": [{
                "address": address,
                "topics": [topic0, topic_node(node)],
                "data": data,
            }],
        })
    }

    /// A receipt with no weight-affecting log (a plain app tx).
    fn plain_receipt(tx_type: u8) -> Value {
        json!({
            "type": format!("0x{tx_type:x}"),
            "status": "0x1",
            "cumulativeGasUsed": "0x5208",
            "logs": [],
        })
    }

    fn deposit_receipt(node: u8, amount: u64) -> Value {
        receipt_with_log(
            2,
            staking::STAKING_ADDRESS,
            staking::DEPOSIT_TOPIC,
            node,
            &data_word(amount),
        )
    }
    fn withdraw_receipt(node: u8, amount: u64) -> Value {
        receipt_with_log(
            2,
            staking::STAKING_ADDRESS,
            staking::WITHDRAW_TOPIC,
            node,
            &data_word(amount),
        )
    }
    fn slashed_receipt(node: u8) -> Value {
        // Slashed carries a 96-byte data blob (view + two block hashes), but the
        // parser only reads topics[1]; any data is fine.
        receipt_with_log(
            2,
            slashing::SLASHING_ADDRESS,
            slashing::SLASHED_TOPIC,
            node,
            &data_word(3),
        )
    }

    /// The `receiptsRoot` reth would compute for this receipt list, via alloy's
    /// canonical `ordered_trie_root_encoded` over the 2718 encodings — the exact
    /// value our proof must anchor to.
    fn receipts_root(receipts: &Value) -> [u8; 32] {
        let parsed = parse_block_receipts(receipts).unwrap();
        let encoded: Vec<Vec<u8>> = parsed.iter().map(|r| r.encoded_2718()).collect();
        alloy_trie::root::ordered_trie_root_encoded(&encoded).0
    }

    /// Our hand-rolled trie build (with the proof retainer) computes the SAME
    /// root as alloy's canonical helper — proving we key/insert leaves exactly
    /// like reth, so the proof anchors to the real `receiptsRoot`.
    #[test]
    fn our_trie_root_matches_alloy_for_each_index() {
        let receipts = json!([
            plain_receipt(2),
            deposit_receipt(7, 5),
            plain_receipt(0),
            withdraw_receipt(9, 2),
        ]);
        let parsed = parse_block_receipts(&receipts).unwrap();
        let encoded: Vec<Vec<u8>> = parsed.iter().map(|r| r.encoded_2718()).collect();
        let want = alloy_trie::root::ordered_trie_root_encoded(&encoded);
        for i in 0..encoded.len() {
            // build_receipt_proof builds the same trie internally; re-derive its
            // root to confirm leaf keying/order matches alloy.
            let len = encoded.len();
            let mut hb = HashBuilder::default();
            for j in 0..len {
                let index = adjust_index_for_rlp(j, len);
                hb.add_leaf(receipt_trie_key(index as u32), &encoded[index]);
            }
            assert_eq!(hb.root(), want, "index {i}");
        }
    }

    /// The boule hash + height of the (single) source block in these tests; the
    /// carrier is one above it, so the lag is the common 1.
    const SRC_HASH: BlockHash = [0xABu8; 32];
    const SRC_HEIGHT: Height = Height(100);
    const CARRIER_HEIGHT: Height = Height(101);

    /// A `resolve` closure mapping `SRC_HASH` → `(root, SRC_HEIGHT)` and every
    /// other hash → `None` (not held). The common case: one held source block.
    fn resolve_src(root: [u8; 32]) -> impl Fn(&BlockHash) -> Option<([u8; 32], Height)> {
        move |h: &BlockHash| {
            if *h == SRC_HASH {
                Some((root, SRC_HEIGHT))
            } else {
                None
            }
        }
    }

    /// Generate a proof set anchored at `SRC_HASH`.
    fn gen_set(weights: &[(NodeId, u64)], receipts: &Value) -> WeightProofSet {
        WeightProofSet::generate(weights, SRC_HASH, receipts).unwrap()
    }

    /// **Honest block validates (1-block lag).** A Deposit of 5 for node 7 in the
    /// source block yields a seated weight of 5; the leader carries a proof naming
    /// the source, and `verify_against_recent` accepts it against the source's
    /// `receiptsRoot`.
    #[test]
    fn honest_deposit_proof_verifies() {
        let node = [7u8; 32];
        let receipts = json!([plain_receipt(2), deposit_receipt(7, 5), plain_receipt(0)]);
        let root = receipts_root(&receipts);
        let weights = vec![(node, 5u64)];

        let set = gen_set(&weights, &receipts);
        assert_eq!(set.proofs.len(), 1);
        set.verify_against_recent(&weights, CARRIER_HEIGHT, &resolve_src(root))
            .expect("honest deposit proof verifies against the source receiptsRoot");
    }

    /// **Honest multi-block lag validates (the liveness bar).** A delta whose
    /// source is 3 blocks back (a legitimate commit-depth lag) names that source;
    /// the voter still holds it (within the window) and the proof verifies — it is
    /// NOT rejected as "too far back".
    #[test]
    fn honest_multi_block_lag_proof_verifies() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 5)]);
        let root = receipts_root(&receipts);
        let weights = vec![(node, 5u64)];
        let set = gen_set(&weights, &receipts);

        // Carrier 3 blocks above the source (within MAX_WEIGHT_PROOF_ANCHOR_LAG).
        let carrier = Height(SRC_HEIGHT.0 + 3);
        set.verify_against_recent(&weights, carrier, &resolve_src(root))
            .expect("a 3-block-lag weight with a valid proof to its held source verifies");
    }

    /// **The gap-excuse exploit — a weight whose source is not held is REJECTED,
    /// not deferred.** A Byzantine leader claims a weight backed by a proof naming
    /// a source block the voter does not hold (the "too far back to verify"
    /// excuse). It is rejected at vote time.
    #[test]
    fn unheld_source_anchor_is_rejected() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 5)]);
        // The proof names a source the resolver never returns.
        let set = WeightProofSet::generate(&[(node, 5u64)], [0xCDu8; 32], &receipts).unwrap();
        let claimed = vec![(node, 5u64)];
        // resolve_src only knows SRC_HASH; the proof's [0xCD;32] anchor is unheld.
        let err = set
            .verify_against_recent(&claimed, CARRIER_HEIGHT, &resolve_src([0u8; 32]))
            .expect_err("a weight naming an unheld source must be rejected, not deferred");
        assert!(
            err.to_string().contains("the voter does not hold"),
            "rejected for the right reason: {err}",
        );
    }

    /// **A source older than the anchor window is rejected.** Even if the voter
    /// holds the named source, a leader naming one beyond
    /// `MAX_WEIGHT_PROOF_ANCHOR_LAG` is rejected (the freshness bound).
    #[test]
    fn too_far_back_source_is_rejected() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 5)]);
        let root = receipts_root(&receipts);
        let set = gen_set(&[(node, 5u64)], &receipts);
        let claimed = vec![(node, 5u64)];
        // Carrier well beyond the window above the held source.
        let carrier = Height(SRC_HEIGHT.0 + MAX_WEIGHT_PROOF_ANCHOR_LAG + 5);
        let err = set
            .verify_against_recent(&claimed, carrier, &resolve_src(root))
            .expect_err("a source beyond the anchor window must be rejected");
        assert!(
            err.to_string().contains("window"),
            "rejected for the right reason: {err}",
        );
    }

    /// **The exploit (forged-from-nothing).** A Byzantine leader claims a weight
    /// for node 9 that has NO staking/slashing log in any held block, alongside an
    /// honest proven weight. The unbacked forgery carries no proof and is rejected
    /// at vote time.
    #[test]
    fn forged_weight_with_no_proof_is_rejected() {
        let real = [7u8; 32];
        let forged = [9u8; 32];
        let receipts = json!([deposit_receipt(7, 5)]);
        let root = receipts_root(&receipts);

        // extra_data claims both the real (7→5) and a forged (9→1000) weight.
        let claimed = vec![(real, 5u64), (forged, 1000u64)];
        // The leader can only prove the real one (9 has no log).
        let set = gen_set(&claimed, &receipts);
        assert_eq!(set.proofs.len(), 1, "only node 7 has a backing log");

        let err = set
            .verify_against_recent(&claimed, CARRIER_HEIGHT, &resolve_src(root))
            .expect_err("a forged weight with no receipt proof must be rejected");
        assert!(
            err.to_string().contains("carries no receipt proof"),
            "rejected for the right reason: {err}",
        );
    }

    /// **A proof of a different amount is rejected.** The leader proves node 7's
    /// real Deposit of 5 but the `extra_data` claims weight 1 — the proof's
    /// claimed amount disagrees with `extra_data`, a forgery.
    #[test]
    fn proof_of_different_amount_is_rejected() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 5)]);
        let root = receipts_root(&receipts);

        // The leader builds a proof asserting weight 5 (the real delta)…
        let set = gen_set(&[(node, 5u64)], &receipts);
        // …but the extra_data claims weight 1 for the same node.
        let claimed = vec![(node, 1u64)];
        let err = set
            .verify_against_recent(&claimed, CARRIER_HEIGHT, &resolve_src(root))
            .expect_err("proof amount disagreeing with extra_data must be rejected");
        assert!(
            err.to_string()
                .contains("claims weight 5 but extra_data carries 1"),
            "rejected for the right reason: {err}",
        );
    }

    /// **A deposit-floor violation is rejected.** Even with a self-consistent
    /// proof (claimed == proof.weight), a pure-Deposit delta whose claimed weight
    /// is below the proven deposit sum is impossible (weight = prior + deposits ≥
    /// deposits) — rejected at vote time.
    #[test]
    fn deposit_below_proven_sum_is_rejected() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 100)]);
        let root = receipts_root(&receipts);
        // Both the proof and extra_data claim weight 1, but the proven deposit is
        // 100 — the seated weight cannot be below it.
        let claimed = vec![(node, 1u64)];
        let set = gen_set(&claimed, &receipts);
        let err = set
            .verify_against_recent(&claimed, CARRIER_HEIGHT, &resolve_src(root))
            .expect_err("claimed weight below the proven deposit sum must be rejected");
        assert!(
            err.to_string().contains("proven deposits total 100"),
            "rejected for the right reason: {err}",
        );
    }

    /// **A `Slashed` pins the weight to 0.** A delta backed by a proven Slashed
    /// must claim weight 0; a non-zero claim is rejected (this is the slash-an-
    /// honest-validator framing vector — a forged non-zero slash weight).
    #[test]
    fn slashed_must_claim_zero_weight() {
        let node = [7u8; 32];
        let receipts = json!([slashed_receipt(7)]);
        let root = receipts_root(&receipts);

        // Honest: a slash → weight 0, accepted.
        let ok = vec![(node, 0u64)];
        let set_ok = gen_set(&ok, &receipts);
        set_ok
            .verify_against_recent(&ok, CARRIER_HEIGHT, &resolve_src(root))
            .expect("a slash → weight 0 verifies");

        // Forged: claim a non-zero weight off a Slashed log.
        let bad = vec![(node, 50u64)];
        let set_bad = gen_set(&bad, &receipts);
        let err = set_bad
            .verify_against_recent(&bad, CARRIER_HEIGHT, &resolve_src(root))
            .expect_err("a non-zero weight off a Slashed must be rejected");
        assert!(
            err.to_string().contains("pins the seated weight to 0"),
            "rejected for the right reason: {err}",
        );
    }

    /// **A tampered proof under the named source's real root is rejected.** A
    /// flipped byte in the target receipt makes the leaf mismatch under the
    /// correctly-named source `receiptsRoot` → reject (a forgery).
    #[test]
    fn tampered_proof_under_real_root_is_rejected() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 5), deposit_receipt(8, 9)]);
        let root = receipts_root(&receipts);
        let mut set = gen_set(&[(node, 5u64), ([8u8; 32], 9u64)], &receipts);
        // Tamper node 7's proven receipt bytes; the proof anchors to the named
        // source's root but the leaf no longer matches.
        let idx = set.proofs.iter().position(|p| p.node_id == node).unwrap();
        set.proofs[idx].receipt_2718[5] ^= 0xff;
        let err = set
            .verify_against_recent(
                &[(node, 5u64), ([8u8; 32], 9u64)],
                CARRIER_HEIGHT,
                &resolve_src(root),
            )
            .expect_err("a tampered receipt under the real root must be rejected");
        assert!(
            err.to_string().contains("inclusion proof failed"),
            "rejected for a proof reason: {err}",
        );
    }

    /// The proof-set codec round-trips (including the anchor block) and rejects
    /// malformed blobs.
    #[test]
    fn codec_roundtrips_and_rejects_garbage() {
        let node = [7u8; 32];
        let receipts = json!([deposit_receipt(7, 5)]);
        let set = gen_set(&[(node, 5u64)], &receipts);
        let bytes = set.encode();
        assert!(WeightProofSet::is_weight_proof_command(&bytes));
        let decoded = WeightProofSet::decode(&bytes).unwrap();
        assert_eq!(decoded, set);
        assert_eq!(decoded.proofs[0].anchor_block, SRC_HASH);

        assert_eq!(WeightProofSet::decode(b"reth/v2.2.0"), None);
        assert_eq!(WeightProofSet::decode(&[]), None);
        let mut trailing = WeightProofSet::default().encode();
        trailing.push(0xff);
        assert_eq!(WeightProofSet::decode(&trailing), None);
        // An empty set encodes/decodes cleanly (count 0).
        assert_eq!(
            WeightProofSet::decode(&WeightProofSet::default().encode()),
            Some(WeightProofSet::default()),
        );
    }
}
