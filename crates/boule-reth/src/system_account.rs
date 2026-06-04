//! The **system account** boule uses to author system EVM transactions (#732).
//!
//! The #732 registry write path (Option A) has boule itself write the on-chain
//! `Registry` from the authoritative consensus key: when consensus accepts a
//! validator rotation it must get a `Registry.recordKey(...)` call *executed*
//! in EVM state. That requires putting a **signed EVM transaction** into reth's
//! pool — a capability the reth backend did not have (its transport only spoke
//! the Engine API plus a read-only `eth_*` RPC). This module is that capability:
//! a fixed secp256k1 account, a signer for it, and a helper that builds a signed
//! EIP-1559 transaction calling `(to, calldata)` ready for
//! [`crate::transport::EngineTransport::send_raw_transaction`].
//!
//! # MVP key caveat — read this
//!
//! [`SYSTEM_ACCOUNT_PRIVATE_KEY`] is a **fixed, well-known development key**,
//! committed in the clear. This is acceptable *only* as an MVP of the
//! submission plumbing: anyone can author "system" txs with it, and on a real
//! deployment it would let anyone forge registry writes. Real key custody
//! (per-deployment key, HSM/keystore, derive-from-node-identity) **and**
//! contract-side access control (`onlyAuthor`-style gating of `recordKey`) are
//! explicit follow-up steps and are *not* in this PR. The genesis funds this
//! address so it can pay gas; that funding is likewise MVP-only.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result};

/// The system account's fixed MVP secp256k1 private key (32 bytes, hex).
///
/// **Development key — see the module-level MVP caveat.** Distinct from the dev
/// faucet (`0xf39Fd6…`). Derives to [`SYSTEM_ACCOUNT_ADDRESS`].
pub const SYSTEM_ACCOUNT_PRIVATE_KEY: &str =
    "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";

/// The system account's EVM address (the `from` of every system tx), derived
/// from [`SYSTEM_ACCOUNT_PRIVATE_KEY`]. Pinned to genesis funding by the test
/// below and to the key by [`signer`].
pub const SYSTEM_ACCOUNT_ADDRESS: &str = "0x2Ae00C96484267e0ed8937426F497404A93aB526";

/// Default gas limit for a system call. `Registry.recordKey` (a single dynamic
/// array append with a `bytes` write) is well under this; generous headroom is
/// fine because reth refunds unused gas and the system account is funded.
pub const SYSTEM_TX_GAS_LIMIT: u64 = 500_000;

/// Default EIP-1559 max priority fee (tip), 1 gwei.
pub const SYSTEM_TX_MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;

/// Default EIP-1559 max fee per gas, 2 gwei. The genesis `baseFeePerGas` is
/// 1 gwei and `--dev` keeps it low, so this comfortably covers base fee + tip.
pub const SYSTEM_TX_MAX_FEE_PER_GAS: u128 = 2_000_000_000;

/// The [`PrivateKeySigner`] for the system account, parsed from
/// [`SYSTEM_ACCOUNT_PRIVATE_KEY`].
pub fn signer() -> PrivateKeySigner {
    SYSTEM_ACCOUNT_PRIVATE_KEY
        .parse()
        .expect("SYSTEM_ACCOUNT_PRIVATE_KEY is a valid 32-byte secp256k1 key")
}

/// The system account's address as an alloy [`Address`].
pub fn address() -> Address {
    SYSTEM_ACCOUNT_ADDRESS
        .parse()
        .expect("SYSTEM_ACCOUNT_ADDRESS is a valid 20-byte address")
}

/// Build and sign an EIP-1559 system transaction calling `(to, calldata)` from
/// the system account, returning the raw EIP-2718 RLP bytes ready for
/// [`crate::transport::EngineTransport::send_raw_transaction`].
///
/// The caller supplies `nonce` (the system account's pending nonce, fetched via
/// the transport) and `chain_id` (the EVM chain id). Gas limit and fees use the
/// `SYSTEM_TX_*` defaults. `value` is zero — system calls move no ether.
pub fn build_system_call(chain_id: u64, nonce: u64, to: Address, calldata: Bytes) -> Result<Bytes> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: SYSTEM_TX_GAS_LIMIT,
        max_fee_per_gas: SYSTEM_TX_MAX_FEE_PER_GAS,
        max_priority_fee_per_gas: SYSTEM_TX_MAX_PRIORITY_FEE_PER_GAS,
        to: TxKind::Call(to),
        value: U256::ZERO,
        access_list: Default::default(),
        input: calldata,
    };
    let signer = signer();
    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .context("signing system tx with the system account key")?;
    let envelope: TxEnvelope = tx.into_signed(signature).into();
    Ok(Bytes::from(envelope.encoded_2718()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_eips::eip2718::Decodable2718;

    /// The committed address constant must be exactly what the committed private
    /// key derives to — so the genesis funding (pinned below) and any future
    /// access-control gate name the *same* account the signer produces.
    #[test]
    fn address_constant_matches_private_key() {
        assert_eq!(signer().address(), address());
    }

    /// The system account must be funded with a non-zero balance in
    /// `genesis.json` (so it can pay gas for system txs), at exactly
    /// [`SYSTEM_ACCOUNT_ADDRESS`]. Mirrors the predeploy genesis-pin tests in
    /// `registry.rs` / `staking.rs`, but asserts a non-zero `balance` rather
    /// than `code`.
    #[test]
    fn system_account_funded_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let balance = g["alloc"][SYSTEM_ACCOUNT_ADDRESS]["balance"]
            .as_str()
            .expect("the system account is funded in genesis at SYSTEM_ACCOUNT_ADDRESS");
        let value = U256::from_str_radix(balance.trim_start_matches("0x"), 16)
            .expect("balance is a hex quantity");
        assert!(
            !value.is_zero(),
            "system account must have a non-zero balance to pay gas",
        );
    }

    /// A built system tx must be a well-formed signed EIP-1559 tx whose
    /// recovered sender is the system account and whose `to`/`input`/`chainId`
    /// are exactly what was requested.
    #[test]
    fn build_system_call_is_well_formed_and_recovers_system_sender() {
        let to: Address = "0x0000000000000000000000000000000000000b12"
            .parse()
            .unwrap();
        let calldata = Bytes::from(vec![0x82, 0x4b, 0x98, 0x02, 0xab, 0xcd]);
        let raw = build_system_call(1337, 7, to, calldata.clone()).unwrap();

        // Decode the raw EIP-2718 bytes back into an envelope.
        let envelope = TxEnvelope::decode_2718(&mut raw.as_ref()).expect("decodes as a typed tx");
        let recovered = envelope.recover_signer().expect("recovers a sender");
        assert_eq!(recovered, address(), "sender is the system account");

        let tx = match &envelope {
            TxEnvelope::Eip1559(signed) => signed.tx(),
            other => panic!("expected an EIP-1559 tx, got {other:?}"),
        };
        assert_eq!(tx.chain_id, 1337);
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.to, TxKind::Call(to));
        assert_eq!(tx.input, calldata);
        assert_eq!(tx.value, U256::ZERO);
        assert_eq!(tx.gas_limit, SYSTEM_TX_GAS_LIMIT);
    }
}
