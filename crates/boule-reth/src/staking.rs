//! On-chain identifiers for the validator-staking predeploy (#655).
//!
//! Users stake/unstake by calling the `Staking` contract
//! (`contracts/Staking.sol`), deployed as a genesis predeploy at
//! [`STAKING_ADDRESS`]. boule reads the events it emits from each committed
//! block — filtered by [`DEPOSIT_TOPIC`] / [`WITHDRAW_TOPIC`] — and drives
//! its validator set from them via a [`StakeSource`] (the log-reading path
//! is a follow-up phase).
//!
//! These constants are the authoritative identifiers and match the compiled
//! runtime bytecode embedded in `genesis.json`; the test below pins the
//! address to the genesis account so the two cannot drift.
//!
//! [`StakeSource`]: boule_consensus::replication::stake_source::StakeSource

/// Fixed genesis-predeploy address of the staking contract.
pub const STAKING_ADDRESS: &str = "0x0000000000000000000000000000000000000b0e";

/// `keccak256("Deposit(bytes32,uint256)")` — topic0 of the `Deposit` event,
/// emitted by `deposit(bytes32 nodeId)` with the bonded `amount`.
pub const DEPOSIT_TOPIC: &str =
    "0x98e783c3864bbf744a057ef605a2a61701c3b62b5ed68b3745b99094497daf1f";

/// `keccak256("Withdraw(bytes32,uint256)")` — topic0 of the `Withdraw`
/// event, emitted by `withdraw(bytes32 nodeId, uint256 amount)`.
pub const WITHDRAW_TOPIC: &str =
    "0x4591ca0897d0d8e83f7153dfe0b2912125672084ab8d84be59ee13240a1778bc";

/// 4-byte selector of `deposit(bytes32)`.
pub const DEPOSIT_SELECTOR: [u8; 4] = [0xb2, 0x14, 0xfa, 0xa5];

/// 4-byte selector of `withdraw(bytes32,uint256)`.
pub const WITHDRAW_SELECTOR: [u8; 4] = [0x04, 0x0c, 0xf0, 0x20];

#[cfg(test)]
mod tests {
    use super::*;

    /// The predeploy address the read path will filter logs on must match
    /// the account actually seeded in `genesis.json` with non-empty code —
    /// otherwise boule would watch the wrong address and never see a stake
    /// event. Pins the Rust constant to the on-chain artifact.
    #[test]
    fn staking_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][STAKING_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at STAKING_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(
            code.len() > 2 + 400 * 2,
            "non-trivial contract code (~536 bytes)"
        );
    }
}
