// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal validator-staking interface for the boule reth backend (#655).
///
/// Users stake or unstake by calling this contract with normal EVM
/// transactions; boule reads the emitted events from each committed block
/// (via `eth_getLogs`) and drives its validator set from them. The
/// authoritative stake balance lives consensus-side (boule's
/// `BondedStakeLedger`, #654), so this contract is a pure event emitter —
/// the EVM-native *interface*, not the source of truth.
///
/// `nodeId` is the validator's 32-byte boule NodeId (its genesis Ed25519
/// public key). Deployed as a genesis predeploy at a fixed address.
contract Staking {
    /// Bond `amount` (= `msg.value`, in wei) of stake to `nodeId`.
    event Deposit(bytes32 indexed nodeId, uint256 amount);
    /// Unbond `amount` of stake from `nodeId`.
    event Withdraw(bytes32 indexed nodeId, uint256 amount);

    /// Bond `msg.value` of stake to `nodeId`.
    function deposit(bytes32 nodeId) external payable {
        emit Deposit(nodeId, msg.value);
    }

    /// Unbond `amount` of stake from `nodeId`. (Authorization that the
    /// caller owns the stake is a follow-up; the MVP trusts the event and
    /// lets boule's ledger saturate at zero.)
    function withdraw(bytes32 nodeId, uint256 amount) external {
        emit Withdraw(nodeId, amount);
    }
}
