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
///
/// ## Authorization (#821)
///
/// `withdraw` emits a `Withdraw(nodeId, amount)` event that boule reads back
/// and applies as a `StakeOp::Unbond` against that validator's bonded stake —
/// draining it to zero **removes the validator from the active set**. An
/// unauthenticated `withdraw` is therefore an open-internet validator-removal
/// vector: any caller (gas funded by the public faucet, #806) could remove any
/// validator. For a trusted-set testnet, unbonding is a privileged governance
/// action, not self-service, so `withdraw` is gated behind a single
/// genesis-seeded [`owner`] — mirroring the `Registry` predeploy's
/// `onlyWriter` gate (`Registry.sol`). Only the owner can emit a `Withdraw`,
/// so only the owner can drive an unbond/removal; every other caller reverts
/// and no event is emitted, so boule never sees the spoofed unbond.
///
/// `deposit` is intentionally left open: it is additive-only — it costs the
/// caller real `msg.value` and can only *increase* a validator's bonded
/// weight, never remove one — so it is not a removal vector and self-service
/// staking is a feature, not a risk. Anyone funding a validator's stake is
/// harmless; only unbonding is gated.
contract Staking {
    /// The privileged address allowed to call [`withdraw`]. Set once at genesis
    /// (seeded directly into this slot's `alloc` storage by the deployment
    /// genesis builder — `src/genesis.rs`), never mutated on-chain. A fresh
    /// chain that does not seed it has `owner == address(0)`, which no caller
    /// can match, so `withdraw` is fully disabled until an owner is seeded
    /// (fails closed).
    ///
    /// A plain **storage** variable, not `immutable`: genesis predeploys are
    /// installed via their `bin-runtime` (no constructor runs at genesis), so
    /// the value must be seeded into `alloc[Staking].storage`. Declared as the
    /// only state variable so it occupies storage **slot 0**, the slot the
    /// genesis seeder writes (`src/genesis.rs`, `src/staking.rs`
    /// `OWNER_SLOT`). The 20-byte address is right-aligned in the 32-byte word,
    /// matching Solidity's `address` storage encoding.
    address public owner;

    /// Bond `amount` (= `msg.value`, in wei) of stake to `nodeId`.
    event Deposit(bytes32 indexed nodeId, uint256 amount);
    /// Unbond `amount` of stake from `nodeId`.
    event Withdraw(bytes32 indexed nodeId, uint256 amount);

    /// Reverts unless the caller is the genesis-seeded [`owner`] — the sole
    /// address allowed to drive an unbond. Any other sender reverts, so the
    /// `Withdraw` event boule reads can only originate from the trusted owner.
    modifier onlyOwner() {
        require(msg.sender == owner, "unauthorized");
        _;
    }

    /// Bond `msg.value` of stake to `nodeId`. Open to anyone: additive-only, so
    /// not a removal vector (see contract-level note).
    function deposit(bytes32 nodeId) external payable {
        emit Deposit(nodeId, msg.value);
    }

    /// Unbond `amount` of stake from `nodeId`. **Access-controlled
    /// ([`onlyOwner`]):** only the genesis-seeded owner may emit a `Withdraw`,
    /// because boule applies it as a validator-set-shrinking unbond (#821).
    function withdraw(bytes32 nodeId, uint256 amount) external onlyOwner {
        emit Withdraw(nodeId, amount);
    }
}
