// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Validator BLS-key registry (#732a) — the EVM-readable mirror of boule's
/// per-validator BLS key history.
///
/// boule's authoritative key history lives consensus-side (`BlsKeyHistory`);
/// this contract materialises it into EVM **storage** so an in-EVM slashing
/// precompile (#732b) can look up *which BLS key a validator signed under at a
/// past view* (`keyAt`) — the settled, lag-free read the design
/// (`docs/validator-registry-and-slashing.md`) relies on. It is a **mirror**:
/// consensus stays authoritative; nothing here drives the validator set.
///
/// `key` is the validator's BLS12-381 G1 pubkey in the **128-byte EIP-2537
/// uncompressed** form the slashing predeploy (`Slashing.sol`) requires
/// (`key.length == 128`). `vEff` is the consensus view from which that key is
/// active.
contract Registry {
    struct KeyEntry {
        uint64 vEff;
        bytes key;
    }

    mapping(bytes32 => KeyEntry[]) private history;

    /// The only account allowed to call [`recordKey`]: boule's **system
    /// account** (`SYSTEM_ACCOUNT_ADDRESS` in `src/system_account.rs`). The
    /// proposer signs every legitimate `recordKey` tx from this address (#756),
    /// so gating on `msg.sender == WRITER` makes the registry a trustworthy
    /// slashing key-source: no other account can pollute a validator's key
    /// history (which could otherwise block a legitimate slash). Genesis-seeded
    /// keys are written directly into `alloc` storage, not via `recordKey`, so
    /// they are unaffected by this gate.
    address constant WRITER = 0x2Ae00C96484267e0ed8937426F497404A93aB526;

    /// A validator's BLS key became active from `vEff`.
    event KeyRecorded(bytes32 indexed validator, uint64 vEff, bytes key);

    /// Record `key` as `validator`'s BLS pubkey active from view `vEff`.
    /// Append-only; `vEff` must strictly exceed the validator's last entry, so
    /// each validator's history is a monotone `(vEff, key)` list — the same
    /// shape as the consensus `BlsKeyHistory` it mirrors.
    ///
    /// **Access-controlled:** only [`WRITER`] (boule's system account) may
    /// record keys. The proposer signs `recordKey` txs from that account on
    /// commit (#756); any other sender reverts. This keeps the registry a
    /// trustworthy slashing key-source — the keys it holds came from boule's
    /// authoritative consensus path, not an arbitrary caller.
    function recordKey(bytes32 validator, uint64 vEff, bytes calldata key) external {
        require(msg.sender == WRITER, "unauthorized");
        KeyEntry[] storage h = history[validator];
        require(h.length == 0 || vEff > h[h.length - 1].vEff, "vEff not increasing");
        h.push(KeyEntry(vEff, key));
        emit KeyRecorded(validator, vEff, key);
    }

    /// The BLS pubkey active at `viewNum`: the entry with the greatest
    /// `vEff <= viewNum`, or empty bytes if the validator has no entry at or
    /// before `viewNum`.
    function keyAt(bytes32 validator, uint64 viewNum) external view returns (bytes memory) {
        KeyEntry[] storage h = history[validator];
        for (uint256 i = h.length; i > 0; i--) {
            if (h[i - 1].vEff <= viewNum) {
                return h[i - 1].key;
            }
        }
        return "";
    }

    /// The number of key entries recorded for `validator`.
    function historyLength(bytes32 validator) external view returns (uint256) {
        return history[validator].length;
    }
}
