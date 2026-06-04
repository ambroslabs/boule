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
/// `key` is the validator's 48-byte BLS12-381 G1 pubkey (boule's `min-pk`
/// variant). `vEff` is the consensus view from which that key is active.
contract Registry {
    struct KeyEntry {
        uint64 vEff;
        bytes key;
    }

    mapping(bytes32 => KeyEntry[]) private history;

    /// A validator's BLS key became active from `vEff`.
    event KeyRecorded(bytes32 indexed validator, uint64 vEff, bytes key);

    /// Record `key` as `validator`'s BLS pubkey active from view `vEff`.
    /// Append-only; `vEff` must strictly exceed the validator's last entry, so
    /// each validator's history is a monotone `(vEff, key)` list — the same
    /// shape as the consensus `BlsKeyHistory` it mirrors.
    ///
    /// **MVP caveat — writes are unauthenticated.** The caller is trusted, the
    /// same follow-up `Staking.withdraw` carries. Hardening (#732): verify the
    /// rotation's dual BLS signature via the EIP-2537 precompiles before
    /// recording, so the registry holds only keys from validator-authorised
    /// rotations and cannot be polluted to block a legitimate slash. The
    /// slashing precompile only reads *settled* past views, which bounds the
    /// exposure until that lands.
    function recordKey(bytes32 validator, uint64 vEff, bytes calldata key) external {
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
