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

    /// Per-validator **current** voting weight (#732 step 4) — the EVM-readable
    /// mirror of the validator's currently-seated consensus weight. `0` means
    /// not seated / removed. Unlike the key history above (a *historical*
    /// `keyAt(validator, view)` the slashing precompile reads for settled past
    /// views), weight is modelled as a single current value: the consumers
    /// (#729's stake-weighted governance tally, #746's param-update auth) need
    /// the **currently seated** weight, never a per-view lookup.
    mapping(bytes32 => uint64) private weight;

    /// Running sum of every seated validator's [`weight`], maintained by
    /// [`recordWeight`] so a consumer can derive a quorum threshold
    /// (e.g. ⌊2·totalWeight/3⌋ + 1) without enumerating the validator set.
    uint64 public totalWeight;

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

    /// `validator`'s current weight was set to `newWeight` (the prior value was
    /// `oldWeight`); `totalWeight` moved by `newWeight - oldWeight`.
    event WeightRecorded(bytes32 indexed validator, uint64 oldWeight, uint64 newWeight);

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

    /// Set `validator`'s **current** seated weight to `newWeight`, overwriting
    /// any prior value, and adjust [`totalWeight`] by the delta (old → new).
    /// `newWeight == 0` removes the validator (its share leaves `totalWeight`).
    ///
    /// **Access-controlled:** only [`WRITER`] (boule's system account) may
    /// record weights — the same gate as [`recordKey`]. The proposer signs a
    /// `recordWeight` tx from that account whenever consensus seats a new
    /// weight for a validator (#732 step 4), so no other caller can skew the
    /// on-chain weight surface #729/#746 read. A no-op same-weight write is
    /// harmless (it emits and leaves `totalWeight` unchanged); the proposer
    /// skips it, but the contract does not reject it.
    function recordWeight(bytes32 validator, uint64 newWeight) external {
        require(msg.sender == WRITER, "unauthorized");
        uint64 oldWeight = weight[validator];
        weight[validator] = newWeight;
        // totalWeight += newWeight - oldWeight, in two non-overflowing steps so
        // the running sum stays exact whether the weight rose or fell.
        totalWeight = totalWeight - oldWeight + newWeight;
        emit WeightRecorded(validator, oldWeight, newWeight);
    }

    /// `validator`'s current seated weight (`0` if unseated / removed) — the
    /// value #729's tally and #746's auth read.
    function weightOf(bytes32 validator) external view returns (uint64) {
        return weight[validator];
    }
}
