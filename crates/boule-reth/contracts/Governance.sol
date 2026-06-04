// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Governance-reconfiguration approval interface for the boule reth backend
/// (#729, milestone #4). Supersedes the committee-approval half of #548.
///
/// A membership change (a *reconfig*: adding/removing/reweighting validators) is
/// enacted by having the seated validators approve it on-chain. Each validator
/// calls `approve(bytes32 proposalId, bytes reconfigCommand, bytes32 validator)`
/// with an ordinary EVM transaction; the contract accumulates the **on-chain
/// weight** of each distinct approving validator and, once the accumulated weight
/// crosses a supermajority of `totalWeight()`, emits `Approved(proposalId,
/// reconfigCommand)` **exactly once**. boule reads that event from each committed
/// block (via `eth_getLogs`), turns it into a `ValidatorEffect` on the widened
/// `CommitResult` (#727), and re-materialises the carried command into a block —
/// where the existing reconfig path validates and schedules the membership change
/// at a view boundary. This replaces the consensus-side signature-accumulation +
/// bespoke tx-gossip approach: approvals ride the ordinary EVM mempool/gossip
/// instead.
///
/// `proposalId` is an opaque 32-byte identifier of the reconfig — boule sets it
/// to the hash of the encoded reconfig command, so the id binds the vote to one
/// exact command and any approver disagreeing on the command produces a
/// different id (and so a separate tally). `reconfigCommand` is the tagged
/// consensus command bytes; the EVM never interprets it, it is carried only so
/// the `Approved` event can hand the full command back to consensus, which
/// validates it. Deployed as a genesis predeploy at a fixed address.
///
/// ## Stake-weighted, validator-gated tally (#729)
///
/// The tally is **weight-based** and restricted to **seated validators**, read
/// from the `Registry` predeploy's on-chain weight surface (#759). An approver
/// passes the 32-byte `validator` id it is voting as; `approve` staticcalls
/// `Registry.weightOf(validator)` and **requires it to be > 0** (the caller is a
/// seated validator) and `Registry.totalWeight()` for the quorum denominator.
/// The validator's weight is accumulated (deduplicated by validator id, so one
/// validator cannot double-count), and `Approved` is emitted once the running
/// weight crosses a strict two-thirds supermajority: `weight * 3 >
/// totalWeight * 2` (BFT-style, integer-safe, no caller-supplied quorum).
///
/// **Residual trust.** `msg.sender` is an EVM address; the Registry keys weight
/// by the 32-byte consensus validator id, and there is no EVM-address →
/// validator-id mapping on chain today. So the caller names the `validator` it
/// votes as, and a caller *could* vote as a validator whose key it does not
/// control. This exposure is bounded exactly as in the dumb-carrier model: the
/// `Approved` event only carries the reconfig command back to consensus, which
/// re-validates that command before applying it — the contract never drives the
/// validator set. Gating on `weightOf > 0` still keeps non-seated addresses out
/// of the tally entirely.
contract Governance {
    /// Fixed genesis-predeploy address of the `Registry` (#759), holding the
    /// per-validator weight surface this tally reads. Mirrors
    /// `REGISTRY_ADDRESS` in `src/registry.rs`.
    address constant REGISTRY = 0x0000000000000000000000000000000000000B12;
    /// `weightOf(bytes32)` selector — `Registry.weightOf(validator)`, the
    /// current seated weight. Mirrors `WEIGHT_OF_SELECTOR` in `src/registry.rs`.
    bytes4 constant WEIGHT_OF_SELECTOR = 0x4c108d6d;
    /// `totalWeight()` selector — the running seated-weight sum, the quorum
    /// denominator. Mirrors `TOTAL_WEIGHT_SELECTOR` in `src/registry.rs`.
    bytes4 constant TOTAL_WEIGHT_SELECTOR = 0x96c82e57;

    /// Per-proposal tally state.
    struct Proposal {
        uint64 weight; // accumulated weight of distinct approving validators
        bool approved; // `Approved` already emitted (one-shot guard)
    }

    /// proposalId => tally.
    mapping(bytes32 => Proposal) private proposals;
    /// proposalId => validator id => has this validator already approved.
    mapping(bytes32 => mapping(bytes32 => bool)) private voted;

    /// A reconfig crossed the weight supermajority. `reconfigCommand` is the
    /// opaque, tagged boule reconfig command consensus will validate and apply.
    /// Emitted exactly once per `proposalId`.
    event Approved(bytes32 indexed proposalId, bytes reconfigCommand);

    /// Approve the reconfig identified by `proposalId`, voting as the seated
    /// `validator` (its 32-byte consensus id) and carrying the encoded
    /// `reconfigCommand`.
    ///
    /// The caller must be a seated validator: `Registry.weightOf(validator)`
    /// must be `> 0`, else the call reverts. A repeat approval by the same
    /// `validator` is a no-op (it does not double-count its weight). When the
    /// accumulated weight of distinct approving validators first crosses a
    /// strict two-thirds supermajority of `Registry.totalWeight()`
    /// (`weight * 3 > totalWeight * 2`), `Approved(proposalId, reconfigCommand)`
    /// is emitted once; further approvals after that are ignored.
    function approve(bytes32 proposalId, bytes calldata reconfigCommand, bytes32 validator)
        external
    {
        uint64 vWeight = registryWeightOf(validator);
        require(vWeight > 0, "not a seated validator");

        Proposal storage p = proposals[proposalId];
        if (p.approved || voted[proposalId][validator]) {
            return; // already enacted, or this validator already approved
        }
        voted[proposalId][validator] = true;
        p.weight += vWeight;

        // Strict BFT supermajority of the current total seated weight,
        // integer-safe: weight > 2/3 * totalWeight <=> weight*3 > totalWeight*2.
        uint64 total = registryTotalWeight();
        if (uint256(p.weight) * 3 > uint256(total) * 2) {
            p.approved = true;
            emit Approved(proposalId, reconfigCommand);
        }
    }

    /// Accumulated approving weight tallied for `proposalId` so far.
    function approvals(bytes32 proposalId) external view returns (uint64) {
        return proposals[proposalId].weight;
    }

    /// Whether `proposalId` has crossed the supermajority and emitted `Approved`.
    function isApproved(bytes32 proposalId) external view returns (bool) {
        return proposals[proposalId].approved;
    }

    /// `Registry.weightOf(validator)` via staticcall — `validator`'s current
    /// seated weight (`0` if unseated).
    function registryWeightOf(bytes32 validator) internal view returns (uint64) {
        (bool ok, bytes memory ret) =
            REGISTRY.staticcall(abi.encodeWithSelector(WEIGHT_OF_SELECTOR, validator));
        require(ok && ret.length == 32, "registry weightOf failed");
        return uint64(abi.decode(ret, (uint256)));
    }

    /// `Registry.totalWeight()` via staticcall — the running seated-weight sum.
    function registryTotalWeight() internal view returns (uint64) {
        (bool ok, bytes memory ret) =
            REGISTRY.staticcall(abi.encodeWithSelector(TOTAL_WEIGHT_SELECTOR));
        require(ok && ret.length == 32, "registry totalWeight failed");
        return uint64(abi.decode(ret, (uint256)));
    }
}
