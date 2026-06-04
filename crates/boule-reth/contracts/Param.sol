// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Live consensus-parameter-update approval interface for the boule reth backend
/// (#542 producer, authorization #746, milestone #4).
///
/// A consensus parameter is changed by having the seated validators approve the
/// specific update on-chain — a validator-weighted supermajority, mirroring the
/// #729 governance tally but reading the on-chain weight surface (#759). Each
/// validator calls `approve(bytes32 proposalId, bytes paramCommand, bytes32
/// validator)` with an ordinary EVM transaction; the contract staticcalls the
/// `Registry` predeploy for the validator's current seated `weightOf(validator)`
/// (which must be `> 0`) and the running `totalWeight()`, accumulates approving
/// **weight** per proposal (deduplicated per validator), and emits
/// `ParamSubmitted(paramCommand)` **exactly once** when the accrued weight first
/// crosses a `> 2/3 · totalWeight` supermajority (integer-safe:
/// `weight·3 > totalWeight·2`).
///
/// The emitted event shape/topic is deliberately **unchanged** from the original
/// pure-submit producer (#542/#738): boule reads `ParamSubmitted(bytes)` from
/// each committed block (via `eth_getLogs`), turns it into a
/// `ValidatorEffect::ParamUpdate` on the widened `CommitResult` (#727), and
/// re-materialises the carried command into a block — where the existing param
/// path (#542) validates the `v_eff` delay and schedules the change at its view
/// boundary so every replica adopts the new value at the same view. Only the
/// *gating* changed (#746): a single unauthenticated submit no longer emits;
/// authorization is now an upstream weighted quorum. The `ConsensusParamHistory`
/// apply mechanism and the `v_eff` floor are untouched.
///
/// `proposalId` is an opaque 32-byte identifier of the update — boule sets it to
/// the hash of the encoded param command, so the id binds the vote to one exact
/// command and any approver disagreeing on the command produces a different id
/// (a separate tally). `paramCommand` is the tagged consensus command bytes
/// (`ConsensusParamUpdate::encode()`); the EVM never interprets it, it is carried
/// only so the `ParamSubmitted` event can hand the full command back to
/// consensus, which validates it.
///
/// **Residual trust (dumb-carrier caveat).** The `bytes32 validator` argument is
/// caller-supplied: a caller could vote *as* a validator it does not control,
/// since this predeploy authenticates the validator only by its on-chain
/// `weightOf > 0` (seated), not by a signature. This is the same caveat the
/// sibling predeploys (rotation/endpoint/governance) carry, and it is bounded:
/// the carried command is still consensus-validated when re-materialised, and the
/// consensus-side `ConsensusParamUpdate` apply still enforces the `v_eff` delay
/// floor as defense-in-depth. The weighted quorum here raises the bar from
/// "anyone may submit" to "a seated supermajority must approve".
contract Param {
    /// The validator-weight registry predeploy (#732a/#759) — the source of the
    /// current per-validator seated `weightOf` and the running `totalWeight`.
    address constant REGISTRY = address(0x0000000000000000000000000000000000000B12);
    /// `weightOf(bytes32)` selector.
    bytes4 constant WEIGHT_OF = 0x4c108d6d;
    /// `totalWeight()` selector.
    bytes4 constant TOTAL_WEIGHT = 0x96c82e57;

    /// Per-proposal tally state.
    struct Proposal {
        uint64 weight; // accrued approving weight so far
        bool emitted; // `ParamSubmitted` already emitted (one-shot guard)
    }

    /// proposalId => tally.
    mapping(bytes32 => Proposal) private proposals;
    /// proposalId => validator => has this validator already approved.
    mapping(bytes32 => mapping(bytes32 => bool)) private voted;

    /// A consensus-parameter-update command crossed the weighted supermajority.
    /// `paramCommand` is the opaque, tagged boule `ConsensusParamUpdate` consensus
    /// will validate and apply. Emitted exactly once per `proposalId`. The shape
    /// and topic are unchanged from the original #542 producer so boule's read /
    /// apply path stays compatible — only the gating moved upstream (#746).
    event ParamSubmitted(bytes paramCommand);

    /// The registry's current seated weight for `validator` (`weightOf`).
    function _weightOf(bytes32 validator) private view returns (uint64) {
        (bool ok, bytes memory r) =
            REGISTRY.staticcall(abi.encodeWithSelector(WEIGHT_OF, validator));
        require(ok, "registry weightOf failed");
        return abi.decode(r, (uint64));
    }

    /// The registry's running sum of all seated validators' weight (`totalWeight`).
    function _totalWeight() private view returns (uint64) {
        (bool ok, bytes memory r) = REGISTRY.staticcall(abi.encodeWithSelector(TOTAL_WEIGHT));
        require(ok, "registry totalWeight failed");
        return abi.decode(r, (uint64));
    }

    /// Approve the consensus-parameter-update identified by `proposalId`, voting
    /// the weight of `validator` and carrying the encoded `paramCommand`.
    ///
    /// `validator` must be currently seated (`weightOf(validator) > 0`) — an
    /// unseated (zero-weight) voter is rejected. A repeat approval by the same
    /// `validator` is a no-op (it does not double-count). When the accrued
    /// approving weight first crosses `> 2/3 · totalWeight`
    /// (`weight·3 > totalWeight·2`), `ParamSubmitted(paramCommand)` is emitted
    /// once; further approvals after that are ignored.
    function approve(bytes32 proposalId, bytes calldata paramCommand, bytes32 validator) external {
        uint64 w = _weightOf(validator);
        require(w > 0, "not a seated validator");

        Proposal storage p = proposals[proposalId];
        if (p.emitted || voted[proposalId][validator]) {
            return; // already emitted, or this validator already approved
        }
        voted[proposalId][validator] = true;
        p.weight += w;

        // Integer-safe strict-supermajority test: weight > 2/3 * totalWeight.
        if (uint256(p.weight) * 3 > uint256(_totalWeight()) * 2) {
            p.emitted = true;
            emit ParamSubmitted(paramCommand);
        }
    }

    /// Accrued approving weight tallied for `proposalId` so far.
    function approvals(bytes32 proposalId) external view returns (uint64) {
        return proposals[proposalId].weight;
    }

    /// Whether `proposalId` has crossed the supermajority and emitted
    /// `ParamSubmitted`.
    function isApproved(bytes32 proposalId) external view returns (bool) {
        return proposals[proposalId].emitted;
    }
}
