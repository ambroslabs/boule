// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Governance-reconfiguration approval interface for the boule reth backend
/// (#729, milestone #4). Supersedes the committee-approval half of #548.
///
/// A membership change (a *reconfig*: adding/removing/reweighting validators) is
/// enacted by having the seated validators approve it on-chain. Each validator
/// calls `approve(bytes32 proposalId, bytes reconfigCommand)` with an ordinary
/// EVM transaction; the contract tallies distinct approvers and, once the tally
/// crosses `quorum`, emits `Approved(proposalId, reconfigCommand)` **exactly
/// once**. boule reads that event from each committed block (via `eth_getLogs`),
/// turns it into a `ValidatorEffect` on the widened `CommitResult` (#727), and
/// re-materialises the carried command into a block — where the existing
/// reconfig path validates and schedules the membership change at a view
/// boundary. This replaces the consensus-side signature-accumulation + bespoke
/// tx-gossip approach: approvals ride the ordinary EVM mempool/gossip instead.
///
/// `proposalId` is an opaque 32-byte identifier of the reconfig — boule sets it
/// to the hash of the encoded reconfig command, so the id binds the vote to one
/// exact command and any approver disagreeing on the command produces a
/// different id (and so a separate tally). `reconfigCommand` is the tagged
/// consensus command bytes; the EVM never interprets it, it is carried only so
/// the `Approved` event can hand the full command back to consensus, which
/// validates it. Deployed as a genesis predeploy at a fixed address.
///
/// **MVP weight model — one-validator-one-vote.** The contract counts *distinct
/// approving addresses*, not stake weight: there is no on-chain queryable
/// validator-weight source today (the `Staking` predeploy, #655, is a pure
/// event emitter whose authoritative balances live consensus-side in
/// `BondedStakeLedger`; the `Registry`, #732a, mirrors BLS keys, not weight), so
/// inventing one here would duplicate state. `quorum` is therefore a count of
/// validators, supplied by the first approver and fixed for that `proposalId`.
/// Hardening (a stake-weighted tally read from an on-chain weight oracle, and
/// restricting `approve` to seated validators) is the same follow-up the sibling
/// predeploys carry; until then consensus still validates the carried command,
/// which bounds the exposure of an over-counted tally.
contract Governance {
    /// Per-proposal tally state.
    struct Proposal {
        uint64 quorum; // approver count required to emit `Approved` (0 = unset)
        uint64 weight; // distinct approvals seen so far
        bool approved; // `Approved` already emitted (one-shot guard)
    }

    /// proposalId => tally.
    mapping(bytes32 => Proposal) private proposals;
    /// proposalId => approver => has this address already approved.
    mapping(bytes32 => mapping(address => bool)) private voted;

    /// A reconfig crossed `quorum` distinct approvals. `reconfigCommand` is the
    /// opaque, tagged boule reconfig command consensus will validate and apply.
    /// Emitted exactly once per `proposalId`.
    event Approved(bytes32 indexed proposalId, bytes reconfigCommand);

    /// Approve the reconfig identified by `proposalId`, carrying its encoded
    /// `reconfigCommand` and the `quorum` (distinct-approver count) required.
    ///
    /// The first approval for a `proposalId` fixes its `quorum`; later approvals
    /// must pass the same value. A repeat approval by the same address is a
    /// no-op (it does not double-count). When the distinct-approver tally first
    /// reaches `quorum`, `Approved(proposalId, reconfigCommand)` is emitted once;
    /// further approvals after that are ignored.
    function approve(bytes32 proposalId, bytes calldata reconfigCommand, uint64 quorum) external {
        require(quorum > 0, "quorum must be positive");
        Proposal storage p = proposals[proposalId];
        if (p.quorum == 0) {
            p.quorum = quorum;
        } else {
            require(p.quorum == quorum, "quorum mismatch");
        }
        if (p.approved || voted[proposalId][msg.sender]) {
            return; // already enacted, or this address already approved
        }
        voted[proposalId][msg.sender] = true;
        p.weight += 1;
        if (p.weight >= p.quorum) {
            p.approved = true;
            emit Approved(proposalId, reconfigCommand);
        }
    }

    /// Distinct approvals tallied for `proposalId` so far.
    function approvals(bytes32 proposalId) external view returns (uint64) {
        return proposals[proposalId].weight;
    }

    /// Whether `proposalId` has crossed quorum and emitted `Approved`.
    function isApproved(bytes32 proposalId) external view returns (bool) {
        return proposals[proposalId].approved;
    }
}
