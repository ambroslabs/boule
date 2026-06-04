// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlsVerify} from "./BlsVerify.sol";

/// Live consensus-parameter-update approval interface for the boule reth backend
/// (#542 producer, authorization #746, milestone #4; **authenticated** in #764).
///
/// A consensus parameter is changed by having the seated validators approve the
/// specific update on-chain — a validator-weighted supermajority, mirroring the
/// #729 governance tally but reading the on-chain weight surface (#759). Each
/// validator calls `approve(bytes32 proposalId, bytes paramCommand, bytes32
/// validator, bytes blsSig)`; the contract staticcalls the `Registry` predeploy
/// for the validator's current seated `weightOf(validator)` (which must be `> 0`)
/// and the running `totalWeight()`, verifies the validator's BLS signature
/// (#764), accumulates approving **weight** per proposal (deduplicated per
/// validator), and emits `ParamSubmitted(paramCommand)` **exactly once** when the
/// accrued weight first crosses a `> 2/3 · totalWeight` supermajority
/// (integer-safe: `weight·3 > totalWeight·2`).
///
/// The emitted event shape/topic is deliberately **unchanged** from the original
/// pure-submit producer (#542/#738): boule reads `ParamSubmitted(bytes)` from
/// each committed block (via `eth_getLogs`), turns it into a
/// `ValidatorEffect::ParamUpdate` on the widened `CommitResult` (#727), and
/// re-materialises the carried command into a block — where the existing param
/// path (#542) validates the `v_eff` delay and schedules the change at its view
/// boundary so every replica adopts the new value at the same view. Only the
/// *gating* changed (#746 weighted quorum, #764 BLS authentication): a single
/// unauthenticated submit no longer emits. The `ConsensusParamHistory` apply
/// mechanism and the `v_eff` floor are untouched.
///
/// `proposalId` is an opaque 32-byte identifier of the update — boule sets it to
/// the hash of the encoded param command, so the id binds the vote to one exact
/// command and any approver disagreeing on the command produces a different id
/// (a separate tally). `paramCommand` is the tagged consensus command bytes
/// (`ConsensusParamUpdate::encode()`); the EVM never interprets it, it is carried
/// only so the `ParamSubmitted` event can hand the full command back to
/// consensus, which validates it.
///
/// ## In-EVM BLS authentication (#764) — closing the forged-quorum hole
///
/// The earlier design gated only on `weightOf(validator) > 0`, so a single actor
/// could name every real validator id and forge a ⅔ supermajority (param ids are
/// public). #764 closes that hole: each approval must carry the **validator's own
/// BLS signature** over a domain-separated, replay-bound digest, verified in-EVM
/// via [`BlsVerify`] against the BLS key the `Registry` holds for that validator.
///
/// **The signed digest** is `keccak256(abi.encode(AUTH_DOMAIN, block.chainid,
/// address(this), proposalId, validator))` where `AUTH_DOMAIN =
/// keccak256("BOULE_PARAM_APPROVE_V1")` — a distinct domain from `Governance`, so
/// a governance signature can never be replayed as a param approval (and vice
/// versa). `block.chainid` blocks cross-chain replay, `address(this)` cross-
/// contract replay, `proposalId` (= `hash(command)`) binds to one exact command,
/// `validator` to the voter; the `(proposalId, validator)` dedup removes any need
/// for a nonce. The BLS message is the digest's raw 32 bytes. `msg.sender` is
/// irrelevant — any relayer can submit a validator's signed approval.
///
/// **Which key:** verification reads `Registry.keyAt(validator, settledView())`,
/// the settled key, so it never races an unrecorded rotation (the slashing
/// predeploy's settled-frontier discipline). **Per-approval** (not aggregated):
/// one `BlsVerify` per `approve`; aggregation is a follow-up optimization.
/// **Consensus re-check:** the authenticated in-EVM tally is the authority;
/// consensus still validates the carried command's `v_eff` floor / well-formedness
/// when it re-materialises it, but need not re-run the quorum.
contract Param is BlsVerify {
    /// The validator-weight registry predeploy (#732a/#759) — the source of the
    /// current per-validator seated `weightOf`, the running `totalWeight`, and the
    /// BLS key history the #764 authentication verifies against.
    address constant REGISTRY = address(0x0000000000000000000000000000000000000B12);
    /// `weightOf(bytes32)` selector.
    bytes4 constant WEIGHT_OF = 0x4c108d6d;
    /// `totalWeight()` selector.
    bytes4 constant TOTAL_WEIGHT = 0x96c82e57;
    /// `keyAt(bytes32,uint64)` selector — the validator's BLS key active at a view.
    bytes4 constant KEY_AT = 0x3a9e358a;
    /// `settledView()` selector — the registry's settled-frontier getter (#732).
    bytes4 constant SETTLED_VIEW = 0x7a686ef2;

    /// Approval-signing domain tag (#764): `keccak256("BOULE_PARAM_APPROVE_V1")`.
    /// Distinct from `Governance`'s `AUTH_DOMAIN` so the two cannot be cross-
    /// replayed. Mirrors `AUTH_DOMAIN` in `src/param.rs`.
    bytes32 constant AUTH_DOMAIN =
        0xfa566b51e8b3f0ea73bb6bd0a56040634697f7ad06bdedc3e670759fbf84c6cd;

    /// -G1_generator in EIP-2537 G1 form (a fixed BLS12-381 constant), passed to
    /// [`BlsVerify._verify`]. Identical to the constant in `Slashing.sol`.
    bytes constant NEG_G1GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

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
    /// apply path stays compatible — only the gating moved upstream (#746/#764).
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

    /// `Registry.keyAt(validator, viewNum)` — the validator's BLS pubkey active at
    /// `viewNum` (EIP-2537 G1, 128 bytes; empty if none).
    function _keyAt(bytes32 validator, uint64 viewNum) private view returns (bytes memory) {
        (bool ok, bytes memory r) =
            REGISTRY.staticcall(abi.encodeWithSelector(KEY_AT, validator, viewNum));
        require(ok, "registry keyAt failed");
        return abi.decode(r, (bytes));
    }

    /// `Registry.settledView()` — #764 verifies approvals against the key at this
    /// settled view so verification never races an unrecorded rotation.
    function _settledView() private view returns (uint64) {
        (bool ok, bytes memory r) = REGISTRY.staticcall(abi.encodeWithSelector(SETTLED_VIEW));
        require(ok, "registry settledView failed");
        return abi.decode(r, (uint64));
    }

    /// The digest a validator must BLS-sign to approve `proposalId` voting as
    /// `validator` (#764). Binds the chain, this contract, the proposal (=
    /// `hash(command)`), and the voter, under the param `AUTH_DOMAIN`. Exposed so
    /// off-chain signers and tests can reconstruct exactly what the contract
    /// checks.
    function approveDigest(bytes32 proposalId, bytes32 validator) public view returns (bytes32) {
        return keccak256(abi.encode(AUTH_DOMAIN, block.chainid, address(this), proposalId, validator));
    }

    /// Approve the consensus-parameter-update identified by `proposalId`, voting
    /// the weight of `validator`, carrying the encoded `paramCommand`, and proving
    /// control of `validator` with `blsSig` — the validator's BLS signature
    /// (EIP-2537 G2, 256 bytes) over [`approveDigest`]`(proposalId, validator)`
    /// (#764).
    ///
    /// `validator` must be currently seated (`weightOf(validator) > 0`) — an
    /// unseated (zero-weight) voter is rejected. `blsSig` must verify against the
    /// validator's `Registry.keyAt(validator, settledView())` BLS key, else the
    /// call reverts — so naming a validator whose key you do not control cannot
    /// contribute its weight (the #764 forged-quorum fix). A repeat approval by
    /// the same `validator` is a no-op (it does not double-count). When the
    /// accrued approving weight first crosses `> 2/3 · totalWeight`
    /// (`weight·3 > totalWeight·2`), `ParamSubmitted(paramCommand)` is emitted
    /// once; further approvals after that are ignored.
    function approve(
        bytes32 proposalId,
        bytes calldata paramCommand,
        bytes32 validator,
        bytes calldata blsSig
    ) external {
        uint64 w = _weightOf(validator);
        require(w > 0, "not a seated validator");

        Proposal storage p = proposals[proposalId];
        if (p.emitted || voted[proposalId][validator]) {
            return; // already emitted, or this validator already approved
        }

        // #764: prove control of `validator`'s consensus key, against the settled
        // registry key, over the domain-separated, replay-bound digest.
        bytes memory pk = _keyAt(validator, _settledView());
        require(pk.length == 128, "no registry key for validator");
        bytes32 digest = approveDigest(proposalId, validator);
        require(_verify(pk, abi.encodePacked(digest), blsSig, NEG_G1GEN), "bad approval signature");

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
