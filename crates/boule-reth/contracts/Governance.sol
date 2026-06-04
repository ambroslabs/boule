// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlsVerify} from "./BlsVerify.sol";

/// Governance-reconfiguration approval interface for the boule reth backend
/// (#729, milestone #4; **authenticated** in #764). Supersedes the
/// committee-approval half of #548.
///
/// A membership change (a *reconfig*: adding/removing/reweighting validators) is
/// enacted by having the seated validators approve it on-chain. Each validator
/// calls `approve(bytes32 proposalId, bytes reconfigCommand, bytes32 validator,
/// bytes blsSig)`; the contract accumulates the **on-chain weight** of each
/// distinct approving validator and, once the accumulated weight crosses a
/// supermajority of `totalWeight()`, emits `Approved(proposalId,
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
/// ## Authenticated, stake-weighted, validator-gated tally (#729 + #764)
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
/// ## In-EVM BLS authentication (#764) — closing the forged-quorum hole
///
/// The earlier design gated only on `weightOf(validator) > 0` and so was
/// **forgeable**: validator ids are public, so a single actor could call
/// `approve` once per real validator id and forge a ⅔ supermajority. #764 closes
/// that hole by requiring each approval to carry the **validator's own BLS
/// signature** over a domain-separated, replay-bound digest, verified in-EVM via
/// [`BlsVerify`] against the BLS key the `Registry` holds for that validator.
/// Naming a validator you don't control no longer counts: you cannot produce its
/// signature.
///
/// **The signed digest (replay / domain separation).** The validator signs the
/// 32-byte `keccak256(abi.encode(...))` of
///
///   ( AUTH_DOMAIN, block.chainid, address(this), proposalId, validator )
///
/// with its consensus BLS key (boule's `min-pk` suite). Each field closes a
/// replay axis: `AUTH_DOMAIN` (`keccak256("BOULE_GOV_APPROVE_V1")`) separates
/// governance from `Param` and from any other use of the BLS key; `block.chainid`
/// blocks cross-chain replay; `address(this)` blocks cross-contract replay;
/// `proposalId` (= boule's `hash(command)`) binds the vote to one exact command;
/// `validator` binds it to the voter. No separate nonce is needed — the contract
/// dedups by `(proposalId, validator)`, so replaying an identical signature for
/// the same proposal is a no-op, and a different command is a different
/// `proposalId`. The BLS message verified is the digest's raw 32 bytes
/// (`abi.encodePacked(digest)`), so a watchtower/relayer can re-sign nothing — it
/// only relays the validator's signature; `msg.sender` is irrelevant.
///
/// **Which key.** Verification reads `Registry.keyAt(validator,
/// settledView())` — the BLS key the registry is **settled** on — so it never
/// races an unrecorded rotation (the same settled-frontier discipline the
/// slashing predeploy follows). A validator that has *just* rotated signs its
/// approval with the key the registry currently holds, until the rotation
/// settles.
///
/// **Per-approval (not aggregated).** Each `approve` runs one `BlsVerify`
/// (`hashToG2` + one EIP-2537 pairing, on the order of hundreds of thousands of
/// gas). This is correct and simplest; BLS *aggregation* (one pairing over the
/// whole approver set) is a follow-up optimization. Reconfigs are infrequent and
/// the contract dedups, so each validator verifies at most once per proposal.
///
/// **Consensus re-check.** The in-EVM authenticated tally is now the authority:
/// the `Approved` event is only emitted after every accrued validator's signature
/// verified against its registry key, so consensus need not re-run the quorum. It
/// continues to validate the carried *command*'s well-formedness when it
/// re-materialises it (tag + reconfig checks at the view boundary) — that is
/// orthogonal to who approved. A buggy/forked EL is out of scope here: the same
/// trust is placed in the EL for every predeploy-driven effect (#727).
contract Governance is BlsVerify {
    /// Fixed genesis-predeploy address of the `Registry` (#759), holding the
    /// per-validator weight surface this tally reads and the BLS key history the
    /// #764 authentication verifies against. Mirrors `REGISTRY_ADDRESS` in
    /// `src/registry.rs`.
    address constant REGISTRY = 0x0000000000000000000000000000000000000B12;
    /// `weightOf(bytes32)` selector — `Registry.weightOf(validator)`, the
    /// current seated weight. Mirrors `WEIGHT_OF_SELECTOR` in `src/registry.rs`.
    bytes4 constant WEIGHT_OF_SELECTOR = 0x4c108d6d;
    /// `totalWeight()` selector — the running seated-weight sum, the quorum
    /// denominator. Mirrors `TOTAL_WEIGHT_SELECTOR` in `src/registry.rs`.
    bytes4 constant TOTAL_WEIGHT_SELECTOR = 0x96c82e57;
    /// `keyAt(bytes32,uint64)` selector — the validator's BLS key active at a
    /// view. Mirrors `KEY_AT_SELECTOR` in `src/registry.rs`.
    bytes4 constant KEY_AT_SELECTOR = 0x3a9e358a;
    /// `settledView()` selector — the registry's settled-frontier getter (#732).
    /// Mirrors `SETTLED_VIEW_SELECTOR` in `src/registry.rs`.
    bytes4 constant SETTLED_VIEW_SELECTOR = 0x7a686ef2;

    /// Approval-signing domain tag (#764): `keccak256("BOULE_GOV_APPROVE_V1")`.
    /// Separates governance approvals from `Param` approvals and any other use of
    /// the validator's BLS key. Mirrors `AUTH_DOMAIN` in `src/governance.rs`.
    bytes32 constant AUTH_DOMAIN =
        0x1c2299be361b40a53153988f6f3db65cee902f43a7d64d948abe0a4eaa156fe9;

    /// -G1_generator in EIP-2537 G1 form (a fixed BLS12-381 constant), passed to
    /// [`BlsVerify._verify`] so it needs no hardcoded generator. Identical to the
    /// constant in `Slashing.sol`.
    bytes constant NEG_G1GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

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

    /// The digest a validator must BLS-sign to approve `proposalId` voting as
    /// `validator` (#764). Binds the chain, this contract, the proposal (=
    /// `hash(command)`), and the voter, under `AUTH_DOMAIN`; see the contract doc
    /// for the replay analysis. Exposed as a view helper so off-chain signers and
    /// tests can reconstruct exactly what the contract checks.
    function approveDigest(bytes32 proposalId, bytes32 validator) public view returns (bytes32) {
        return keccak256(abi.encode(AUTH_DOMAIN, block.chainid, address(this), proposalId, validator));
    }

    /// Approve the reconfig identified by `proposalId`, voting as the seated
    /// `validator` (its 32-byte consensus id), carrying the encoded
    /// `reconfigCommand`, and proving control of `validator` with `blsSig` — the
    /// validator's BLS signature (EIP-2537 G2, 256 bytes) over
    /// [`approveDigest`]`(proposalId, validator)` (#764).
    ///
    /// The caller must be a seated validator: `Registry.weightOf(validator)`
    /// must be `> 0`, else the call reverts. `blsSig` must verify against the
    /// validator's `Registry.keyAt(validator, settledView())` BLS key, else the
    /// call reverts — so naming a validator whose key you do not control cannot
    /// contribute its weight (the #764 forged-quorum fix). A repeat approval by
    /// the same `validator` is a no-op (it does not double-count its weight).
    /// When the accumulated weight of distinct approving validators first crosses
    /// a strict two-thirds supermajority of `Registry.totalWeight()`
    /// (`weight * 3 > totalWeight * 2`), `Approved(proposalId, reconfigCommand)`
    /// is emitted once; further approvals after that are ignored.
    function approve(
        bytes32 proposalId,
        bytes calldata reconfigCommand,
        bytes32 validator,
        bytes calldata blsSig
    ) external {
        uint64 vWeight = registryWeightOf(validator);
        require(vWeight > 0, "not a seated validator");

        Proposal storage p = proposals[proposalId];
        if (p.approved || voted[proposalId][validator]) {
            return; // already enacted, or this validator already approved
        }

        // #764: prove control of `validator`'s consensus key. Verify the BLS
        // signature against the key the registry is *settled* on (never racing an
        // unrecorded rotation), over the domain-separated, replay-bound digest.
        bytes memory pk = registryKeyAt(validator, registrySettledView());
        require(pk.length == 128, "no registry key for validator");
        bytes32 digest = approveDigest(proposalId, validator);
        require(_verify(pk, abi.encodePacked(digest), blsSig, NEG_G1GEN), "bad approval signature");

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

    /// `Registry.keyAt(validator, viewNum)` via staticcall — the validator's BLS
    /// pubkey active at `viewNum` (EIP-2537 G1, 128 bytes; empty if none).
    function registryKeyAt(bytes32 validator, uint64 viewNum) internal view returns (bytes memory) {
        (bool ok, bytes memory ret) =
            REGISTRY.staticcall(abi.encodeWithSelector(KEY_AT_SELECTOR, validator, viewNum));
        require(ok, "registry keyAt failed");
        return abi.decode(ret, (bytes));
    }

    /// `Registry.settledView()` via staticcall — the highest view all of whose
    /// rotations the registry has recorded. #764 verifies approvals against the
    /// key at this settled view so it never races an unrecorded rotation.
    function registrySettledView() internal view returns (uint64) {
        (bool ok, bytes memory ret) =
            REGISTRY.staticcall(abi.encodeWithSelector(SETTLED_VIEW_SELECTOR));
        require(ok && ret.length == 32, "registry settledView failed");
        return uint64(abi.decode(ret, (uint256)));
    }
}
