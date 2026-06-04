// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Live consensus-parameter-update submission interface for the boule reth
/// backend (#542 producer, milestone #4).
///
/// A consensus parameter is changed by sending an EVM transaction to this
/// predeploy carrying the encoded boule `ConsensusParamUpdate` command as
/// calldata. The contract is a pure event emitter: it does no verification.
/// boule reads the emitted event from each committed block (via `eth_getLogs`),
/// turns it into a `ValidatorEffect::ParamUpdate` on the widened `CommitResult`
/// (#727), and re-materialises the carried command into a block — where the
/// existing param-update path (#542) validates the `v_eff` delay and schedules
/// the change at its view boundary so every replica adopts the new value at the
/// same view. Only the *submission* path moves onto the EVM; the
/// `ConsensusParamHistory` apply mechanism is unchanged.
///
/// `paramCommand` is the tagged consensus command bytes produced by
/// `ConsensusParamUpdate::encode()` — the EVM never interprets it. Unlike a key
/// rotation or endpoint advertisement, a parameter update is *not* tied to a
/// single validator, so no `validator` is indexed.
///
/// **Authorization is an open follow-up (#542):** who may change a consensus
/// parameter — a governance multisig, a validator-quorum signature — is
/// deliberately unresolved. This predeploy emits whatever is submitted; the
/// only consensus-side guard today is the `v_eff` delay floor. The first wired
/// parameter (`min_block_interval`) is leader-local and harmless, which bounds
/// the risk until authorization lands.
contract Param {
    /// A consensus-parameter-update command was submitted. `paramCommand` is the
    /// opaque, tagged boule `ConsensusParamUpdate` consensus will validate.
    event ParamSubmitted(bytes paramCommand);

    /// Submit an encoded consensus-parameter-update command.
    function submitParam(bytes calldata paramCommand) external {
        emit ParamSubmitted(paramCommand);
    }
}
