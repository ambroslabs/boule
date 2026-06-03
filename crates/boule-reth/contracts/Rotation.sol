// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Validator key-rotation submission interface for the boule reth backend
/// (#730, milestone #4).
///
/// A validator rotates its consensus signing key or operator key by sending an
/// ordinary EVM transaction to this predeploy, carrying the *already-encoded,
/// dual-signed* boule rotation command as calldata. The contract is a pure
/// event emitter: it does no verification. boule reads the emitted event from
/// each committed block (via `eth_getLogs`), turns it into a
/// `ValidatorEffect::KeyRotation` on the widened `CommitResult` (#727), and
/// re-materialises the carried command into a block — where the existing
/// rotation path verifies the self-attestation signatures and schedules the
/// `v_eff` key swap (the `RotatableSigner` / key-history mechanism, #312/#258,
/// is unchanged; only the *submission* path moves onto the EVM).
///
/// `rotationCommand` is the tagged consensus command bytes produced by
/// `DualSignedRotation::encode_command()` (or an operator/cancel variant) — the
/// EVM never interprets it. `validator` is indexed for log filtering and must
/// match the validator named inside the command; consensus trusts the command,
/// not this field. Deployed as a genesis predeploy at a fixed address.
contract Rotation {
    /// A rotation command was submitted for `validator`. `rotationCommand` is
    /// the opaque, dual-signed boule rotation command consensus will verify.
    event RotationSubmitted(bytes32 indexed validator, bytes rotationCommand);

    /// Submit a dual-signed rotation command for `validator`.
    function submitRotation(bytes32 validator, bytes calldata rotationCommand) external {
        emit RotationSubmitted(validator, rotationCommand);
    }
}
