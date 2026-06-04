// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Validator endpoint-advertisement submission interface for the boule reth
/// backend (#731, milestone #4).
///
/// A validator publishes or updates where peers can reach its consensus traffic
/// (#546) by sending an ordinary EVM transaction to this predeploy, carrying
/// the *already-signed* boule endpoint command as calldata. The contract is a
/// pure event emitter: it does no verification. boule reads the emitted event
/// from each committed block (via `eth_getLogs`), turns it into a
/// `ValidatorEffect::EndpointUpdate` on the widened `CommitResult` (#727), and
/// re-materialises the carried command into a block — where the existing
/// endpoint path (#546) verifies the validator's signature and the
/// strictly-monotone `seq`, then applies it to the `EndpointRegistry`. Only the
/// *submission* path moves onto the EVM; the registry + apply mechanism is
/// unchanged. Endpoint advertisement is optional and a discovery hint only.
///
/// `endpointCommand` is the tagged consensus command bytes produced by
/// `SignedEndpointCommand::encode_command()` — the EVM never interprets it.
/// `validator` is indexed for log filtering and must match the validator named
/// inside the command; consensus trusts the command, not this field. Deployed
/// as a genesis predeploy at a fixed address.
contract Endpoint {
    /// An endpoint command was submitted for `validator`. `endpointCommand` is
    /// the opaque, signed boule endpoint command consensus will verify.
    event EndpointSubmitted(bytes32 indexed validator, bytes endpointCommand);

    /// Submit a signed endpoint command for `validator`.
    function submitEndpoint(bytes32 validator, bytes calldata endpointCommand) external {
        emit EndpointSubmitted(validator, endpointCommand);
    }
}
