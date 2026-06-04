// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlsVerify} from "./BlsVerify.sol";

/// Equivocation slashing predeploy (#732b): a watcher submits proof that a
/// validator double-signed at one view (two `Vote`s, same `view`, different
/// `block_hash`); this verifies both BLS signatures in-EVM against the
/// validator's key from the `Registry`, and on success emits `Slashed`.
///
/// boule reads `Slashed` from each committed block (the #655/#730 `eth_getLogs`
/// pattern) and applies the penalty through its `StakeSource` (zero the bonded
/// stake → `weight 0` → jail, the existing #658 apply-target). The economic
/// ledger stays consensus-authoritative (#654); this predeploy only *verifies*
/// + *signals*, moving evidence verification onto the EL.
///
/// Each vote's signed message is the boule production pre-image
/// `preimage::<Vote>` = `chain_id ‖ u32_be(len(DST)) ‖ DST ‖ postcard(Vote)`,
/// where `postcard(Vote{view, block_hash})` = `varint(view) ‖ block_hash`
/// (`View` is a `u64` newtype → LEB128 varint; `BlockHash` is `[u8;32]` → 32
/// raw bytes). Reconstructed here so verification trusts only the registry key
/// and the proof, not a caller-supplied message.
contract Slashing is BlsVerify {
    /// The validator-key registry predeploy (#732a).
    address constant REGISTRY = address(0x0000000000000000000000000000000000000B12);
    /// `keyAt(bytes32,uint64)` selector.
    bytes4 constant KEY_AT = 0x3a9e358a;
    /// Vote signing domain tag (boule `SignedMessage` for `Vote`).
    bytes constant VOTE_DOMAIN = "boule.hotstuff.vote.v1";
    /// -G1_generator in EIP-2537 G1 form (a fixed BLS12-381 constant).
    bytes constant NEG_G1GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    /// A validator's equivocation at `view` was verified and slashed.
    event Slashed(bytes32 indexed validator, uint64 viewNum, bytes32 blockA, bytes32 blockB);

    /// postcard unsigned LEB128 varint of a u64.
    function _varint(uint64 v) private pure returns (bytes memory out) {
        while (v >= 0x80) {
            out = abi.encodePacked(out, uint8((v & 0x7f) | 0x80));
            v >>= 7;
        }
        out = abi.encodePacked(out, uint8(v));
    }

    /// preimage::<Vote>(Vote{view, blockHash}, chainId).
    function _votePreimage(bytes memory chainId, uint64 view_, bytes32 blockHash)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            chainId, // 32-byte ChainId
            uint32(VOTE_DOMAIN.length), // big-endian u32 domain length
            VOTE_DOMAIN,
            _varint(view_),
            blockHash
        );
    }

    /// The validator's BLS pubkey active at `view`, read from the registry
    /// (EIP-2537 uncompressed G1, 128 bytes). Empty if the validator has no
    /// recorded key at or before `view`.
    function _keyAt(bytes32 validator, uint64 view_) private view returns (bytes memory) {
        (bool ok, bytes memory r) =
            REGISTRY.staticcall(abi.encodeWithSelector(KEY_AT, validator, view_));
        require(ok, "registry call failed");
        return abi.decode(r, (bytes));
    }

    /// Submit proof that `validator` double-signed at `view`: `sigA` over the
    /// vote for `blockA` and `sigB` over the vote for `blockB`, both under
    /// `chainId`. Reverts unless it is a genuine equivocation (distinct blocks,
    /// both signatures valid under the registry key). On success emits `Slashed`.
    ///
    /// `chainId` is supplied by the caller; a wrong value yields a pre-image
    /// that won't verify, so it cannot forge a slash — it must be the
    /// deployment's `ChainId` for an honest proof to pass.
    function submitEquivocation(
        bytes32 validator,
        bytes calldata chainId,
        uint64 view_,
        bytes32 blockA,
        bytes calldata sigA,
        bytes32 blockB,
        bytes calldata sigB
    ) external {
        require(chainId.length == 32, "chainId");
        require(blockA != blockB, "not an equivocation: same block");

        bytes memory key = _keyAt(validator, view_);
        require(key.length == 128, "no registry key at view");

        require(
            _verify(key, _votePreimage(chainId, view_, blockA), sigA, NEG_G1GEN),
            "sigA invalid"
        );
        require(
            _verify(key, _votePreimage(chainId, view_, blockB), sigB, NEG_G1GEN),
            "sigB invalid"
        );

        emit Slashed(validator, view_, blockA, blockB);
    }
}
