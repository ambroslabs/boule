// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// In-EVM verification of a boule BLS signature (#732b), using the Prague
/// EIP-2537 BLS12-381 precompiles + the SHA-256 / MODEXP precompiles.
///
/// boule signs with the `min-pk` IETF suite (G1 pubkeys, G2 sigs) under the DST
/// `BOULE_HOTSTUFF_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Verification is
/// `e(pubkey, hash_to_G2(msg)) == e(G1_gen, sig)`, checked as
/// `e(pubkey, H) · e(-G1gen, sig) == 1` via the pairing precompile.
///
/// Points are EIP-2537 uncompressed: G1 = x‖y (each Fp 16-byte-zero-padded to
/// 64 = 128 bytes); G2 = x.c0‖x.c1‖y.c0‖y.c1 (256 bytes). The caller supplies
/// pubkey/sig in this form; `hash_to_G2` is computed here so verification does
/// not trust a caller-supplied curve point.
contract BlsVerify {
    bytes constant DST =
        "BOULE_HOTSTUFF_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    // BLS12-381 base field modulus p (48 bytes).
    bytes constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    address constant SHA256 = address(0x02);
    address constant MODEXP = address(0x05);
    address constant BLS_G2ADD = address(0x0d);
    address constant BLS_PAIRING = address(0x0f);
    address constant BLS_MAP_FP2_TO_G2 = address(0x11);

    function _sha256(bytes memory data) private view returns (bytes32) {
        (bool ok, bytes memory r) = SHA256.staticcall(data);
        require(ok && r.length == 32, "sha256");
        return bytes32(r);
    }

    /// RFC 9380 §5.3.1 expand_message_xmd with SHA-256, output `len` bytes.
    /// `len` here is always 256 (ell = 8 blocks).
    function _expandMessageXmd(bytes memory message) private view returns (bytes memory) {
        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        // msg_prime = Z_pad(64) ‖ message ‖ I2OSP(256,2) ‖ I2OSP(0,1) ‖ DST_prime
        bytes memory msgPrime = abi.encodePacked(
            new bytes(64), // s_in_bytes = SHA-256 block size
            message,
            uint8(0x01), // 256 = 0x0100, high byte
            uint8(0x00), // low byte
            uint8(0x00), // I2OSP(0,1)
            dstPrime
        );
        bytes32 b0 = _sha256(msgPrime);
        bytes32 prev = _sha256(abi.encodePacked(b0, uint8(1), dstPrime)); // b_1
        bytes memory out = new bytes(256);
        _store32(out, 0, prev);
        for (uint8 i = 2; i <= 8; i++) {
            bytes32 bi = _sha256(abi.encodePacked(b0 ^ prev, i, dstPrime));
            _store32(out, (uint256(i) - 1) * 32, bi);
            prev = bi;
        }
        return out;
    }

    function _store32(bytes memory dst, uint256 off, bytes32 v) private pure {
        for (uint256 j = 0; j < 32; j++) {
            dst[off + j] = v[j];
        }
    }

    /// Reduce a 64-byte big-endian value mod p via MODEXP (base^1 mod p),
    /// returning the 48-byte result left-padded to a 64-byte EIP-2537 Fp coord.
    function _reduceTo64(bytes memory chunk64) private view returns (bytes memory) {
        bytes memory input = abi.encodePacked(
            uint256(64), // base length
            uint256(1), // exp length
            uint256(48), // mod length
            chunk64,
            uint8(1), // exponent = 1
            P
        );
        (bool ok, bytes memory r) = MODEXP.staticcall(input);
        require(ok && r.length == 48, "modexp");
        return abi.encodePacked(new bytes(16), r); // pad 48 -> 64
    }

    function _slice64(bytes memory src, uint256 off) private pure returns (bytes memory) {
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            out[i] = src[off + i];
        }
        return out;
    }

    function _mapToG2(bytes memory fp2) private view returns (bytes memory) {
        (bool ok, bytes memory r) = BLS_MAP_FP2_TO_G2.staticcall(fp2);
        require(ok && r.length == 256, "map");
        return r;
    }

    /// hash_to_curve(message) -> G2 point (EIP-2537, 256 bytes).
    function hashToG2(bytes memory message) public view returns (bytes memory) {
        bytes memory u = _expandMessageXmd(message); // 256 bytes -> 4 Fp coords
        // u0 = (e0, e1), u1 = (e2, e3); each Fp2 = c0‖c1 = 128 bytes.
        bytes memory u0 = abi.encodePacked(
            _reduceTo64(_slice64(u, 0)),
            _reduceTo64(_slice64(u, 64))
        );
        bytes memory u1 = abi.encodePacked(
            _reduceTo64(_slice64(u, 128)),
            _reduceTo64(_slice64(u, 192))
        );
        bytes memory q0 = _mapToG2(u0);
        bytes memory q1 = _mapToG2(u1);
        (bool ok, bytes memory h) = BLS_G2ADD.staticcall(abi.encodePacked(q0, q1));
        require(ok && h.length == 256, "g2add");
        return h;
    }

    /// Verify `sig` is `pubkey`'s BLS signature over `message`.
    /// `pubkey` is EIP-2537 G1 (128 bytes); `sig` is EIP-2537 G2 (256 bytes);
    /// `negG1Gen` is -G1_generator in EIP-2537 G1 form (supplied by the caller
    /// as a constant so this contract needs no hardcoded generator).
    function verify(
        bytes calldata pubkey,
        bytes calldata message,
        bytes calldata sig,
        bytes calldata negG1Gen
    ) external view returns (bool) {
        return _verify(pubkey, message, sig, negG1Gen);
    }

    /// Memory-argument verify, callable by inheriting contracts (the slashing
    /// predeploy reconstructs the vote pre-image in memory).
    function _verify(
        bytes memory pubkey,
        bytes memory message,
        bytes memory sig,
        bytes memory negG1Gen
    ) internal view returns (bool) {
        bytes memory h = hashToG2(message);
        // PAIRING_CHECK([pubkey, H], [-G1gen, sig]) == 1
        bytes memory input = abi.encodePacked(pubkey, h, negG1Gen, sig);
        (bool ok, bytes memory r) = BLS_PAIRING.staticcall(input);
        return ok && r.length == 32 && r[31] == 0x01;
    }
}
