//! Sign an approval digest with a deterministic boule BLS key, emitting the
//! pubkey + signature in the **EIP-2537 uncompressed** encoding the in-EVM
//! `BlsVerify` / `Registry.keyAt` path requires (#764). A test helper for the
//! manual live-reth harnesses (`contracts/test/governance.mjs`,
//! `contracts/test/param-auth.mjs`); **not** used by the node.
//!
//! It mirrors the `gen_slashing_vectors` machinery (`boule-consensus`
//! `hotstuff::qc`): a keypair is derived from a one-byte seed via
//! [`BlsAggregated::keygen`], the message is signed with `sign_partial` (boule's
//! `min-pk` IETF suite under the `…_POP_` DST — exactly what `BlsVerify`
//! verifies), and the compressed `blst` points are re-encoded to the EIP-2537
//! 128-byte G1 / 256-byte G2 uncompressed form.
//!
//! Usage:
//! ```text
//! bls-sign --seed <u8>                 # print PUBKEY=<eip2537-g1-128b-hex>
//! bls-sign --seed <u8> --msg <hex32>   # also print SIG=<eip2537-g2-256b-hex>
//! ```
//!
//! `--msg` is the raw bytes the validator signs — for #764 that is the 32-byte
//! `approveDigest(proposalId, validator)` the contract reconstructs (the BLS
//! message is `abi.encodePacked(digest)`). The harness computes the digest with
//! ethers and passes it here, so the signature is over exactly what the contract
//! checks.

use blst::min_pk::{PublicKey, Signature};
use blst::{
    BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_p1_affine, blst_p1_deserialize, blst_p2_affine,
    blst_p2_deserialize,
};
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, BlsSecretKey};

/// One BLS12-381 Fp coordinate as a 64-byte EIP-2537 word (48 big-endian bytes
/// left-padded with 16 zero bytes).
fn fp64(fp: &blst_fp) -> [u8; 64] {
    let mut be = [0u8; 48];
    unsafe { blst_bendian_from_fp(be.as_mut_ptr(), fp) };
    let mut out = [0u8; 64];
    out[16..].copy_from_slice(&be);
    out
}

/// EIP-2537 uncompressed G1 = x‖y (128 bytes).
fn g1(a: &blst_p1_affine) -> Vec<u8> {
    [fp64(&a.x), fp64(&a.y)].concat()
}

/// EIP-2537 uncompressed G2 = x.c0‖x.c1‖y.c0‖y.c1 (256 bytes).
fn g2(a: &blst_p2_affine) -> Vec<u8> {
    [
        fp64(&a.x.fp[0]),
        fp64(&a.x.fp[1]),
        fp64(&a.y.fp[0]),
        fp64(&a.y.fp[1]),
    ]
    .concat()
}

/// Compressed `min-pk` G1 pubkey -> EIP-2537 128-byte uncompressed form.
fn pk_eip2537(pk: &BlsPublicKey) -> Vec<u8> {
    let mut aff = blst_p1_affine::default();
    let un = PublicKey::from_bytes(pk).expect("valid pubkey").serialize();
    unsafe {
        assert_eq!(
            blst_p1_deserialize(&mut aff, un.as_ptr()),
            BLST_ERROR::BLST_SUCCESS
        );
    }
    g1(&aff)
}

/// Compressed G2 signature -> EIP-2537 256-byte uncompressed form.
fn sig_eip2537(sig: &[u8; 96]) -> Vec<u8> {
    let mut aff = blst_p2_affine::default();
    let un = Signature::from_bytes(sig).expect("valid sig").serialize();
    unsafe {
        assert_eq!(
            blst_p2_deserialize(&mut aff, un.as_ptr()),
            BLST_ERROR::BLST_SUCCESS
        );
    }
    g2(&aff)
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let mut seed: Option<u8> = None;
    let mut msg: Option<Vec<u8>> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--seed" => {
                seed = Some(
                    args.next()
                        .expect("--seed needs a value")
                        .parse()
                        .expect("--seed must be a u8"),
                );
            }
            "--msg" => {
                let h = args.next().expect("--msg needs a hex value");
                let h = h.strip_prefix("0x").unwrap_or(&h);
                msg = Some(hex::decode(h).expect("--msg must be hex"));
            }
            other => panic!("unknown arg: {other}"),
        }
    }
    let seed = seed.expect("--seed is required");

    let mut ikm = [0u8; 32];
    ikm.fill(seed);
    let (sk, pk): (BlsSecretKey, BlsPublicKey) =
        BlsAggregated::keygen(&ikm).expect("keygen from 32-byte ikm");

    println!("PUBKEY={}", hx(&pk_eip2537(&pk)));
    if let Some(m) = msg {
        let sig = BlsAggregated::sign_partial(&sk, &m).expect("sign");
        println!("SIG={}", hx(&sig_eip2537(&sig)));
    }
}
