//! Forge a validator equivocation proof (two `Vote`s, same `view`, different
//! `block_hash`, both BLS-signed under the same key + chain id) in the
//! **EIP-2537 uncompressed** encoding the `Slashing` predeploy
//! (`boule-reth/contracts/Slashing.sol`, `submitEquivocation`) verifies in-EVM
//! against the registry's `keyAt(validator, view)`.
//!
//! A test helper for the A1 Phase-5 e2e (`boule-reth/single-node-el-e2e.sh`,
//! #785/#777); **not** used by the node. It drives the slashing read path
//! against the **EL-written** registry key: the equivocating signatures are
//! produced by the *same* BLS key the registry holds at `view` (a genesis-seeded
//! dev validator key via `--seed`, or a node's key file via `--key-file`), so
//! the predeploy verifies them against the EL-written key and emits `Slashed`.
//!
//! It reuses the same machinery as `gen_slashing_vectors` (`hotstuff::qc`) and
//! `bls-sign`: each vote's signed message is the production pre-image
//! `preimage::<Vote>(Vote{view, block_hash}, chain_id)` — exactly what
//! `Slashing.sol` reconstructs — signed with boule's `min-pk` IETF suite under
//! the consensus DST (what the in-EVM `BlsVerify` checks). The compressed
//! `blst` G1 pubkey / G2 sigs are re-encoded to the EIP-2537 128-byte /
//! 256-byte uncompressed form.
//!
//! Usage:
//! ```text
//! gen-equivocation (--seed <u8> | --key-file <path>) \
//!   --validator <hex32> --view <u64> \
//!   [--chain-id <hex32>] [--block-a <hex32>] [--block-b <hex32>]
//! ```
//! Prints `KEY=VALUE` lines (`VALIDATOR/CHAINID/VIEW/BLOCKA/BLOCKB/SIGA/SIGB/
//! PUBKEY`) for the shell to splice into the `submitEquivocation` calldata.

use blst::min_pk::{PublicKey, Signature};
use blst::{
    BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_p1_affine, blst_p1_deserialize, blst_p2_affine,
    blst_p2_deserialize,
};
use boule_consensus::View;
use boule_consensus::hotstuff::qc::Vote;
use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, BlsSecretKey};
use boule_core::crypto::signed::{ChainId, preimage};

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

fn parse_hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim_start_matches("0x")).expect("hex");
    assert_eq!(b.len(), 32, "expected 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

fn main() {
    let mut seed: Option<u8> = None;
    let mut key_file: Option<String> = None;
    let mut validator: Option<[u8; 32]> = None;
    // Default to the all-zero chain id. The Slashing predeploy takes the chain
    // id from the caller and only checks the signatures verify against the
    // registry key under it, so a forged equivocation simply signs under, and
    // passes, the same value. An honest watcher would pass the deployment's
    // real ChainId; `--chain-id` overrides for that case.
    let mut chain_id = ChainId([0u8; 32]);
    let mut view: Option<u64> = None;
    let mut block_a = [0xAAu8; 32];
    let mut block_b = [0xBBu8; 32];
    // `--digest <hex32>` switches to a plain digest-signing mode: sign the raw
    // 32-byte message with the *same* dev-validator-convention key, emitting just
    // `PUBKEY=`/`SIG=`. Used for the Governance/Param approval digest, whose key
    // the Registry holds at the genesis vEff — so it must derive identically to
    // the seeded key (IKM = [seed, 0, …]), unlike `bls-sign`'s `ikm.fill(seed)`.
    let mut digest: Option<Vec<u8>> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut next = || args.next().unwrap_or_else(|| panic!("{a} needs a value"));
        match a.as_str() {
            "--seed" => seed = Some(next().parse().expect("--seed must be a u8")),
            "--key-file" => key_file = Some(next()),
            "--validator" => validator = Some(parse_hex32(&next())),
            "--chain-id" => chain_id = ChainId(parse_hex32(&next())),
            "--view" => view = Some(next().parse().expect("--view must be a u64")),
            "--block-a" => block_a = parse_hex32(&next()),
            "--block-b" => block_b = parse_hex32(&next()),
            "--digest" => {
                let h = next();
                digest = Some(hex::decode(h.trim_start_matches("0x")).expect("--digest hex"));
            }
            other => panic!("unknown arg: {other}"),
        }
    }

    // Load the secret key: either a one-byte dev seed (the same derivation the
    // genesis dev validators use — IKM = [seed, 0, …]) or a node's BLS key file.
    let (secret, public): (BlsSecretKey, BlsPublicKey) = match (seed, key_file) {
        (Some(s), None) => {
            let mut ikm = [0u8; 32];
            ikm[0] = s;
            BlsAggregated::keygen(&ikm).expect("keygen from dev seed")
        }
        (None, Some(path)) => {
            let id = BlsKeyFile::new(path.into())
                .with_allow_insecure_perms(true)
                .load_or_init()
                .expect("load BLS key file");
            (*id.secret, id.public)
        }
        _ => panic!("exactly one of --seed / --key-file is required"),
    };

    // Plain digest-signing mode (Governance/Param approval): sign the raw message.
    if let Some(msg) = digest {
        let sig = BlsAggregated::sign_partial(&secret, &msg).expect("sign digest");
        println!("PUBKEY={}", hx(&pk_eip2537(&public)));
        println!("SIG={}", hx(&sig_eip2537(&sig)));
        return;
    }

    let validator = validator.expect("--validator is required");
    let view = view.expect("--view is required");

    let pre_a = preimage::<Vote>(
        &Vote {
            view: View(view),
            block_hash: block_a,
        },
        &chain_id,
    )
    .expect("preimage A");
    let pre_b = preimage::<Vote>(
        &Vote {
            view: View(view),
            block_hash: block_b,
        },
        &chain_id,
    )
    .expect("preimage B");

    let sig_a = BlsAggregated::sign_partial(&secret, &pre_a).expect("sign A");
    let sig_b = BlsAggregated::sign_partial(&secret, &pre_b).expect("sign B");

    println!("VALIDATOR={}", hx(&validator));
    println!("CHAINID={}", hx(chain_id.as_bytes()));
    println!("VIEW={view}");
    println!("BLOCKA={}", hx(&block_a));
    println!("BLOCKB={}", hx(&block_b));
    println!("PUBKEY={}", hx(&pk_eip2537(&public)));
    println!("SIGA={}", hx(&sig_eip2537(&sig_a)));
    println!("SIGB={}", hx(&sig_eip2537(&sig_b)));
}
