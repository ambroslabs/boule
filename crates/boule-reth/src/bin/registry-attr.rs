//! Emit the A1 `registryPayload` build attribute (the hex `extra_data` carrier)
//! for the custom EL (#781), produced by boule's **real** population code
//! ([`boule_reth::registry_payload::RegistryPayload`]). The live-drive harness
//! (`drive-custom-el.sh`) calls this so the bytes fed to the custom
//! `boule-reth-node` over the Engine API are exactly what a boule leader would
//! send — not a hand-rolled fixture — closing the population→EL→registry loop
//! with the production encoder.
//!
//! It also prints, on stderr, the per-record fields so the harness can assert the
//! Registry's `keyAt`/`weightOf`/`settledView` reflect them.
//!
//! Usage:
//! ```text
//! registry-attr --settled <view> \
//!   [--key <validator_hex32>:<vEff>:<key128_hex>] ... \
//!   [--weight <validator_hex32>:<weight>] ...
//! ```
//! Prints the `0x`-prefixed attribute hex to stdout.

use boule_consensus::View;
use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;
use boule_reth::registry::RecordKey;
use boule_reth::registry_payload::RegistryPayload;

fn hex32(s: &str) -> NodeId {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim_start_matches("0x"), &mut out).expect("32-byte hex");
    out
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut settled: Option<View> = None;
    let mut keys: Vec<RecordKey> = Vec::new();
    let mut weights: Vec<ValidatorUpdate> = Vec::new();

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--settled" => {
                let v: u64 = args.next().expect("--settled <view>").parse().expect("u64");
                settled = Some(View::new(v));
            }
            "--key" => {
                // validator:vEff:key128hex
                let spec = args.next().expect("--key <val>:<vEff>:<key128hex>");
                let mut parts = spec.splitn(3, ':');
                let validator = hex32(parts.next().expect("validator"));
                let v_eff: u64 = parts.next().expect("vEff").parse().expect("u64 vEff");
                let key_hex = parts.next().expect("key128 hex");
                let key_bytes = hex::decode(key_hex.trim_start_matches("0x")).expect("key hex");
                assert_eq!(key_bytes.len(), 128, "key must be 128-byte EIP-2537 G1");
                let mut key128 = [0u8; 128];
                key128.copy_from_slice(&key_bytes);
                keys.push(RecordKey {
                    validator,
                    v_eff: View::new(v_eff),
                    key128,
                });
            }
            "--weight" => {
                let spec = args.next().expect("--weight <val>:<weight>");
                let (val, w) = spec.split_once(':').expect("validator:weight");
                weights.push(ValidatorUpdate {
                    node_id: hex32(val),
                    weight: w.parse().expect("u64 weight"),
                });
            }
            other => panic!("unknown flag {other}"),
        }
    }

    let payload = RegistryPayload::new(keys, &weights, settled);
    // Echo what we are asserting, for the harness, on stderr.
    eprintln!("settled_view={:?}", payload.settled_view.map(|v| v.0));
    for k in &payload.keys {
        eprintln!(
            "key validator=0x{} vEff={}",
            hex::encode(k.validator),
            k.v_eff.0
        );
    }
    for (v, w) in &payload.weights {
        eprintln!("weight validator=0x{} weight={}", hex::encode(v), w);
    }
    // The attribute hex (production encoder).
    println!("{}", payload.to_attribute_hex());
}
