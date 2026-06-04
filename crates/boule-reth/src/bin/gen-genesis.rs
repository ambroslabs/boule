//! Emit a boule reth genesis with the genesis `Registry` predeploy seeded with
//! validator keys + weights + `totalWeight` (#765), so a fresh chain has a
//! working weighted-quorum surface (`weightOf`/`totalWeight`) from block zero —
//! no `recordWeight` tx, no manual setup in e2e/harnesses.
//!
//! Dev/test path: seeds the embedded base genesis with a deterministic dev
//! validator set ([`boule_reth::dev_genesis_validators`]). A per-deployment
//! builder that seeds *minted* validators instead is a follow-up; it would call
//! the same [`boule_reth::seed_registry_genesis`] primitive this binary uses.
//!
//! Usage:
//! ```text
//! gen-genesis [N] [OUT]
//!   N    number of dev validators to seed (default 4); weights are 1..=N.
//!   OUT  output path (default: stdout).
//! ```
//!
//! `run-reth.sh` / `testnet.sh` invoke this so the reth chain they boot already
//! has seated weights.

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let n: usize = args
        .next()
        .map(|s| s.parse().expect("N must be a positive integer"))
        .unwrap_or(4);
    assert!(n >= 1, "N must be >= 1");
    let out = args.next();

    let genesis = boule_reth::build_dev_genesis(n);
    let json = serde_json::to_string_pretty(&genesis).expect("serialize genesis") + "\n";

    match out {
        Some(path) => std::fs::write(path, json)?,
        None => {
            use std::io::Write as _;
            std::io::stdout().write_all(json.as_bytes())?;
        }
    }
    Ok(())
}
