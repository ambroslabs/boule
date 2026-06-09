//! Single-validator smoke for the unified `boule` binary (milestone #7, #897).
//!
//! This is the Rust replacement for the old `crates/boule-bundle/smoke.sh`
//! (now deleted). ONE process = boule consensus + the custom reth EL
//! in-process (no second process, no HTTP Engine API, no JWT). It provisions
//! a chain end-to-end **through the unified binary's own subcommands** —
//! `boule genesis dev` (seeded Registry genesis), `boule init` (node key),
//! `boule genesis bls-pop` (chain-bound PoP) — then runs `boule node` and
//! asserts blocks COMMIT via `eth_blockNumber`.
//!
//! It is `#[ignore]`d so the normal `cargo test` skips it (it boots reth, well
//! over the 15s/test ceiling). The heavy CI lane runs it explicitly with
//! `--ignored`. Run locally:
//! ```sh
//! cargo test -p boule-bundle --test bundle_smoke -- --ignored --nocapture
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn boule_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_boule"))
}

/// A spawned `boule node` we always kill on drop.
struct NodeGuard(Option<Child>);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_ok(bin: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawning `boule {}`: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "`boule {}` failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

/// Pull a `key=value` line's value out of combined output.
fn grab<'a>(haystack: &'a str, key: &str) -> Option<&'a str> {
    haystack.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix(key).map(str::trim)
    })
}

/// `eth_blockNumber` against the node's HTTP RPC. `None` if the endpoint is not
/// up yet or the response can't be parsed.
fn eth_block_number(http: &str) -> Option<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []
    });
    let resp = reqwest::blocking::Client::new()
        .post(http)
        .json(&body)
        .timeout(Duration::from_secs(2))
        .send()
        .ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    let hex = v.get("result")?.as_str()?.trim_start_matches("0x");
    u64::from_str_radix(hex, 16).ok()
}

#[test]
#[ignore = "boots reth in-process; heavy, run via the CI lane with --ignored"]
fn single_validator_commits_blocks() {
    let bin = boule_bin();
    let work = tempfile::tempdir().expect("tempdir");
    let w = work.path();

    // Ports: pick high, fixed ports for this single-process smoke.
    let http_port: u16 = 8545;
    let auth_port: u16 = 8551;
    let probe_http: u16 = 8600;
    let probe_auth: u16 = 8651;

    // 1) Seeded reth genesis (Registry predeploy + dev validator weights).
    let genesis = w.join("genesis.json");
    run_ok(
        &bin,
        &[
            "genesis",
            "dev",
            "--validators",
            "4",
            "--out",
            genesis.to_str().unwrap(),
        ],
    );
    assert!(genesis.exists(), "genesis.json not written");

    // 2) Mint a node key via `boule init` (reth-free path).
    let node_key = w.join("node.key");
    let init_toml = w.join("init.toml");
    write_file(
        &init_toml,
        &format!(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n\
             [node.identity]\nbackend = \"file\"\npath = \"{}\"\n\
             [api]\nlisten_addr = \"127.0.0.1:8000\"\n",
            node_key.display()
        ),
    );
    let init_out = run_ok(&bin, &["init", "--config", init_toml.to_str().unwrap()]);
    let init_str = String::from_utf8_lossy(&init_out.stdout);
    let nid = init_str
        .lines()
        .find_map(|l| l.split("NodeId = ").nth(1))
        .map(|s| s.split_whitespace().next().unwrap().to_string())
        .or_else(|| {
            // Fallback: any base58-looking token after "NodeId".
            String::from_utf8_lossy(&init_out.stderr)
                .lines()
                .find_map(|l| l.split("NodeId = ").nth(1))
                .map(|s| s.split_whitespace().next().unwrap().to_string())
        })
        .expect("could not parse NodeId from `boule init`");
    let _ = std::fs::set_permissions(&node_key, perms_0600());

    // 3) Discover reth's genesis state root via a fail-closed probe run: boot
    //    `boule node` with an all-zero seed; the genesis bridge bails and prints
    //    the correct root.
    let probe_toml = w.join("probe.toml");
    write_file(
        &probe_toml,
        &format!(
            "[node]\nlisten_addr = \"127.0.0.1:7001\"\n\
             [node.identity]\nbackend = \"file\"\npath = \"{}\"\n\
             [api]\nlisten_addr = \"127.0.0.1:8001\"\n\
             [consensus]\nvalidators = [\"{nid}\"]\n\
             genesis_seed_hex = \"{}\"\n\
             storage_dir = \"{}\"\n\
             [consensus.application]\nbackend = \"reth-inprocess\"\n\
             fee_recipient = \"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\"\n",
            node_key.display(),
            "0".repeat(64),
            w.join("consensus-probe").display(),
        ),
    );
    let probe_out = Command::new(&bin)
        .args([
            "node",
            "-c",
            probe_toml.to_str().unwrap(),
            "--chain",
            genesis.to_str().unwrap(),
            "--datadir",
            w.join("reth-probe").to_str().unwrap(),
            "--authrpc.ipcpath",
            w.join("probe.ipc").to_str().unwrap(),
            "--http.port",
            &probe_http.to_string(),
            "--authrpc.port",
            &probe_auth.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("probe run");
    let probe_log = format!(
        "{}{}",
        String::from_utf8_lossy(&probe_out.stdout),
        String::from_utf8_lossy(&probe_out.stderr)
    );
    let seed = extract_genesis_root(&probe_log)
        .unwrap_or_else(|| panic!("could not read reth genesis root from probe:\n{probe_log}"));
    assert_eq!(seed.len(), 64, "genesis root must be 64 hex chars");

    // 4) Mint the BLS key + chain-bound PoP for this validator at that seed.
    let bls_key = w.join("bls.key");
    let bls_out = run_ok(
        &bin,
        &[
            "genesis",
            "bls-pop",
            "--genesis-seed",
            &seed,
            "--validator",
            &format!("{nid}:{}", bls_key.display()),
            "--allow-insecure-key-perms",
        ],
    );
    let bls_str = String::from_utf8_lossy(&bls_out.stdout);
    let bls_pub = grab(&bls_str, "bls_pubkey_0=").expect("bls_pubkey_0 in output");
    let bls_pop = grab(&bls_str, "bls_pop_0=").expect("bls_pop_0 in output");
    let _ = std::fs::set_permissions(&bls_key, perms_0600());

    // 5) Real run: single-validator BLS chain, reth in-process.
    let node_toml = w.join("node.toml");
    write_file(
        &node_toml,
        &format!(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n\
             [node.identity]\nbackend = \"file\"\npath = \"{node_key}\"\n\
             [node.bls_validator_identity]\nbackend = \"file\"\npath = \"{bls_key}\"\n\
             [api]\nlisten_addr = \"127.0.0.1:8000\"\n\
             [consensus]\nvalidators = [\"{nid}\"]\n\
             signature_scheme = \"bls_aggregated\"\n\
             genesis_seed_hex = \"{seed}\"\n\
             storage_dir = \"{storage}\"\n\
             timeout_base_ms = 500\ntimeout_max_ms = 5000\nmin_block_interval_ms = 800\n\
             [[consensus.validators_bls]]\nnode_id = \"{nid}\"\n\
             bls_pubkey = \"{bls_pub}\"\nbls_pop = \"{bls_pop}\"\n\
             [consensus.application]\nbackend = \"reth-inprocess\"\n\
             fee_recipient = \"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\"\n",
            node_key = node_key.display(),
            bls_key = bls_key.display(),
            storage = w.join("consensus").display(),
        ),
    );

    let log = w.join("boule.log");
    let log_file = std::fs::File::create(&log).expect("create log");
    let child = Command::new(&bin)
        .args([
            "node",
            "-c",
            node_toml.to_str().unwrap(),
            "--chain",
            genesis.to_str().unwrap(),
            "--datadir",
            w.join("reth").to_str().unwrap(),
            "--authrpc.ipcpath",
            w.join("engine.ipc").to_str().unwrap(),
            "--http.port",
            &http_port.to_string(),
            "--authrpc.port",
            &auth_port.to_string(),
        ])
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn `boule node`");
    let mut guard = NodeGuard(Some(child));

    // 6) Wait for blocks to COMMIT (eth_blockNumber advances past several).
    let http = format!("http://127.0.0.1:{http_port}");
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut last = 0u64;
    let mut passed = false;
    while Instant::now() < deadline {
        // Bail out early if the node died.
        if let Some(child) = guard.0.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            let tail = std::fs::read_to_string(&log).unwrap_or_default();
            panic!(
                "`boule node` exited early ({status:?}); log tail:\n{}",
                tail.lines().rev().take(60).collect::<Vec<_>>().join("\n")
            );
        }
        if let Some(n) = eth_block_number(&http) {
            last = n;
            if n >= 5 {
                passed = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    if !passed {
        let tail = std::fs::read_to_string(&log).unwrap_or_default();
        panic!(
            "chain did not advance past several blocks (last={last}); log tail:\n{}",
            tail.lines().rev().take(80).collect::<Vec<_>>().join("\n")
        );
    }
    eprintln!("PASS — single-process boule+reth committed blocks; eth_blockNumber reached {last}");
    drop(guard);
}

fn write_file(path: &Path, contents: &str) {
    let mut f = std::fs::File::create(path).unwrap_or_else(|e| panic!("create {path:?}: {e}"));
    f.write_all(contents.as_bytes())
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

#[cfg(unix)]
fn perms_0600() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(0o600)
}
#[cfg(not(unix))]
fn perms_0600() -> std::fs::Permissions {
    std::fs::metadata(".").unwrap().permissions()
}

/// Find the 64-hex reth genesis state root in the fail-closed bridge error.
/// The message reads: "... reth's genesis state root <64hex>; set ...".
fn extract_genesis_root(log: &str) -> Option<String> {
    // Look for the phrase, then take the next 64-hex run.
    let marker = "genesis state root ";
    let idx = log.find(marker)? + marker.len();
    let tail = &log[idx..];
    let hex: String = tail.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() >= 64 {
        Some(hex[..64].to_string())
    } else {
        None
    }
}
