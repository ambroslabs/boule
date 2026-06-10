use std::path::{Path, PathBuf};
use std::process::Command;

fn find_solc() -> PathBuf {
    if let Ok(s) = std::env::var("SOLC") {
        return PathBuf::from(s);
    }
    if Command::new("solc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return PathBuf::from("solc");
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".solcx/solc-v0.8.24");
        if p.exists() {
            return p;
        }
    }
    panic!(
        "solc not found. Set $SOLC to a solc 0.8.24 binary, or put `solc` on PATH. \
         The genesis predeploy bytecode is generated from contracts/*.sol at build \
         time (never committed) — see AGENTS.md 'Generated artifacts'."
    );
}

fn compile_runtime(solc: &Path, contracts_dir: &Path, name: &str) -> String {
    let sol = contracts_dir.join(format!("{name}.sol"));
    let out = Command::new(solc)
        .args(["--combined-json", "bin-runtime"])
        .arg(&sol)
        .output()
        .unwrap_or_else(|e| panic!("running solc on {}: {e}", sol.display()));
    if !out.status.success() {
        panic!(
            "solc failed on {}:\n{}",
            sol.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("solc --combined-json output is JSON");
    let contracts = json["contracts"]
        .as_object()
        .expect("solc output has a `contracts` object");

    let suffix = format!(":{name}");
    let entry = contracts
        .iter()
        .find(|(k, _)| k.ends_with(&suffix))
        .unwrap_or_else(|| panic!("solc output has no contract named {name}"));
    let bin = entry.1["bin-runtime"]
        .as_str()
        .expect("contract has a `bin-runtime`");
    assert!(!bin.is_empty(), "{name} compiled to empty runtime bytecode");
    format!("0x{bin}")
}

fn main() {
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let contracts_dir = crate_dir.join("contracts");
    let template_path = crate_dir.join("genesis.template.json");

    println!("cargo:rerun-if-changed=genesis.template.json");
    println!("cargo:rerun-if-changed=contracts");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOLC");

    let solc = find_solc();
    let template = std::fs::read_to_string(&template_path).expect("read genesis.template.json");
    let mut genesis: serde_json::Value =
        serde_json::from_str(&template).expect("parse genesis.template.json");

    let alloc = genesis["alloc"]
        .as_object_mut()
        .expect("genesis template has an `alloc` object");
    for acct in alloc.values_mut() {
        let acct = acct.as_object_mut().expect("alloc entry is an object");
        if let Some(name) = acct.remove("contract") {
            let name = name.as_str().expect("`contract` is a string").to_string();
            let code = compile_runtime(&solc, &contracts_dir, &name);
            acct.insert("code".to_string(), serde_json::Value::String(code));
        }
    }

    let genesis_path = crate_dir.join("genesis.json");
    let out = serde_json::to_string_pretty(&genesis).expect("serialize genesis") + "\n";
    let changed = std::fs::read_to_string(&genesis_path)
        .map(|c| c != out)
        .unwrap_or(true);
    if changed {
        std::fs::write(&genesis_path, out).expect("write genesis.json");
    }
}
