//! `boule node --dev` — a zero-config, single-process dev chain (#892).
//!
//! With `--dev` and no chain/config, bootstrap a one-validator chain entirely
//! in-process and in one shot — no shell, no probe run, no log-parsing:
//!
//! 1. Mint a deterministic dev node key (Ed25519) + BLS key under the datadir.
//! 2. Build the seeded dev genesis ([`boule_reth::build_seeded_genesis`]) for
//!    that single validator (weight 1) and write it to the datadir.
//! 3. Launch reth in-process and read its genesis state root *from the
//!    in-process provider* — the chain's genesis seed.
//! 4. Mint the validator's chain-bound BLS PoP at that root
//!    ([`boule_reth::mint_genesis_bls_pops`]).
//! 5. Build the `reth-inprocess` consensus config (BLS-aggregated, single
//!    validator) with `genesis_seed_hex` = the root, so the genesis bridge
//!    matches by construction.
//! 6. Run consensus against the already-launched reth.
//!
//! Steps 3–6 happen inside [`crate::runtime::run_bundled_with`] via the
//! [`crate::runtime::ConfigProvider`] callback (the root is only known after
//! reth launches), so reth is launched exactly once.
//!
//! The whole thing runs out of a `--datadir` (default: a temp dir kept alive for
//! the process), so a fresh `docker run <img> node --dev` commits blocks with
//! no glue.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::info;

use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::identity::file::FileKeyProvider;
use boule_core::identity::{KeyProvider, node_id_to_base58};

use crate::runtime::{BundleRethConfig, ConfigProvider, RethPorts, run_bundled_with};

/// CLI inputs for `boule node --dev`. A subset of `NodeArgs`: the dev path
/// supplies the chain/config/identity itself, so only the ports + datadir are
/// operator-facing.
pub struct DevArgs {
    /// Data directory for the dev chain's reth state + minted keys + genesis.
    /// `None` → a fresh temp dir, kept alive for the lifetime of the process
    /// (wiped on exit), so repeated `node --dev` runs are clean.
    pub datadir: Option<PathBuf>,
    /// Public `eth_*` HTTP RPC port.
    pub http_port: u16,
    /// Authenticated Engine API TCP port (bound by reth; the bundle uses IPC).
    pub auth_port: u16,
    /// devp2p listener port (`0` lets the OS pick).
    pub p2p_port: u16,
    /// Public eth RPC module selection.
    pub http_api: String,
    /// EVM fee recipient (block coinbase) for produced payloads.
    pub fee_recipient: String,
}

/// The fixed dev fee recipient when none is given: the canonical Anvil/Hardhat
/// account 0, which the dev genesis also prefunds for convenience.
pub const DEV_FEE_RECIPIENT: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Run a zero-config single-validator dev chain in this process (#892).
pub async fn run_dev(args: DevArgs) -> Result<()> {
    // Resolve the datadir. A temp dir is held in `_tmp` for the whole run so it
    // is not deleted until the process exits.
    let (datadir, _tmp) = match args.datadir {
        Some(d) => (d, None),
        None => {
            let tmp = tempfile::Builder::new()
                .prefix("boule-dev-")
                .tempdir()
                .context("creating dev temp datadir")?;
            (tmp.path().to_path_buf(), Some(tmp))
        }
    };
    std::fs::create_dir_all(&datadir)
        .with_context(|| format!("creating dev datadir {}", datadir.display()))?;
    let dev_dir = datadir.join("dev");
    std::fs::create_dir_all(&dev_dir)
        .with_context(|| format!("creating dev key/genesis dir {}", dev_dir.display()))?;

    // 1) Mint the dev node key (Ed25519) → NodeId.
    let node_key_path = dev_dir.join("node.key");
    let node_identity = FileKeyProvider::new(node_key_path.clone())
        .with_allow_insecure_perms(true)
        .load_or_init()
        .context("minting dev node key")?;
    let node_id = node_identity.node_id().context("deriving dev NodeId")?;
    info!(
        target: "boule::dev",
        node_id = %node_id_to_base58(&node_id),
        "minted dev validator node key",
    );

    // 2) Mint the dev BLS key → public key.
    let bls_key_path = dev_dir.join("bls.key");
    let bls_identity = BlsKeyFile::new(bls_key_path.clone())
        .with_allow_insecure_perms(true)
        .load_or_init()
        .context("minting dev BLS key")?;
    let bls_pubkey = bls_identity.public;

    // 3) Build the seeded dev genesis for this single validator (weight 1) and
    //    write it to the datadir, so reth boots a chain whose Registry already
    //    seats this validator with non-zero weight.
    let genesis = boule_reth::build_seeded_genesis([(node_id, bls_pubkey, 1u64)])
        .map_err(|e| anyhow::anyhow!("building seeded dev genesis: {e:?}"))?;
    let genesis_json = serde_json::to_string_pretty(&genesis)? + "\n";
    let genesis_path = dev_dir.join("genesis.json");
    std::fs::write(&genesis_path, &genesis_json)
        .with_context(|| format!("writing dev genesis {}", genesis_path.display()))?;
    info!(
        target: "boule::dev",
        genesis = %genesis_path.display(),
        "wrote seeded dev genesis",
    );

    let reth_cfg = BundleRethConfig {
        chain_json: genesis_json,
        datadir: datadir.join("reth"),
        ports: RethPorts {
            // Bind the public RPC on all interfaces so a published Docker port
            // (`docker run -p 8545:8545 ... node --dev`) reaches it. `--dev` is a
            // local-only convenience, so the wider bind is acceptable here (the
            // operator `boule node` path keeps the loopback default).
            http_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            http_port: args.http_port,
            auth_port: args.auth_port,
            p2p_port: args.p2p_port,
            auth_ipc_path: dev_dir.join("engine.ipc"),
        },
        http_api: args.http_api,
    };

    // 4–6) The genesis state root is only known once reth launches in-process;
    // mint the chain-bound PoP and assemble the config in the provider callback.
    let fee_recipient = args.fee_recipient;
    let provider: ConfigProvider = Box::new(move |genesis_root: [u8; 32]| {
        let config = build_dev_config(DevConfigInputs {
            node_id,
            node_key_path: &node_key_path,
            bls_key_path: &bls_key_path,
            genesis_root,
            storage_dir: &datadir.join("consensus"),
            fee_recipient: &fee_recipient,
        })?;
        // Both identities live in the same Ed25519 node key (network +
        // consensus signing reuse it); the dedicated BLS validator identity is
        // wired via `[node.bls_validator_identity]` in the config.
        let net_identity = FileKeyProvider::new(node_key_path.clone())
            .with_allow_insecure_perms(true)
            .load_or_init()
            .context("loading dev node identity")?;
        Ok((config, net_identity, None))
    });

    info!(target: "boule::dev", "starting zero-config single-validator dev chain");
    run_bundled_with(reth_cfg, provider).await
}

struct DevConfigInputs<'a> {
    node_id: [u8; 32],
    node_key_path: &'a Path,
    bls_key_path: &'a Path,
    genesis_root: [u8; 32],
    storage_dir: &'a Path,
    fee_recipient: &'a str,
}

/// Mint the chain-bound BLS PoP at `genesis_root` and render the single-validator
/// `reth-inprocess` consensus config (parsed via the normal TOML path so it gets
/// the same validation as a file-loaded config).
fn build_dev_config(inputs: DevConfigInputs<'_>) -> Result<boule_core::config::Config> {
    let DevConfigInputs {
        node_id,
        node_key_path,
        bls_key_path,
        genesis_root,
        storage_dir,
        fee_recipient,
    } = inputs;

    // Mint the chain-bound PoP at the real genesis root (single-validator case).
    let rows = boule_reth::mint_genesis_bls_pops(
        &[(node_id, bls_key_path.to_path_buf())],
        genesis_root,
        /* allow_insecure_perms = */ true,
    )
    .context("minting dev chain-bound BLS PoP")?;
    let row = rows.first().context("expected one dev PoP row")?;
    let nid = node_id_to_base58(&node_id);
    let bls_pub = hex::encode(row.pubkey);
    let bls_pop = hex::encode(&row.pop_sig);
    let seed = hex::encode(genesis_root);

    // Render and parse the config through the normal TOML path so it is validated
    // exactly like a file-loaded config (`config::load`).
    let toml = format!(
        "[node]\nlisten_addr = \"127.0.0.1:7000\"\n\
         [node.identity]\nbackend = \"file\"\npath = \"{node_key}\"\nallow_insecure_perms = true\n\
         [node.bls_validator_identity]\nbackend = \"file\"\npath = \"{bls_key}\"\n\
         allow_insecure_perms = true\n\
         [api]\nlisten_addr = \"127.0.0.1:8000\"\n\
         [consensus]\nvalidators = [\"{nid}\"]\n\
         signature_scheme = \"bls_aggregated\"\n\
         genesis_seed_hex = \"{seed}\"\n\
         storage_dir = \"{storage}\"\n\
         timeout_base_ms = 500\ntimeout_max_ms = 5000\nmin_block_interval_ms = 800\n\
         [[consensus.validators_bls]]\nnode_id = \"{nid}\"\n\
         bls_pubkey = \"{bls_pub}\"\nbls_pop = \"{bls_pop}\"\n\
         [consensus.application]\nbackend = \"reth-inprocess\"\n\
         fee_recipient = \"{fee_recipient}\"\n",
        node_key = node_key_path.display(),
        bls_key = bls_key_path.display(),
        storage = storage_dir.display(),
    );

    let config: boule_core::config::Config =
        toml::from_str(&toml).context("parsing the generated dev config")?;
    Ok(config)
}
