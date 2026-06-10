use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::info;

use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::identity::file::FileKeyProvider;
use boule_core::identity::{KeyProvider, node_id_to_base58};

use crate::runtime::{BundleRethConfig, ConfigProvider, RethPorts, run_bundled_with};

pub struct DevArgs {
    pub datadir: Option<PathBuf>,

    pub http_port: u16,

    pub auth_port: u16,

    pub p2p_port: u16,

    pub http_api: String,

    pub fee_recipient: String,
}

pub const DEV_FEE_RECIPIENT: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

pub async fn run_dev(args: DevArgs) -> Result<()> {
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

    let bls_key_path = dev_dir.join("bls.key");
    let bls_identity = BlsKeyFile::new(bls_key_path.clone())
        .with_allow_insecure_perms(true)
        .load_or_init()
        .context("minting dev BLS key")?;
    let bls_pubkey = bls_identity.public;

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
            http_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            http_port: args.http_port,
            auth_port: args.auth_port,
            p2p_port: args.p2p_port,
            auth_ipc_path: dev_dir.join("engine.ipc"),
        },
        http_api: args.http_api,
    };

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

fn build_dev_config(inputs: DevConfigInputs<'_>) -> Result<boule_core::config::Config> {
    let DevConfigInputs {
        node_id,
        node_key_path,
        bls_key_path,
        genesis_root,
        storage_dir,
        fee_recipient,
    } = inputs;

    let rows = boule_reth::mint_genesis_bls_pops(
        &[(node_id, bls_key_path.to_path_buf())],
        genesis_root,
        true,
    )
    .context("minting dev chain-bound BLS PoP")?;
    let row = rows.first().context("expected one dev PoP row")?;
    let nid = node_id_to_base58(&node_id);
    let bls_pub = hex::encode(row.pubkey);
    let bls_pop = hex::encode(&row.pop_sig);
    let seed = hex::encode(genesis_root);

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
