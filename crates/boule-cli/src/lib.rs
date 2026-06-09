//! `boule-cli` — the reth-SDK-free `boule` command tree, as a **library**.
//!
//! The user-facing `boule` binary is produced by `boule-bundle` (which links
//! the reth EL in-process); that binary composes this crate's [`cli::Command`]
//! tree (every reth-free subcommand — `init`/`start`/`key`/`config`/`snapshot`/
//! `reconfig`/`rotation`/`endpoint`, plus the reth-gated `genesis`/`faucet`/
//! `rpc-proxy`) with its own `node` subcommand. Keeping these subcommands here,
//! reth-SDK-free, lets the root workspace build/test/clippy them without ever
//! compiling the reth dependency tree (see `Cargo.toml`).
//!
//! The `testnet` driver bin (`src/bin/testnet.rs`) is a thin shell over
//! [`boule_node::testnet`]; it stays in this crate so the root-workspace
//! integration tests can spawn it.

pub mod cli;

/// Initialize the tracing subscriber.
///
/// Honors two environment variables:
///
/// - `RUST_LOG`: standard `tracing-subscriber` env filter. Defaults to
///   `boule=info`. Set to `info,boule_core::consensus=debug` to get the
///   structured event-boundary logs the consensus layer emits.
/// - `RUST_LOG_FORMAT`: `pretty` (default) or `json`. JSON emits one
///   structured event per line, which operators can pipe through `jq`.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "boule=info".into());

    let json = std::env::var("RUST_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}
