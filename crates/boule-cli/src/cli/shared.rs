//! Helpers shared across CLI subcommands.

use std::path::PathBuf;

use boule_core::cli::OutputFormat;
use boule_core::paths;

/// Env var that enables fail-closed production semantics when set to
/// "production" (equivalent to passing `--production`).
pub(crate) const ENV_PRODUCTION: &str = "BOULE_ENV";

/// The explicit `--config` value, or the platform-specific default.
pub(crate) fn resolve_config_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    paths::default_config_path().ok_or_else(|| {
        anyhow::anyhow!(
            "no --config given and the platform default could not be resolved \
             (HOME / APPDATA unset?). Pass --config <path> explicitly."
        )
    })
}

pub(crate) fn is_production(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    std::env::var(ENV_PRODUCTION)
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// `--format` value parser for the shared [`OutputFormat`].
pub(crate) fn parse_output_format(s: &str) -> anyhow::Result<OutputFormat> {
    OutputFormat::parse(s)
}
