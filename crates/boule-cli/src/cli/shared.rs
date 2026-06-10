use std::path::PathBuf;

use boule_core::cli::OutputFormat;
use boule_core::paths;

pub(crate) const ENV_PRODUCTION: &str = "BOULE_ENV";

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

pub(crate) fn parse_output_format(s: &str) -> anyhow::Result<OutputFormat> {
    OutputFormat::parse(s)
}
