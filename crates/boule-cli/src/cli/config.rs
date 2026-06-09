//! `boule config` — print or edit the effective configuration.

use std::path::{Path, PathBuf};

use clap::Args;

use boule_core::cli::{self, OutputFormat};
use boule_core::config;

use super::shared::{parse_output_format, resolve_config_path};

#[derive(Args)]
pub struct ConfigArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Output format: human, json, or toml. Overrides `[ui] output_format`.
    #[arg(
        short = 'f',
        long,
        value_parser = parse_output_format,
        conflicts_with_all = ["raw", "edit", "print_path"],
    )]
    format: Option<OutputFormat>,
    /// Print the config file as-written, without filling in defaults.
    #[arg(long, group = "config_mode")]
    raw: bool,
    /// Open the config in $EDITOR / $VISUAL and validate the result.
    #[arg(long, group = "config_mode")]
    edit: bool,
    /// Print the resolved config file path and exit.
    #[arg(long = "path", group = "config_mode")]
    print_path: bool,
}

pub(crate) fn handle(args: ConfigArgs) -> anyhow::Result<()> {
    let config_path = resolve_config_path(args.config_path)?;

    if args.print_path {
        println!("{}", config_path.display());
        return Ok(());
    }

    if args.edit {
        return edit_config(&config_path);
    }

    if args.raw {
        let text = std::fs::read_to_string(&config_path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", config_path.display()))?;
        // print! (not println!) so we don't add a newline beyond the file's own.
        print!("{text}");
        return Ok(());
    }

    let config = config::load(&config_path)?;
    // `config` has no human rendering (the data IS the TOML), so `human`
    // falls back to TOML; the CLI override wins over `[ui] output_format`.
    let format =
        cli::resolve_structured_format(args.format, config.ui.output_format, OutputFormat::Toml);
    let rendered = cli::render_structured(&config, format)?;
    print!("{rendered}");
    if !rendered.ends_with('\n') {
        println!();
    }
    Ok(())
}

/// Open the config in `$EDITOR` (or `$VISUAL`, or a platform default) and
/// validate the saved result. A non-zero editor exit leaves the file
/// untouched, honouring abort semantics (`vim :cq`, etc.).
fn edit_config(config_path: &Path) -> anyhow::Result<()> {
    if !config_path.exists() {
        anyhow::bail!(
            "no config at {} to edit; run `boule init --config {}` first",
            config_path.display(),
            config_path.display(),
        );
    }
    let editor = pick_editor();
    let (program, mut argv) = split_editor_command(&editor);
    argv.push(config_path.as_os_str().to_owned());
    let status = std::process::Command::new(&program)
        .args(&argv)
        .status()
        .map_err(|e| anyhow::anyhow!("spawning editor `{}`: {e}", editor))?;
    if !status.success() {
        anyhow::bail!(
            "editor `{}` exited {}; not validating, config left untouched",
            editor,
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "via signal".to_string()),
        );
    }
    // Re-parse so operators learn about typos before they restart the node.
    config::load(config_path).map_err(|e| {
        anyhow::anyhow!(
            "config at {} is no longer valid after edit: {e}",
            config_path.display(),
        )
    })?;
    println!("config validated: {}", config_path.display());
    Ok(())
}

fn pick_editor() -> String {
    if let Ok(v) = std::env::var("EDITOR") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::env::var("VISUAL") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        "nano".to_string()
    }
}

/// Split `"vim -u NONE"` into `(program, argv)` on whitespace. Shell
/// metacharacters are not interpreted; wrap exotic invocations in a script.
fn split_editor_command(cmd: &str) -> (std::ffi::OsString, Vec<std::ffi::OsString>) {
    let mut parts = cmd.split_whitespace();
    let program = parts.next().unwrap_or("nano").into();
    let argv = parts.map(std::ffi::OsString::from).collect();
    (program, argv)
}
