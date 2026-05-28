//! Cross-platform default locations for the node's config and on-disk
//! state, following XDG on Linux, the standard Library directories on
//! macOS, and the `%APPDATA%` / `%LOCALAPPDATA%` split on Windows.
//!
//! Implemented manually rather than via the `directories` crate to keep
//! the dependency graph small (the crate pulls in an MPL-2.0 transitive
//! that would expand the project's allowed-license matrix).
//!
//! All getters return `Option`: a missing `HOME` (or the Windows
//! equivalents) means we have nowhere sensible to default to and the
//! caller must fall back to demanding `--config`.
//!
//! | Resource | Linux | macOS | Windows |
//! | --- | --- | --- | --- |
//! | Config | `$XDG_CONFIG_HOME/boule/config.toml` | `~/Library/Application Support/boule/config.toml` | `%APPDATA%\boule\config.toml` |
//! | State / WAL / storage | `$XDG_DATA_HOME/boule/` | `~/Library/Application Support/boule/` | `%LOCALAPPDATA%\boule\` |

use std::path::PathBuf;

/// Application name used as the leaf directory under each platform's
/// well-known location.
pub const APP_NAME: &str = "boule";

/// Filename of the TOML config inside the platform-specific config dir.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Default path to the node's TOML config file. `None` if the platform
/// home directory could not be resolved (no `HOME` / `APPDATA`).
pub fn default_config_path() -> Option<PathBuf> {
    default_config_dir().map(|d| d.join(CONFIG_FILE_NAME))
}

/// Default directory holding the node's config. `None` if the platform
/// home directory could not be resolved.
#[cfg(target_os = "linux")]
pub fn default_config_dir() -> Option<PathBuf> {
    if let Some(xdg) = nonempty_env("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join(APP_NAME));
    }
    home_dir().map(|h| h.join(".config").join(APP_NAME))
}

#[cfg(target_os = "macos")]
pub fn default_config_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join("Library").join("Application Support").join(APP_NAME))
}

#[cfg(target_os = "windows")]
pub fn default_config_dir() -> Option<PathBuf> {
    nonempty_env("APPDATA").map(|p| PathBuf::from(p).join(APP_NAME))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn default_config_dir() -> Option<PathBuf> {
    // Fall back to XDG semantics on the BSDs and other Unix-likes.
    if let Some(xdg) = nonempty_env("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join(APP_NAME));
    }
    home_dir().map(|h| h.join(".config").join(APP_NAME))
}

/// Default directory for the node's durable state (consensus KV / WAL,
/// generated keys, addr files). `None` if the platform home directory
/// could not be resolved.
#[cfg(target_os = "linux")]
pub fn default_data_dir() -> Option<PathBuf> {
    if let Some(xdg) = nonempty_env("XDG_DATA_HOME") {
        return Some(PathBuf::from(xdg).join(APP_NAME));
    }
    home_dir().map(|h| h.join(".local").join("share").join(APP_NAME))
}

#[cfg(target_os = "macos")]
pub fn default_data_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join("Library").join("Application Support").join(APP_NAME))
}

#[cfg(target_os = "windows")]
pub fn default_data_dir() -> Option<PathBuf> {
    nonempty_env("LOCALAPPDATA").map(|p| PathBuf::from(p).join(APP_NAME))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn default_data_dir() -> Option<PathBuf> {
    if let Some(xdg) = nonempty_env("XDG_DATA_HOME") {
        return Some(PathBuf::from(xdg).join(APP_NAME));
    }
    home_dir().map(|h| h.join(".local").join("share").join(APP_NAME))
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    nonempty_env("HOME").map(PathBuf::from)
}

#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    nonempty_env("USERPROFILE").map(PathBuf::from)
}

fn nonempty_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_path_uses_app_name() {
        // Whatever the platform decides, the leaf must be the app's
        // config filename and the parent must end in the app name.
        if let Some(path) = default_config_path() {
            assert_eq!(path.file_name().unwrap(), CONFIG_FILE_NAME);
            let parent = path.parent().unwrap();
            assert_eq!(parent.file_name().unwrap(), APP_NAME);
        }
    }

    #[test]
    fn default_data_dir_ends_in_app_name() {
        if let Some(path) = default_data_dir() {
            assert_eq!(path.file_name().unwrap(), APP_NAME);
        }
    }
}
