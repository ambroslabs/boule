use std::path::PathBuf;

pub const APP_NAME: &str = "boule";

pub const CONFIG_FILE_NAME: &str = "config.toml";

pub fn default_config_path() -> Option<PathBuf> {
    default_config_dir().map(|d| d.join(CONFIG_FILE_NAME))
}

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
    if let Some(xdg) = nonempty_env("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join(APP_NAME));
    }
    home_dir().map(|h| h.join(".config").join(APP_NAME))
}

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
