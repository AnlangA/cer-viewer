//! Application configuration persistence.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Theme mode (dark or light).
    pub theme: String,
    /// Window width in pixels.
    pub window_width: f32,
    /// Window height in pixels.
    pub window_height: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            window_width: 1024.0,
            window_height: 768.0,
        }
    }
}

impl Config {
    /// Get the config file path using the directories crate.
    fn config_path() -> Option<PathBuf> {
        let proj_dirs = directories::ProjectDirs::from("", "", "cer-viewer")?;
        Some(proj_dirs.config_dir().join("config.json"))
    }

    /// Load configuration from disk. Returns default config if file doesn't exist or is corrupt.
    pub fn load() -> Self {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return Self::default(),
        };

        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save configuration to disk.
    pub fn save(&self) {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return,
        };

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let _ = std::fs::write(
            &path,
            serde_json::to_string_pretty(self).unwrap_or_default(),
        );
    }
}
