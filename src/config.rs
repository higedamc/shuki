//! Configuration types (frozen) + load/save (bodies owned by `leaf/cli-commands-all`).
//!
//! Config is non-secret: relays, network mode, signer kind. 0600 on disk.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Result;

pub const DEFAULT_SOCKS5_ADDR: &str = "127.0.0.1:9050";
pub const DEFAULT_CLIPBOARD_CLEAR_SECS: u64 = 45;

/// How relay connections reach the network.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum NetMode {
    #[default]
    Clearnet,
    /// External Tor (or any SOCKS5 proxy).
    Socks5 { addr: String },
    /// Embedded arti (requires the `tor` cargo feature).
    Tor,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SignerConfig {
    #[default]
    Software,
    /// `port == None` → autodetect by pinging serial ports.
    Nsd { port: Option<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub signer: SignerConfig,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub net: NetMode,
    #[serde(default = "default_clipboard_clear_secs")]
    pub clipboard_clear_secs: u64,
    /// Override the data directory (default: platform data dir + "shuki").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,
}

fn default_clipboard_clear_secs() -> u64 {
    DEFAULT_CLIPBOARD_CLEAR_SECS
}

impl Default for Config {
    fn default() -> Self {
        Self {
            signer: SignerConfig::default(),
            relays: Vec::new(),
            net: NetMode::default(),
            clipboard_clear_secs: DEFAULT_CLIPBOARD_CLEAR_SECS,
            data_dir: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        todo!("leaf/cli-commands-all")
    }

    pub fn save(&self) -> Result<()> {
        todo!("leaf/cli-commands-all")
    }

    /// `~/.config/shuki/config.json` (platform-appropriate via `dirs`).
    pub fn config_path() -> PathBuf {
        todo!("leaf/cli-commands-all")
    }

    /// Effective data dir (respects `data_dir` override).
    pub fn resolve_data_dir(&self) -> PathBuf {
        todo!("leaf/cli-commands-all")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_shapes() {
        let c = Config::default();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"mode\":\"clearnet\""));
        assert!(json.contains("\"kind\":\"software\""));
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.net, NetMode::Clearnet);

        let nsd: Config = serde_json::from_str(
            r#"{"signer":{"kind":"nsd","port":"/dev/ttyUSB0"},"net":{"mode":"socks5","addr":"127.0.0.1:9050"}}"#,
        )
        .unwrap();
        assert_eq!(
            nsd.signer,
            SignerConfig::Nsd {
                port: Some("/dev/ttyUSB0".into())
            }
        );
        assert_eq!(nsd.clipboard_clear_secs, DEFAULT_CLIPBOARD_CLEAR_SECS);
    }
}
