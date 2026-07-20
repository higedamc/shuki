//! Configuration types (frozen) + load/save (bodies owned by `leaf/cli-commands-all`).
//!
//! Config is non-secret: relays, network mode, signer kind. 0600 on disk.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShukiError};

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
    /// Load from [`Config::config_path`].
    ///
    /// A missing file yields `Ok(Config::default())`; unreadable or
    /// malformed JSON yields [`ShukiError::Config`].
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(ShukiError::Config(format!("read {}: {e}", path.display())));
            }
        };
        serde_json::from_slice(&bytes)
            .map_err(|e| ShukiError::Config(format!("parse {}: {e}", path.display())))
    }

    /// Persist to [`Config::config_path`]: parent dirs are created, the file
    /// is written atomically (tmp + rename) and is `0600` on unix.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| ShukiError::Config(format!("serialize config: {e}")))?;
        write_atomic(&path, &json)?;
        Ok(())
    }

    /// Config file location: `dirs::config_dir()/shuki/config.json`
    /// (platform-appropriate via `dirs`, e.g. `~/.config/shuki/config.json`
    /// on Linux).
    ///
    /// The `SHUKI_CONFIG` environment variable, when set and non-empty,
    /// overrides the full path to the config file.
    pub fn config_path() -> PathBuf {
        if let Some(p) = std::env::var_os("SHUKI_CONFIG") {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("shuki")
            .join("config.json")
    }

    /// Effective data dir (respects `data_dir` override).
    ///
    /// Precedence: `self.data_dir` override, else the `SHUKI_DATA_DIR`
    /// environment variable, else `dirs::data_dir()/shuki`.
    pub fn resolve_data_dir(&self) -> PathBuf {
        if let Some(d) = &self.data_dir {
            return d.clone();
        }
        if let Some(p) = std::env::var_os("SHUKI_DATA_DIR") {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("shuki")
    }
}

/// Atomic write: tmp file in the same directory (created `0600` on unix),
/// fsync, rename over the target.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent)?;
    let tmp = parent.join(".config.json.tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut f = new_secret_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(unix)]
fn new_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn new_secret_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Serializes tests (crate-wide) that mutate `SHUKI_CONFIG` / `SHUKI_DATA_DIR`.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
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

    fn clear_env() {
        std::env::remove_var("SHUKI_CONFIG");
        std::env::remove_var("SHUKI_DATA_DIR");
    }

    #[test]
    fn load_missing_file_returns_default() {
        let _g = test_env_lock();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("SHUKI_CONFIG", dir.path().join("nope").join("config.json"));
        let c = Config::load().unwrap();
        assert_eq!(c.relays, Vec::<String>::new());
        assert_eq!(c.signer, SignerConfig::Software);
        clear_env();
    }

    #[test]
    fn load_parse_error_is_config_error() {
        let _g = test_env_lock();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"{ not json").unwrap();
        std::env::set_var("SHUKI_CONFIG", &path);
        match Config::load() {
            Err(crate::error::ShukiError::Config(msg)) => assert!(msg.contains("parse")),
            other => panic!("expected Config error, got {other:?}"),
        }
        clear_env();
    }

    #[test]
    fn save_load_roundtrip_and_0600() {
        let _g = test_env_lock();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.json");
        std::env::set_var("SHUKI_CONFIG", &path);

        let c = Config {
            relays: vec!["wss://relay.example".into()],
            net: NetMode::Socks5 {
                addr: DEFAULT_SOCKS5_ADDR.into(),
            },
            data_dir: Some(PathBuf::from("/tmp/shuki-data")),
            ..Config::default()
        };
        c.save().unwrap();
        // Save twice: atomic path must handle an existing target.
        c.save().unwrap();

        let back = Config::load().unwrap();
        assert_eq!(back.relays, c.relays);
        assert_eq!(back.net, c.net);
        assert_eq!(back.data_dir, c.data_dir);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "config must be 0600");
        }
        clear_env();
    }

    #[test]
    fn config_path_env_override() {
        let _g = test_env_lock();
        clear_env();
        std::env::set_var("SHUKI_CONFIG", "/x/y/custom.json");
        assert_eq!(Config::config_path(), PathBuf::from("/x/y/custom.json"));
        clear_env();
        let def = Config::config_path();
        assert!(def.ends_with(Path::new("shuki").join("config.json")));
    }

    #[test]
    fn resolve_data_dir_precedence() {
        let _g = test_env_lock();
        clear_env();
        let mut c = Config::default();
        assert!(c.resolve_data_dir().ends_with("shuki"));
        std::env::set_var("SHUKI_DATA_DIR", "/env/data");
        assert_eq!(c.resolve_data_dir(), PathBuf::from("/env/data"));
        c.data_dir = Some(PathBuf::from("/override/data"));
        assert_eq!(c.resolve_data_dir(), PathBuf::from("/override/data"));
        clear_env();
    }
}
