//! Unified error type. Every fallible shuki API returns [`Result`].

/// Unified error for all shuki operations.
///
/// Variants carry human-readable context only — never secret material.
#[derive(Debug, thiserror::Error)]
pub enum ShukiError {
    #[error("keychain: {0}")]
    Keychain(String),
    /// Serial/IO failure talking to a signing device.
    #[error("signer device: {0}")]
    Device(String),
    /// The user rejected the operation on the device (physical button).
    #[error("signing rejected on device")]
    DeviceRejected,
    /// The device did not answer in time (locked, unplugged, wrong port).
    #[error("device timeout")]
    DeviceTimeout,
    /// NIP-44 / NIP-49 / HMAC failures.
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("store: {0}")]
    Store(#[from] std::io::Error),
    /// On-disk or remote data that fails to parse/validate.
    #[error("corrupt store data: {0}")]
    Corrupt(String),
    #[error("config: {0}")]
    Config(String),
    #[error("relay: {0}")]
    Relay(String),
    #[error("clipboard: {0}")]
    Clipboard(String),
    #[error("operation cancelled")]
    Cancelled,
    /// The signer backend cannot perform this operation (e.g. no exportable
    /// conversation key); callers fall back to per-entry `nip44_*` calls.
    #[error("unsupported by this signer backend: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ShukiError>;
