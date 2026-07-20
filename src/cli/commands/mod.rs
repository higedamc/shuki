//! Command handlers (owned by `leaf/cli-commands-all`).

pub(crate) mod entry_ops;
pub(crate) mod init;
pub(crate) mod key_cmd;
pub(crate) mod sync_cmd;
pub(crate) mod whoami;

use crate::cli::Prompter;
use crate::domain::SecretField;
use crate::error::{Result, ShukiError};

/// Prompt for `what` twice; on mismatch allow exactly one retry, then
/// [`ShukiError::Cancelled`].
pub(crate) fn prompt_secret_twice(p: &mut dyn Prompter, what: &str) -> Result<SecretField> {
    for attempt in 0..2 {
        let a = p.prompt_secret(&format!("Enter {what}: "))?;
        let b = p.prompt_secret(&format!("Retype {what}: "))?;
        if a == b {
            return Ok(a);
        }
        if attempt == 0 {
            eprintln!("Entries do not match; one more try.");
        }
    }
    Err(ShukiError::Cancelled)
}

/// Relay URLs must be websocket URLs.
pub(crate) fn validate_relay_url(url: &str) -> Result<()> {
    if url.starts_with("ws://") || url.starts_with("wss://") {
        Ok(())
    } else {
        Err(ShukiError::Config(format!(
            "relay url must start with ws:// or wss://: {url}"
        )))
    }
}
