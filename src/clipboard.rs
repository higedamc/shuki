//! Clipboard with auto-clear (owned by `leaf/clipboard-util-autoclear`).
//!
//! `copy_secret` copies and spawns a tokio task that clears the clipboard
//! after the TTL — but only if the clipboard still holds our value (never
//! clobber something the user copied afterwards).

use std::time::Duration;

use crate::domain::SecretField;
use crate::error::Result;

pub struct Clipboard {
    _private: (),
}

impl Clipboard {
    /// Infallible: the underlying provider is initialized lazily on first copy.
    pub fn new(_clear_after: Duration) -> Self {
        todo!("leaf/clipboard-util-autoclear")
    }

    pub fn copy_secret(&self, _secret: &SecretField) -> Result<()> {
        todo!("leaf/clipboard-util-autoclear")
    }
}
