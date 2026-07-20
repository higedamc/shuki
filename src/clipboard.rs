//! Clipboard with auto-clear (owned by `leaf/clipboard-util-autoclear`).
//!
//! `copy_secret` copies and spawns a tokio task that clears the clipboard
//! after the TTL — but only if the clipboard still holds our value (never
//! clobber something the user copied afterwards).
//!
//! # Platform caveats
//!
//! "Clearing" means writing an empty string. On macOS the pasteboard has
//! already been observed by any running clipboard managers by then, and
//! `arboard` has no support for the concealed pasteboard type
//! (`org.nspasteboard.ConcealedType`), so secrets may persist in
//! clipboard-manager history. This is a documented limitation covered by the
//! README threat model.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::domain::SecretField;
use crate::error::{Result, ShukiError};

/// Copies secrets to the system clipboard and auto-clears them after a TTL.
///
/// The underlying `arboard` context is created lazily per operation (it is
/// not `Send` on all platforms, so each copy/clear opens its own short-lived
/// handle). Overlapping copies are safe: a second [`Clipboard::copy_secret`]
/// supersedes the first, whose deferred clear no-ops because the clipboard
/// contents no longer match what it set (compare-before-clear).
pub struct Clipboard {
    clear_after: Duration,
}

impl Clipboard {
    /// Infallible: the underlying provider is initialized lazily on first copy.
    pub fn new(clear_after: Duration) -> Self {
        Self { clear_after }
    }

    /// Copy `secret` to the system clipboard and schedule an auto-clear.
    ///
    /// Must be called from within a tokio runtime: the deferred clear runs in
    /// a task spawned via [`tokio::spawn`] (calling outside a runtime panics).
    ///
    /// After the configured TTL the task re-opens the clipboard and clears it
    /// (sets an empty string) **only if** the current contents still equal
    /// what was copied here; anything the user copied in the meantime is left
    /// untouched. The deferred clear is best-effort: failures to re-open or
    /// read the clipboard at expiry are ignored.
    ///
    /// # Errors
    ///
    /// [`ShukiError::Clipboard`] if the clipboard cannot be opened or written
    /// (e.g. headless Linux without an X11/Wayland session).
    pub fn copy_secret(&self, secret: &SecretField) -> Result<()> {
        let mut clipboard = open()?;
        clipboard
            .set_text(secret.expose())
            .map_err(|e| ShukiError::Clipboard(e.to_string()))?;
        drop(clipboard);

        // Keep our own zeroizing copy for the compare-before-clear check.
        let expected = Zeroizing::new(secret.expose().to_owned());
        let ttl = self.clear_after;
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            // Best-effort from here on: never panic inside the drain task.
            let Ok(mut clipboard) = open() else {
                return;
            };
            let Ok(current) = clipboard.get_text() else {
                // Unreadable/empty clipboard: nothing of ours left to clear.
                return;
            };
            let current = Zeroizing::new(current);
            if *current == *expected {
                let _ = clipboard.set_text("");
            }
        });
        Ok(())
    }
}

/// Open a fresh per-operation clipboard context.
fn open() -> Result<arboard::Clipboard> {
    arboard::Clipboard::new().map_err(|e| ShukiError::Clipboard(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system clipboard is a global resource; serialize the tests that
    /// touch it so `cargo test`'s parallelism cannot interleave them.
    /// Async-aware because the guard is held across `sleep().await`.
    static CLIPBOARD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn read_clipboard() -> String {
        // An empty/unreadable clipboard reads as "".
        arboard::Clipboard::new()
            .unwrap()
            .get_text()
            .unwrap_or_default()
    }

    fn clear_clipboard() {
        let _ = arboard::Clipboard::new().unwrap().set_text("");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn copy_then_auto_clear_after_ttl() {
        if arboard::Clipboard::new().is_err() {
            eprintln!("skip: no clipboard");
            return;
        }
        let _guard = CLIPBOARD_LOCK.lock().await;

        let secret_text = "shuki-test-autoclear-disposable";
        let cb = Clipboard::new(Duration::from_millis(300));
        cb.copy_secret(&SecretField::from(secret_text)).unwrap();

        assert_eq!(read_clipboard(), secret_text, "copy must land verbatim");

        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_ne!(
            read_clipboard(),
            secret_text,
            "secret must be cleared after the TTL"
        );

        clear_clipboard();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn does_not_clobber_user_copy_mid_ttl() {
        if arboard::Clipboard::new().is_err() {
            eprintln!("skip: no clipboard");
            return;
        }
        let _guard = CLIPBOARD_LOCK.lock().await;

        let secret_text = "shuki-test-superseded-disposable";
        let user_text = "shuki-test-user-copy-disposable";
        let cb = Clipboard::new(Duration::from_millis(300));
        cb.copy_secret(&SecretField::from(secret_text)).unwrap();

        // The user copies something else before the TTL fires.
        tokio::time::sleep(Duration::from_millis(100)).await;
        arboard::Clipboard::new()
            .unwrap()
            .set_text(user_text)
            .unwrap();

        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            read_clipboard(),
            user_text,
            "a newer user copy must never be clobbered by the deferred clear"
        );

        clear_clipboard();
    }
}
