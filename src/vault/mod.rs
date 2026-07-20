//! The [`Vault`] facade — what CLI and TUI program against.

pub mod service;

use async_trait::async_trait;

use crate::domain::{Entry, VaultPath};
use crate::error::Result;

/// High-level decrypted view over the encrypted store.
///
/// Implementations combine a [`crate::signer::Signer`] (conversation key),
/// [`crate::store::VaultStore`] (ciphertext persistence) and
/// [`crate::crypto`] (d-tags). Plaintext exists only in return values.
#[async_trait]
pub trait Vault: Send + Sync {
    /// Decrypt all entries once and build the in-memory path index.
    async fn open(&self) -> Result<()>;

    /// All live entry paths (tombstones excluded), sorted.
    async fn list_paths(&self) -> Result<Vec<VaultPath>>;

    async fn get(&self, path: &VaultPath) -> Result<Entry>;

    /// Insert or update; stamps `updated_at = now` and marks the entry dirty
    /// for the next sync.
    async fn put(&self, entry: Entry) -> Result<()>;

    /// Delete: writes an encrypted tombstone (so deletion syncs) and marks dirty.
    async fn remove(&self, path: &VaultPath) -> Result<()>;

    /// `put(to)` + tombstone(from), atomically from the caller's perspective.
    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<()>;

    /// Case-insensitive substring search over paths.
    async fn find(&self, query: &str) -> Result<Vec<VaultPath>>;
}
