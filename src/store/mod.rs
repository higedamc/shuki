//! Local ciphertext store contract. Implementations persist ONLY ciphertext
//! (`CipherEntry.payload` is a NIP-44 base64 string) plus non-secret sync
//! bookkeeping. Blocking API — async callers wrap in `spawn_blocking`.

pub mod fs;
pub mod syncstate;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// One encrypted entry, exactly as published to relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherEntry {
    /// Lowercase-hex HMAC of the path (public, meaningless without the tag key).
    pub d_tag: String,
    /// NIP-44 base64 payload string (the Nostr event `content`).
    pub payload: String,
}

/// Non-secret per-entry sync bookkeeping.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EntrySyncState {
    /// Last event id we published/accepted for this d-tag.
    pub event_id: Option<String>,
    /// `created_at` of that event (drives relay replaceability).
    pub event_created_at: Option<u64>,
    /// Local change not yet pushed.
    pub dirty: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub entries: BTreeMap<String, EntrySyncState>,
    pub last_sync_at: Option<u64>,
}

/// Persistence for ciphertext entries + sync state.
pub trait VaultStore: Send + Sync {
    fn list(&self) -> Result<Vec<CipherEntry>>;
    fn get(&self, d_tag: &str) -> Result<Option<CipherEntry>>;
    /// Atomic write (tmp + rename), file mode 0600.
    fn put(&self, entry: &CipherEntry) -> Result<()>;
    fn remove(&self, d_tag: &str) -> Result<()>;
    fn load_sync_state(&self) -> Result<SyncState>;
    fn save_sync_state(&self, s: &SyncState) -> Result<()>;
}
