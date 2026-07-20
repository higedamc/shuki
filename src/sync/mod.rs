//! Nostr relay sync contract.

pub mod engine;
pub mod payload;
pub mod relays;

use async_trait::async_trait;

use crate::error::Result;

/// Outcome of a sync run (shown to the user).
#[derive(Debug, Default)]
pub struct SyncReport {
    pub pushed: u32,
    pub pulled: u32,
    pub tombstones_applied: u32,
    /// Conflicts resolved by last-write-wins.
    pub conflicts_lww: u32,
    /// (d_tag or relay url, message) — non-fatal per-item failures.
    pub errors: Vec<(String, String)>,
}

#[async_trait]
pub trait SyncApi: Send + Sync {
    /// Pull remote changes, reconcile (LWW on payload `updated_at`,
    /// tie-break on event id), push dirty local entries.
    async fn sync(&self) -> Result<SyncReport>;

    /// Disaster recovery: fetch ALL kind-30078 events by our author,
    /// try-decrypt each, keep payloads with `app == "shuki"`.
    async fn restore_all(&self) -> Result<SyncReport>;

    /// Publish our relay list as NIP-65 (kind 10002).
    async fn publish_relay_list(&self) -> Result<()>;

    /// Fetch our NIP-65 relay list from the configured relays.
    async fn fetch_relay_list(&self) -> Result<Vec<String>>;
}
