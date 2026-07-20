//! [`super::SyncApi`] implementation (owned by `leaf/sync-nostr-engine`).
//!
//! `reconcile()` is a pure function over (local sync state, remote events) so
//! LWW logic is unit-testable without a relay. When local wins a conflict,
//! republish with `created_at = max(remote_created_at + 1, now)` so the relay
//! actually replaces the stored event.

use std::sync::Arc;

use crate::config::Config;
use crate::signer::Signer;
use crate::store::VaultStore;

pub struct SyncEngine {
    _private: (),
}

impl SyncEngine {
    pub fn new(_signer: Arc<dyn Signer>, _store: Arc<dyn VaultStore>, _config: Config) -> Self {
        todo!("leaf/sync-nostr-engine")
    }
}
