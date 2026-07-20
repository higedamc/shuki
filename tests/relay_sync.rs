//! End-to-end sync tests against a real local Nostr relay.
//!
//! Requires a relay at `ws://127.0.0.1:7000`, e.g.:
//! `docker run --rm -p 7000:8080 scsibug/nostr-rs-relay`
//! Run with: `cargo test --features relay-tests -- --ignored`
//!
//! Uses an in-memory `VaultStore` (the filesystem store lives on another
//! leaf) and `MockSigner` from `shuki::testutil`.

#![cfg(feature = "relay-tests")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use shuki::config::{Config, NetMode, SignerConfig};
use shuki::domain::{Entry, EntryFields, SecretField, VaultPath};
use shuki::error::Result;
use shuki::signer::Signer;
use shuki::store::{CipherEntry, EntrySyncState, SyncState, VaultStore};
use shuki::sync::engine::SyncEngine;
use shuki::sync::payload::SyncPayload;
use shuki::sync::SyncApi;
use shuki::testutil::MockSigner;

const RELAY_URL: &str = "ws://127.0.0.1:7000";

/// In-memory [`VaultStore`] for tests (ciphertext + sync state only).
#[derive(Default)]
struct MemStore {
    inner: Mutex<(BTreeMap<String, CipherEntry>, SyncState)>,
}

impl VaultStore for MemStore {
    fn list(&self) -> Result<Vec<CipherEntry>> {
        Ok(self.inner.lock().unwrap().0.values().cloned().collect())
    }
    fn get(&self, d_tag: &str) -> Result<Option<CipherEntry>> {
        Ok(self.inner.lock().unwrap().0.get(d_tag).cloned())
    }
    fn put(&self, entry: &CipherEntry) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .0
            .insert(entry.d_tag.clone(), entry.clone());
        Ok(())
    }
    fn remove(&self, d_tag: &str) -> Result<()> {
        self.inner.lock().unwrap().0.remove(d_tag);
        Ok(())
    }
    fn load_sync_state(&self) -> Result<SyncState> {
        Ok(self.inner.lock().unwrap().1.clone())
    }
    fn save_sync_state(&self, s: &SyncState) -> Result<()> {
        self.inner.lock().unwrap().1 = s.clone();
        Ok(())
    }
}

fn test_config() -> Config {
    Config {
        signer: SignerConfig::Software,
        relays: vec![RELAY_URL.to_owned()],
        net: NetMode::Clearnet,
        ..Config::default()
    }
}

fn entry_payload(path: &str, secret: &str, updated_at: u64) -> SyncPayload {
    SyncPayload::from_entry(&Entry {
        path: VaultPath::parse(path).unwrap(),
        fields: EntryFields {
            password: Some(SecretField::from(secret)),
            ..Default::default()
        },
        updated_at,
    })
}

/// Encrypt `payload` with `signer` and stage it in `store` as a dirty entry.
async fn stage_dirty(signer: &MockSigner, store: &MemStore, d_tag: &str, payload: &SyncPayload) {
    let pk = signer.public_key().await.unwrap();
    let ct = signer
        .nip44_encrypt(&pk, &payload.encode().unwrap())
        .await
        .unwrap();
    store
        .put(&CipherEntry {
            d_tag: d_tag.to_owned(),
            payload: ct,
        })
        .unwrap();
    let mut state = store.load_sync_state().unwrap();
    state.entries.insert(
        d_tag.to_owned(),
        EntrySyncState {
            dirty: true,
            ..state.entries.get(d_tag).cloned().unwrap_or_default()
        },
    );
    store.save_sync_state(&state).unwrap();
}

fn sorted_ciphers(store: &MemStore) -> Vec<CipherEntry> {
    let mut v = store.list().unwrap();
    v.sort_by(|a, b| a.d_tag.cmp(&b.d_tag));
    v
}

/// (a) Engine A pushes 3 entries; engine B (same keys, empty store)
/// restore_all → identical CipherEntry sets.
#[tokio::test]
#[ignore = "requires local relay: docker run --rm -p 7000:8080 scsibug/nostr-rs-relay"]
async fn push_then_restore_roundtrip() {
    let signer_a = MockSigner::new();
    let keys = signer_a.keys().clone();

    let store_a = Arc::new(MemStore::default());
    let now = 1_700_000_000u64;
    stage_dirty(
        &signer_a,
        &store_a,
        &"a1".repeat(32),
        &entry_payload("web/one", "s1", now),
    )
    .await;
    stage_dirty(
        &signer_a,
        &store_a,
        &"b2".repeat(32),
        &entry_payload("web/two", "s2", now + 1),
    )
    .await;
    stage_dirty(
        &signer_a,
        &store_a,
        &"c3".repeat(32),
        &entry_payload("mail/three", "s3", now + 2),
    )
    .await;

    let engine_a = SyncEngine::new(Arc::new(signer_a), store_a.clone(), test_config());
    let report = engine_a.sync().await.unwrap();
    assert_eq!(report.pushed, 3, "errors: {:?}", report.errors);
    assert!(report.errors.is_empty());

    // Same identity, empty store → disaster recovery.
    let store_b = Arc::new(MemStore::default());
    let engine_b = SyncEngine::new(
        Arc::new(MockSigner::from_keys(keys)),
        store_b.clone(),
        test_config(),
    );
    let report_b = engine_b.restore_all().await.unwrap();
    assert_eq!(report_b.pulled, 3, "errors: {:?}", report_b.errors);
    assert_eq!(report_b.tombstones_applied, 0);

    // The relay stores our ciphertext verbatim → identical CipherEntry sets.
    assert_eq!(sorted_ciphers(&store_a), sorted_ciphers(&store_b));

    // Sync state was rebuilt for every pulled entry.
    let state_b = store_b.load_sync_state().unwrap();
    assert_eq!(state_b.entries.len(), 3);
    assert!(state_b
        .entries
        .values()
        .all(|e| !e.dirty && e.event_id.is_some()));
}

/// (b) A tombstone pushed by A replaces the live entry on B.
#[tokio::test]
#[ignore = "requires local relay: docker run --rm -p 7000:8080 scsibug/nostr-rs-relay"]
async fn tombstone_propagates() {
    let signer_a = MockSigner::new();
    let keys = signer_a.keys().clone();
    let d_tag = "d4".repeat(32);
    let now = 1_700_000_000u64;

    // A pushes a live entry.
    let store_a = Arc::new(MemStore::default());
    stage_dirty(
        &signer_a,
        &store_a,
        &d_tag,
        &entry_payload("web/doomed", "pw", now),
    )
    .await;
    let signer_a = Arc::new(signer_a);
    let engine_a = SyncEngine::new(signer_a.clone(), store_a.clone(), test_config());
    assert_eq!(engine_a.sync().await.unwrap().pushed, 1);

    // B receives it.
    let store_b = Arc::new(MemStore::default());
    let engine_b = SyncEngine::new(
        Arc::new(MockSigner::from_keys(keys)),
        store_b.clone(),
        test_config(),
    );
    assert_eq!(engine_b.sync().await.unwrap().pulled, 1);
    assert!(store_b.get(&d_tag).unwrap().is_some());

    // A deletes: newer tombstone replaces the same d tag.
    let tomb = SyncPayload::tombstone(VaultPath::parse("web/doomed").unwrap(), now + 10);
    stage_dirty(&signer_a, &store_a, &d_tag, &tomb).await;
    assert_eq!(engine_a.sync().await.unwrap().pushed, 1);

    // B pulls the tombstone.
    let report = engine_b.sync().await.unwrap();
    assert_eq!(report.pulled, 1, "errors: {:?}", report.errors);
    assert_eq!(report.tombstones_applied, 1);

    // B's stored ciphertext now decodes to the tombstone.
    let cipher = store_b
        .get(&d_tag)
        .unwrap()
        .expect("tombstone kept as ciphertext");
    let pk = signer_a.public_key().await.unwrap();
    let pt = signer_a.nip44_decrypt(&pk, &cipher.payload).await.unwrap();
    let payload = SyncPayload::decode(&pt).unwrap();
    assert!(payload.deleted);
    assert_eq!(payload.updated_at, now + 10);
}
