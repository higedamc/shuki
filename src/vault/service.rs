//! [`super::Vault`] implementation (owned by `leaf/vault-core-service`).
//!
//! # Crypto path
//!
//! [`VaultService::open`] fetches [`Signer::self_conversation_key`] once and
//! caches it for the lifetime of the open state. All entry encryption and
//! decryption then runs host-side through the `nostr::nips::nip44::v2`
//! conversation-key APIs ([`nip44v2::encrypt_to_bytes`] /
//! [`nip44v2::decrypt_to_bytes`]) with the standard base64 encoding, i.e. the
//! stored/published payload string is the canonical NIP-44
//! `base64(version || nonce || ciphertext || mac)` format — byte-for-byte the
//! same format the high-level `nip44::encrypt` produces (cross-checked in
//! tests against [`crate::testutil::MockSigner`]).
//!
//! # No-conversation-key backends (accepted simplification)
//!
//! If the signer returns [`ShukiError::Unsupported`] from
//! `self_conversation_key`, `open()` propagates that error ("this signer
//! backend cannot open a vault yet"). Per-entry `signer.nip44_encrypt /
//! nip44_decrypt` could cover payload crypto, but the d-tag key
//! ([`crate::crypto::tagkey::derive_tag_key`]) is derived *from* the
//! conversation key and has no deterministic fallback derivation; a future
//! hardware backend without an exportable conversation key needs a separate
//! tag-key derivation contract first. Both v1 backends (software keychain,
//! NSD) do support `self_conversation_key`.
//!
//! # Lazy open
//!
//! Every operation auto-opens the vault on first use (`ensure_open`), so
//! callers may skip an explicit `open()`. An explicit `open()` always
//! rebuilds the index from the store (useful after an external sync).
//!
//! # Timestamps
//!
//! `put`/`remove`/`rename` stamp `updated_at` themselves with
//! `max(now, last_stamp + 1)`, making stamps strictly monotonic within a
//! session even when several writes land in the same wall-clock second —
//! this keeps last-write-wins reconciliation well-ordered. The floor is
//! seeded from the largest `updated_at` seen at open time. The caller's
//! `Entry::updated_at` is ignored on `put`.
//!
//! # Rename atomicity
//!
//! `rename` writes the entry under the new d-tag *before* tombstoning the
//! old one. It is atomic from the caller's perspective (one write lock), but
//! not across process crashes: the worst case after a crash between the two
//! store writes is a duplicate entry under both paths — never data loss.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use nostr::nips::nip44::v2::{self as nip44v2, ConversationKey};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::Vault;
use crate::crypto::memlock::LockedBox;
use crate::crypto::tagkey::{d_tag, derive_tag_key};
use crate::crypto::TagKey;
use crate::domain::{Entry, VaultPath};
use crate::error::{Result, ShukiError};
use crate::signer::Signer;
use crate::store::{CipherEntry, VaultStore};
use crate::sync::payload::SyncPayload;

/// Decrypted in-memory view, built once per `open()`.
struct OpenState {
    /// Self conversation key (cached; devices are asked once). Kept on
    /// page-locked memory and shared as an `Arc` so operations reference it
    /// across store IO instead of copying the key out of the locked pages.
    conversation_key: Arc<LockedBox<ConversationKey>>,
    /// HMAC key for path → d-tag derivation.
    tag_key: TagKey,
    /// Live entries: path → d-tag of the ciphertext file that holds it.
    /// Normally the canonical `d_tag(tag_key, path)`; after self-healing a
    /// d-tag mismatch it is the stored (actual) file's d-tag.
    index: BTreeMap<VaultPath, String>,
    /// Tombstoned paths → d-tag (kept out of the live index; the ciphertext
    /// stays in the store so the sync engine pushes the deletion).
    tombstones: BTreeMap<VaultPath, String>,
    /// Floor for strictly-monotonic `updated_at` stamping.
    last_stamp: u64,
}

/// The production [`Vault`]: NIP-44 self-encryption over a ciphertext store.
pub struct VaultService {
    signer: Arc<dyn Signer>,
    store: Arc<dyn VaultStore>,
    state: RwLock<Option<OpenState>>,
}

impl VaultService {
    pub fn new(signer: Arc<dyn Signer>, store: Arc<dyn VaultStore>) -> Self {
        Self {
            signer,
            store,
            state: RwLock::new(None),
        }
    }

    /// Open lazily if no state exists yet (see module docs).
    async fn ensure_open(&self) -> Result<()> {
        if self.state.read().await.is_some() {
            return Ok(());
        }
        let mut guard = self.state.write().await;
        if guard.is_none() {
            *guard = Some(self.build_state().await?);
        }
        Ok(())
    }

    /// Decrypt every stored entry and build the path index.
    async fn build_state(&self) -> Result<OpenState> {
        let ck = self
            .signer
            .self_conversation_key()
            .await
            .map_err(|e| match e {
                ShukiError::Unsupported(msg) => ShukiError::Unsupported(format!(
                    "this signer backend cannot open a vault yet \
                     (no exportable self conversation key): {msg}"
                )),
                other => other,
            })?;
        // Move the key onto its own locked pages immediately; everything
        // below works through references into that allocation.
        let ck = LockedBox::new(ck);
        let tag_key = derive_tag_key(&ck);
        let entries = store_blocking(&self.store, |s| s.list()).await?;

        // path → (d_tag, updated_at, deleted); duplicates resolved by
        // last-write-wins on `updated_at` (duplicates can only appear after
        // a crashed rename or a healed d-tag mismatch).
        let mut seen: BTreeMap<VaultPath, (String, u64, bool)> = BTreeMap::new();
        let mut last_stamp: u64 = 0;
        for ce in entries {
            let plain = match decrypt_payload(&ck, &ce.payload) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(d_tag = %ce.d_tag, "skipping undecryptable entry");
                    continue;
                }
            };
            let payload = match SyncPayload::decode(&plain) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(d_tag = %ce.d_tag, "skipping corrupt/foreign entry");
                    continue;
                }
            };
            drop(plain);
            let expected = d_tag(&tag_key, &payload.path);
            if expected != ce.d_tag {
                // Self-heal: trust the authenticated (decrypted) path and
                // index the file where it actually lives.
                tracing::warn!(
                    stored = %ce.d_tag,
                    expected = %expected,
                    "d-tag mismatch; trusting decrypted path"
                );
            }
            last_stamp = last_stamp.max(payload.updated_at);
            let newer = match seen.get(&payload.path) {
                Some((_, ts, _)) => payload.updated_at > *ts,
                None => true,
            };
            if newer {
                seen.insert(
                    payload.path,
                    (ce.d_tag, payload.updated_at, payload.deleted),
                );
            }
        }

        let mut index = BTreeMap::new();
        let mut tombstones = BTreeMap::new();
        for (path, (dt, _, deleted)) in seen {
            if deleted {
                tombstones.insert(path, dt);
            } else {
                index.insert(path, dt);
            }
        }
        Ok(OpenState {
            conversation_key: Arc::new(ck),
            tag_key,
            index,
            tombstones,
            last_stamp,
        })
    }

    /// Strictly-monotonic unix-seconds stamp (see module docs).
    fn stamp(st: &mut OpenState) -> u64 {
        let s = now_unix().max(st.last_stamp.saturating_add(1));
        st.last_stamp = s;
        s
    }

    /// Encrypt `payload` and persist it under `d_tag`, marking it dirty in
    /// the sync state (existing `event_id` / `event_created_at` are kept).
    async fn write_encrypted(
        &self,
        ck: &ConversationKey,
        d_tag: String,
        payload: &SyncPayload,
    ) -> Result<()> {
        let plain = Zeroizing::new(payload.encode()?);
        let cipher = encrypt_payload(ck, &plain)?;
        drop(plain);
        let ce = CipherEntry {
            d_tag,
            payload: cipher,
        };
        store_blocking(&self.store, move |s| {
            s.put(&ce)?;
            let mut ss = s.load_sync_state()?;
            ss.entries.entry(ce.d_tag.clone()).or_default().dirty = true;
            s.save_sync_state(&ss)
        })
        .await
    }

    /// Fetch + decrypt + decode the live payload stored under `d_tag`.
    async fn read_payload(
        &self,
        ck: Arc<LockedBox<ConversationKey>>,
        d_tag: String,
    ) -> Result<Option<SyncPayload>> {
        let ce = store_blocking(&self.store, move |s| s.get(&d_tag)).await?;
        let Some(ce) = ce else { return Ok(None) };
        let plain = decrypt_payload(&ck, &ce.payload)?;
        Ok(Some(SyncPayload::decode(&plain)?))
    }
}

#[async_trait]
impl Vault for VaultService {
    async fn open(&self) -> Result<()> {
        // Hold the write lock during the rebuild so concurrent writes
        // cannot interleave with the store listing.
        let mut guard = self.state.write().await;
        *guard = Some(self.build_state().await?);
        Ok(())
    }

    async fn list_paths(&self) -> Result<Vec<VaultPath>> {
        self.ensure_open().await?;
        let guard = self.state.read().await;
        let st = state_ref(&guard)?;
        Ok(st.index.keys().cloned().collect())
    }

    async fn get(&self, path: &VaultPath) -> Result<Entry> {
        self.ensure_open().await?;
        let guard = self.state.read().await;
        let st = state_ref(&guard)?;
        let dt = st
            .index
            .get(path)
            .cloned()
            .ok_or_else(|| ShukiError::NotFound(path.as_str().to_owned()))?;
        let ck = Arc::clone(&st.conversation_key);
        drop(guard);
        let payload = self
            .read_payload(ck, dt)
            .await?
            .filter(|p| !p.deleted)
            .ok_or_else(|| ShukiError::NotFound(path.as_str().to_owned()))?;
        Ok(Entry {
            path: payload.path,
            fields: payload.fields,
            updated_at: payload.updated_at,
        })
    }

    async fn put(&self, entry: Entry) -> Result<()> {
        self.ensure_open().await?;
        let mut guard = self.state.write().await;
        let st = state_mut(&mut guard)?;
        let mut entry = entry;
        entry.updated_at = Self::stamp(st);
        let dt = d_tag(&st.tag_key, &entry.path);
        let ck = Arc::clone(&st.conversation_key);
        let payload = SyncPayload::from_entry(&entry);
        self.write_encrypted(&ck, dt.clone(), &payload).await?;
        let st = state_mut(&mut guard)?;
        st.tombstones.remove(&entry.path);
        st.index.insert(entry.path, dt);
        Ok(())
    }

    async fn remove(&self, path: &VaultPath) -> Result<()> {
        self.ensure_open().await?;
        let mut guard = self.state.write().await;
        let st = state_mut(&mut guard)?;
        let dt = st
            .index
            .get(path)
            .cloned()
            .ok_or_else(|| ShukiError::NotFound(path.as_str().to_owned()))?;
        let ts = Self::stamp(st);
        let ck = Arc::clone(&st.conversation_key);
        let tomb = SyncPayload::tombstone(path.clone(), ts);
        // Replaces the live ciphertext under the SAME d-tag; the tombstone
        // stays in the store so the sync engine pushes the deletion and the
        // entry cannot resurrect from a stale relay copy.
        self.write_encrypted(&ck, dt.clone(), &tomb).await?;
        let st = state_mut(&mut guard)?;
        st.index.remove(path);
        st.tombstones.insert(path.clone(), dt);
        Ok(())
    }

    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<()> {
        self.ensure_open().await?;
        let mut guard = self.state.write().await;
        let st = state_mut(&mut guard)?;
        if st.index.contains_key(to) {
            return Err(ShukiError::AlreadyExists(to.as_str().to_owned()));
        }
        let from_dt = st
            .index
            .get(from)
            .cloned()
            .ok_or_else(|| ShukiError::NotFound(from.as_str().to_owned()))?;
        let ck = Arc::clone(&st.conversation_key);
        let old = self
            .read_payload(Arc::clone(&ck), from_dt.clone())
            .await?
            .filter(|p| !p.deleted)
            .ok_or_else(|| ShukiError::NotFound(from.as_str().to_owned()))?;

        // 1) Write the entry under the new path first (crash ⇒ duplicate,
        //    never loss).
        let st = state_mut(&mut guard)?;
        let entry = Entry {
            path: to.clone(),
            fields: old.fields,
            updated_at: Self::stamp(st),
        };
        let to_dt = d_tag(&st.tag_key, to);
        let payload = SyncPayload::from_entry(&entry);
        self.write_encrypted(&ck, to_dt.clone(), &payload).await?;
        let st = state_mut(&mut guard)?;
        st.tombstones.remove(to);
        st.index.insert(to.clone(), to_dt);

        // 2) Tombstone the old path.
        let ts = Self::stamp(st);
        let tomb = SyncPayload::tombstone(from.clone(), ts);
        self.write_encrypted(&ck, from_dt.clone(), &tomb).await?;
        let st = state_mut(&mut guard)?;
        st.index.remove(from);
        st.tombstones.insert(from.clone(), from_dt);
        Ok(())
    }

    async fn find(&self, query: &str) -> Result<Vec<VaultPath>> {
        self.ensure_open().await?;
        let guard = self.state.read().await;
        let st = state_ref(&guard)?;
        let q = query.to_lowercase();
        Ok(st
            .index
            .keys()
            .filter(|p| p.as_str().to_lowercase().contains(&q))
            .cloned()
            .collect())
    }
}

fn state_ref(guard: &Option<OpenState>) -> Result<&OpenState> {
    guard
        .as_ref()
        .ok_or_else(|| ShukiError::Other("vault not opened".into()))
}

fn state_mut(guard: &mut Option<OpenState>) -> Result<&mut OpenState> {
    guard
        .as_mut()
        .ok_or_else(|| ShukiError::Other("vault not opened".into()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run a blocking [`VaultStore`] operation off the async runtime.
async fn store_blocking<T, F>(store: &Arc<dyn VaultStore>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn VaultStore) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || f(store.as_ref()))
        .await
        .map_err(|e| ShukiError::Other(format!("blocking store task: {e}")))?
}

/// NIP-44 v2 encrypt to the standard base64 payload string
/// (`base64(version || nonce || ciphertext || mac)`).
fn encrypt_payload(ck: &ConversationKey, plaintext: &[u8]) -> Result<String> {
    let bytes = nip44v2::encrypt_to_bytes(ck, plaintext)
        .map_err(|e| ShukiError::Crypto(format!("nip44 encrypt: {e}")))?;
    Ok(BASE64.encode(bytes))
}

/// Decrypt a standard base64 NIP-44 payload string (v2 only).
fn decrypt_payload(ck: &ConversationKey, payload: &str) -> Result<Zeroizing<Vec<u8>>> {
    let raw = BASE64
        .decode(payload)
        .map_err(|e| ShukiError::Crypto(format!("nip44 payload base64: {e}")))?;
    match raw.first() {
        Some(2) => {}
        Some(v) => {
            return Err(ShukiError::Crypto(format!(
                "unsupported nip44 version: {v}"
            )));
        }
        None => return Err(ShukiError::Crypto("empty nip44 payload".into())),
    }
    nip44v2::decrypt_to_bytes(ck, &raw)
        .map(Zeroizing::new)
        .map_err(|e| ShukiError::Crypto(format!("nip44 decrypt: {e}")))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use nostr::{Event, Keys, PublicKey, UnsignedEvent};

    use super::*;
    use crate::domain::{EntryFields, SecretField};
    use crate::store::SyncState;
    use crate::testutil::MockSigner;

    // ---- in-memory VaultStore (fs.rs is a different leaf) ----------------

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

    // ---- helpers ---------------------------------------------------------

    fn service(keys: &Keys, store: &Arc<MemStore>) -> VaultService {
        VaultService::new(
            Arc::new(MockSigner::from_keys(keys.clone())),
            Arc::clone(store) as Arc<dyn VaultStore>,
        )
    }

    fn setup() -> (Keys, Arc<MemStore>, VaultService) {
        let keys = Keys::generate();
        let store = Arc::new(MemStore::default());
        let svc = service(&keys, &store);
        (keys, store, svc)
    }

    fn path(s: &str) -> VaultPath {
        VaultPath::parse(s).unwrap()
    }

    fn sample_entry(p: &str) -> Entry {
        let mut custom = BTreeMap::new();
        custom.insert("totp".to_owned(), SecretField::from("JBSWY3DP"));
        custom.insert("pin".to_owned(), SecretField::from("1234"));
        Entry {
            path: path(p),
            fields: EntryFields {
                password: Some(SecretField::from("s3cret!")),
                username: Some("alice".into()),
                url: Some("https://example.com".into()),
                notes: Some(SecretField::from("multi\nline note")),
                custom,
            },
            updated_at: 0, // stamped by put()
        }
    }

    fn own_ck(keys: &Keys) -> ConversationKey {
        ConversationKey::derive(keys.secret_key(), &keys.public_key()).unwrap()
    }

    fn own_d_tag(keys: &Keys, p: &VaultPath) -> String {
        d_tag(&derive_tag_key(&own_ck(keys)), p)
    }

    // ---- tests -----------------------------------------------------------

    #[tokio::test]
    async fn put_get_roundtrip_preserves_all_fields_with_lazy_open() {
        let (_, _, svc) = setup();
        // No explicit open(): first op auto-opens.
        let e = sample_entry("web/example.com/alice");
        svc.put(e.clone()).await.unwrap();
        let back = svc.get(&e.path).await.unwrap();
        assert_eq!(back.path, e.path);
        assert_eq!(back.fields, e.fields);
        assert!(back.updated_at > 0);
    }

    #[tokio::test]
    async fn list_paths_sorted_and_excludes_tombstones() {
        let (_, _, svc) = setup();
        for p in ["b/two", "a/one", "c/three"] {
            svc.put(sample_entry(p)).await.unwrap();
        }
        svc.remove(&path("c/three")).await.unwrap();
        let paths = svc.list_paths().await.unwrap();
        let strs: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
        assert_eq!(strs, ["a/one", "b/two"]);
    }

    #[tokio::test]
    async fn remove_yields_not_found_and_leaves_decryptable_tombstone() {
        let (keys, store, svc) = setup();
        assert!(matches!(
            svc.remove(&path("no/such")).await,
            Err(ShukiError::NotFound(_))
        ));

        let p = path("web/gone");
        svc.put(sample_entry("web/gone")).await.unwrap();
        svc.remove(&p).await.unwrap();
        assert!(matches!(svc.get(&p).await, Err(ShukiError::NotFound(_))));

        // The tombstone ciphertext stays in the store under the same d-tag
        // and decrypts (via the high-level signer API) to deleted:true.
        let dt = own_d_tag(&keys, &p);
        let ce = store.get(&dt).unwrap().expect("tombstone file present");
        let signer = MockSigner::from_keys(keys.clone());
        let pk = keys.public_key();
        let plain = signer.nip44_decrypt(&pk, &ce.payload).await.unwrap();
        let payload = SyncPayload::decode(&plain).unwrap();
        assert!(payload.deleted);
        assert_eq!(payload.path, p);
    }

    #[tokio::test]
    async fn put_resurrects_after_remove_and_survives_reopen() {
        let (keys, store, svc) = setup();
        let p = path("web/back");
        svc.put(sample_entry("web/back")).await.unwrap();
        svc.remove(&p).await.unwrap();
        svc.put(sample_entry("web/back")).await.unwrap();
        assert!(svc.get(&p).await.is_ok());

        // Fresh service over the same store: still live (put outstamps the
        // tombstone).
        let svc2 = service(&keys, &store);
        assert!(svc2.get(&p).await.is_ok());
    }

    #[tokio::test]
    async fn rename_moves_content_and_guards() {
        let (keys, store, svc) = setup();
        let from = path("old/name");
        let to = path("new/name");
        let orig = sample_entry("old/name");
        svc.put(orig.clone()).await.unwrap();
        svc.put(sample_entry("other/entry")).await.unwrap();

        assert!(matches!(
            svc.rename(&path("missing"), &to).await,
            Err(ShukiError::NotFound(_))
        ));
        assert!(matches!(
            svc.rename(&from, &path("other/entry")).await,
            Err(ShukiError::AlreadyExists(_))
        ));

        svc.rename(&from, &to).await.unwrap();
        let moved = svc.get(&to).await.unwrap();
        assert_eq!(moved.fields, orig.fields);
        assert!(matches!(svc.get(&from).await, Err(ShukiError::NotFound(_))));

        // Old d-tag now holds a tombstone (deletion syncs, no resurrection).
        let old_ce = store.get(&own_d_tag(&keys, &from)).unwrap().unwrap();
        let signer = MockSigner::from_keys(keys.clone());
        let pk = keys.public_key();
        let plain = signer.nip44_decrypt(&pk, &old_ce.payload).await.unwrap();
        assert!(SyncPayload::decode(&plain).unwrap().deleted);

        // The move persists across a reopen.
        let svc2 = service(&keys, &store);
        let paths = svc2.list_paths().await.unwrap();
        assert!(paths.contains(&to));
        assert!(!paths.contains(&from));
    }

    #[tokio::test]
    async fn find_is_case_insensitive_substring() {
        let (_, _, svc) = setup();
        for p in ["web/GitHub.com/alice", "web/gitlab.com/bob", "bank/main"] {
            svc.put(sample_entry(p)).await.unwrap();
        }
        let hits = svc.find("GITHUB").await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].as_str(), "web/GitHub.com/alice");
        let git = svc.find("git").await.unwrap();
        assert_eq!(git.len(), 2);
        assert!(svc.find("zzz").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn reopen_rebuilds_identical_index() {
        let (keys, store, svc) = setup();
        for p in ["a/1", "a/2", "b/1"] {
            svc.put(sample_entry(p)).await.unwrap();
        }
        svc.remove(&path("a/2")).await.unwrap();
        let before = svc.list_paths().await.unwrap();

        let svc2 = service(&keys, &store);
        svc2.open().await.unwrap();
        assert_eq!(svc2.list_paths().await.unwrap(), before);
        let e = svc2.get(&path("a/1")).await.unwrap();
        assert_eq!(e.fields, sample_entry("a/1").fields);
        assert!(matches!(
            svc2.get(&path("a/2")).await,
            Err(ShukiError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn put_and_remove_mark_dirty_and_keep_event_bookkeeping() {
        let (keys, store, svc) = setup();
        let p = path("dirty/check");
        svc.put(sample_entry("dirty/check")).await.unwrap();
        let dt = own_d_tag(&keys, &p);
        let ss = store.load_sync_state().unwrap();
        assert!(ss.entries.get(&dt).unwrap().dirty);

        // Simulate the sync engine having pushed the event.
        let mut ss = ss;
        {
            let es = ss.entries.get_mut(&dt).unwrap();
            es.dirty = false;
            es.event_id = Some("evt123".into());
            es.event_created_at = Some(1_700_000_000);
        }
        store.save_sync_state(&ss).unwrap();

        svc.remove(&p).await.unwrap();
        let ss = store.load_sync_state().unwrap();
        let es = ss.entries.get(&dt).unwrap();
        assert!(es.dirty, "remove must re-dirty the entry");
        assert_eq!(es.event_id.as_deref(), Some("evt123"));
        assert_eq!(es.event_created_at, Some(1_700_000_000));
    }

    /// Proof of standard-format compatibility, both directions:
    /// VaultService-encrypted payloads decrypt via the high-level
    /// `nip44::decrypt` path (MockSigner), and high-level `nip44::encrypt`
    /// output is readable by VaultService.
    #[tokio::test]
    async fn payload_format_interoperates_with_high_level_nip44() {
        let (keys, store, svc) = setup();
        let signer = MockSigner::from_keys(keys.clone());
        let pk = keys.public_key();

        // Direction 1: VaultService internals → MockSigner.nip44_decrypt.
        let p = path("compat/ours");
        svc.put(sample_entry("compat/ours")).await.unwrap();
        let ce = store.get(&own_d_tag(&keys, &p)).unwrap().unwrap();
        let plain = signer.nip44_decrypt(&pk, &ce.payload).await.unwrap();
        let payload = SyncPayload::decode(&plain).unwrap();
        assert_eq!(payload.path, p);
        assert_eq!(payload.fields, sample_entry("compat/ours").fields);

        // Direction 2: MockSigner.nip44_encrypt → VaultService open()/get().
        let p2 = path("compat/theirs");
        let foreign = SyncPayload::from_entry(&Entry {
            path: p2.clone(),
            fields: sample_entry("x").fields,
            updated_at: 1_800_000_000,
        });
        let cipher = signer
            .nip44_encrypt(&pk, &foreign.encode().unwrap())
            .await
            .unwrap();
        store
            .put(&CipherEntry {
                d_tag: own_d_tag(&keys, &p2),
                payload: cipher,
            })
            .unwrap();
        svc.open().await.unwrap(); // rebuild index over the injected file
        let got = svc.get(&p2).await.unwrap();
        assert_eq!(got.fields, sample_entry("x").fields);
        assert_eq!(got.updated_at, 1_800_000_000);
    }

    #[tokio::test]
    async fn updated_at_is_strictly_monotonic() {
        let (_, _, svc) = setup();
        let p = path("mono/tonic");
        let mut stamps = Vec::new();
        for _ in 0..3 {
            svc.put(sample_entry("mono/tonic")).await.unwrap();
            stamps.push(svc.get(&p).await.unwrap().updated_at);
        }
        assert!(stamps[0] > 0);
        assert!(stamps[1] > stamps[0]);
        assert!(stamps[2] > stamps[1]);
    }

    #[tokio::test]
    async fn open_skips_undecryptable_and_corrupt_entries() {
        let (keys, store, svc) = setup();
        svc.put(sample_entry("good/entry")).await.unwrap();

        // Garbage (not even base64 nip44).
        store
            .put(&CipherEntry {
                d_tag: "aa".repeat(32),
                payload: "!!!not-a-payload!!!".into(),
            })
            .unwrap();
        // Valid nip44 under a DIFFERENT key (undecryptable for us).
        let stranger = MockSigner::new();
        let spk = stranger.keys().public_key();
        let alien = stranger.nip44_encrypt(&spk, b"{\"x\":1}").await.unwrap();
        store
            .put(&CipherEntry {
                d_tag: "bb".repeat(32),
                payload: alien,
            })
            .unwrap();
        // Decryptable but not a SyncPayload.
        let signer = MockSigner::from_keys(keys.clone());
        let pk = keys.public_key();
        let junk = signer.nip44_encrypt(&pk, b"not json").await.unwrap();
        store
            .put(&CipherEntry {
                d_tag: "cc".repeat(32),
                payload: junk,
            })
            .unwrap();

        let svc2 = service(&keys, &store);
        svc2.open().await.unwrap();
        let paths = svc2.list_paths().await.unwrap();
        assert_eq!(paths, vec![path("good/entry")]);
        let _ = svc; // keep first service alive for clarity
    }

    #[tokio::test]
    async fn d_tag_mismatch_self_heals_by_trusting_payload_path() {
        let (keys, store, svc) = setup();
        let p = path("moved/by-bug");
        let signer = MockSigner::from_keys(keys.clone());
        let pk = keys.public_key();
        let payload = SyncPayload::from_entry(&Entry {
            path: p.clone(),
            fields: sample_entry("x").fields,
            updated_at: 42,
        });
        let cipher = signer
            .nip44_encrypt(&pk, &payload.encode().unwrap())
            .await
            .unwrap();
        // Stored under the WRONG d-tag.
        store
            .put(&CipherEntry {
                d_tag: "dd".repeat(32),
                payload: cipher,
            })
            .unwrap();

        svc.open().await.unwrap();
        assert_eq!(svc.list_paths().await.unwrap(), vec![p.clone()]);
        let got = svc.get(&p).await.unwrap();
        assert_eq!(got.updated_at, 42);
    }

    // ---- Unsupported signer ---------------------------------------------

    struct NoCkSigner;

    #[async_trait]
    impl Signer for NoCkSigner {
        fn kind(&self) -> crate::signer::SignerKind {
            crate::signer::SignerKind::Nsd
        }
        async fn public_key(&self) -> Result<PublicKey> {
            Err(ShukiError::Other("unused".into()))
        }
        async fn sign_event(&self, _u: UnsignedEvent) -> Result<Event> {
            Err(ShukiError::Other("unused".into()))
        }
        async fn self_conversation_key(&self) -> Result<ConversationKey> {
            Err(ShukiError::Unsupported("no exportable CK".into()))
        }
        async fn nip44_encrypt(&self, _p: &PublicKey, _pt: &[u8]) -> Result<String> {
            Err(ShukiError::Other("unused".into()))
        }
        async fn nip44_decrypt(&self, _p: &PublicKey, _c: &str) -> Result<Zeroizing<Vec<u8>>> {
            Err(ShukiError::Other("unused".into()))
        }
    }

    #[tokio::test]
    async fn open_propagates_unsupported_conversation_key() {
        let store: Arc<dyn VaultStore> = Arc::new(MemStore::default());
        let svc = VaultService::new(Arc::new(NoCkSigner), store);
        match svc.open().await {
            Err(ShukiError::Unsupported(msg)) => {
                assert!(msg.contains("cannot open a vault"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
