//! [`super::SyncApi`] implementation (owned by `leaf/sync-nostr-engine`).
//!
//! `reconcile()` is a pure function over (local sync state, remote events) so
//! LWW logic is unit-testable without a relay. When local wins a conflict,
//! republish with `created_at = max(remote_created_at + 1, now)` so the relay
//! actually replaces the stored event.
//!
//! # LWW + tie-break (frozen semantics)
//!
//! The LWW authority is the *payload* `updated_at`, never the event
//! `created_at`. On equal `updated_at` the version whose event id (lowercase
//! hex string) is lexicographically GREATER wins, comparing the remote event
//! id against the locally recorded one; a local entry with no recorded event
//! id loses to any remote event. The winner is applied on both sides: pull if
//! remote wins, republish (push) if local wins. Tombstones participate like
//! normal entries — a newer tombstone beats an older live entry and a newer
//! live entry beats an older tombstone.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use nostr::nips::nip44::v2::{self as nip44v2, ConversationKey};
use nostr::{EventBuilder, Filter, Kind, PublicKey, Tag, Timestamp};
use nostr_sdk::Client;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use super::payload::SyncPayload;
use super::{relays, SyncApi, SyncReport};
use crate::config::Config;
use crate::error::{Result, ShukiError};
use crate::signer::Signer;
use crate::store::{CipherEntry, EntrySyncState, SyncState, VaultStore};

/// Overlap window subtracted from `last_sync_at` for the `since` filter, so
/// clock skew between devices/relays cannot hide events.
const SINCE_OVERLAP_SECS: u64 = 3600;

/// Cap on kind-30078 events accepted from relays per fetch. Well-behaved
/// relays keep only the latest event per (author, kind, d-tag) — this bound
/// exists purely as defense-in-depth against a misbehaving/malicious relay
/// replaying unbounded stale/duplicate/spam events under our own pubkey (it
/// cannot forge new ones: `nostr-relay-pool` verifies event signatures
/// before handing events to us, and NIP-44's MAC means anything it forges
/// content-wise fails to decrypt). Generous enough for very large vaults.
const MAX_FETCH_EVENTS: usize = 20_000;

/// One decrypted kind-30078 event authored by us.
#[derive(Clone, Debug)]
pub struct RemoteEntry {
    pub d_tag: String,
    pub payload: SyncPayload,
    /// Lowercase-hex event id (tie-break key).
    pub event_id: String,
    /// Event `created_at` (drives relay replaceability, NOT LWW).
    pub created_at: u64,
}

/// Outcome of reconciling one d-tag.
// PullRemote is fat (a whole RemoteEntry) but actions are few and
// short-lived per sync round; boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum ReconcileAction {
    /// Remote version wins: write it to the local store.
    PullRemote {
        remote: RemoteEntry,
        /// True when both sides held competing versions (LWW decided).
        conflict: bool,
    },
    /// Local version wins: publish it with `created_at` strictly greater
    /// than `remote_created_at` (when known) so the relay replaces.
    PushLocal {
        d_tag: String,
        remote_created_at: Option<u64>,
        conflict: bool,
    },
    /// Already converged.
    Noop { d_tag: String },
}

/// True when remote candidate `a` beats candidate `b` (dedupe among remote
/// events sharing a d-tag): higher payload `updated_at`, tie → higher event id.
fn remote_beats(a: &RemoteEntry, b: &RemoteEntry) -> bool {
    match a.payload.updated_at.cmp(&b.payload.updated_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => a.event_id > b.event_id,
    }
}

/// Keep the winning remote candidate per d-tag.
fn dedupe_remote(remote: &[RemoteEntry]) -> BTreeMap<&str, &RemoteEntry> {
    let mut best: BTreeMap<&str, &RemoteEntry> = BTreeMap::new();
    for r in remote {
        match best.get(r.d_tag.as_str()) {
            Some(cur) if !remote_beats(r, cur) => {}
            _ => {
                best.insert(r.d_tag.as_str(), r);
            }
        }
    }
    best
}

/// Pure LWW reconciliation. `local_payloads` holds the decrypted payloads of
/// the local ciphertext entries; `local` is the sync bookkeeping. See the
/// module docs for the exact tie-break semantics.
pub fn reconcile(
    local: &SyncState,
    local_payloads: &BTreeMap<String, SyncPayload>,
    remote: &[RemoteEntry],
) -> Vec<ReconcileAction> {
    let best = dedupe_remote(remote);
    let mut actions = Vec::new();

    for (d_tag, r) in &best {
        let Some(lp) = local_payloads.get(*d_tag) else {
            // Unknown locally → pull.
            actions.push(ReconcileAction::PullRemote {
                remote: (*r).clone(),
                conflict: false,
            });
            continue;
        };
        let st = local.entries.get(*d_tag);
        let local_event_id = st.and_then(|s| s.event_id.as_deref());
        let dirty = st.is_none_or(|s| s.dirty);
        let same_event = local_event_id == Some(r.event_id.as_str());

        match r.payload.updated_at.cmp(&lp.updated_at) {
            std::cmp::Ordering::Greater => actions.push(ReconcileAction::PullRemote {
                remote: (*r).clone(),
                // Conflict only when local also changed since our last push.
                conflict: dirty && !same_event,
            }),
            std::cmp::Ordering::Less => actions.push(ReconcileAction::PushLocal {
                d_tag: (*d_tag).to_owned(),
                remote_created_at: Some(r.created_at),
                // The remote event is not the one we recorded → competing write.
                conflict: !same_event,
            }),
            std::cmp::Ordering::Equal => {
                if same_event {
                    if dirty {
                        // Local edit that kept updated_at (edge case): push it.
                        actions.push(ReconcileAction::PushLocal {
                            d_tag: (*d_tag).to_owned(),
                            remote_created_at: Some(r.created_at),
                            conflict: false,
                        });
                    } else {
                        actions.push(ReconcileAction::Noop {
                            d_tag: (*d_tag).to_owned(),
                        });
                    }
                } else {
                    // Equal updated_at, different events: higher event id wins;
                    // a local entry with no recorded event id loses.
                    let local_wins = local_event_id.is_some_and(|l| l > r.event_id.as_str());
                    if local_wins {
                        actions.push(ReconcileAction::PushLocal {
                            d_tag: (*d_tag).to_owned(),
                            remote_created_at: Some(r.created_at),
                            conflict: true,
                        });
                    } else {
                        actions.push(ReconcileAction::PullRemote {
                            remote: (*r).clone(),
                            conflict: true,
                        });
                    }
                }
            }
        }
    }

    // Local-only entries: push when dirty (or never pushed), else leave alone
    // (absence from a windowed fetch does not mean remote deletion).
    for d_tag in local_payloads.keys() {
        if best.contains_key(d_tag.as_str()) {
            continue;
        }
        let st = local.entries.get(d_tag);
        let dirty = st.is_none_or(|s| s.dirty || s.event_id.is_none());
        if dirty {
            actions.push(ReconcileAction::PushLocal {
                d_tag: d_tag.clone(),
                remote_created_at: None,
                conflict: false,
            });
        } else {
            actions.push(ReconcileAction::Noop {
                d_tag: d_tag.clone(),
            });
        }
    }

    actions
}

/// Run a blocking [`VaultStore`] call on the blocking thread pool.
async fn blocking<T, F>(store: &Arc<dyn VaultStore>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn VaultStore) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || f(store.as_ref()))
        .await
        .map_err(|e| ShukiError::Other(format!("blocking store task: {e}")))?
}

/// Per-run context shared by every push.
#[derive(Clone, Copy)]
struct PushCtx<'a> {
    client: &'a Client,
    own_pk: PublicKey,
    /// Unix seconds captured once at the start of the run.
    now: u64,
}

pub struct SyncEngine {
    signer: Arc<dyn Signer>,
    store: Arc<dyn VaultStore>,
    /// Behind a lock so [`SyncApi::set_net_mode`] can switch the network
    /// mode at runtime; each operation snapshots the config on entry.
    config: tokio::sync::RwLock<Config>,
}

impl SyncEngine {
    pub fn new(signer: Arc<dyn Signer>, store: Arc<dyn VaultStore>, config: Config) -> Self {
        Self {
            signer,
            store,
            config: tokio::sync::RwLock::new(config),
        }
    }

    /// Snapshot of the current config (relays + net mode).
    async fn config_snapshot(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Self conversation key, or `None` when the backend cannot export one
    /// (callers then fall back to per-entry [`Signer::nip44_decrypt`]).
    async fn conversation_key(&self) -> Result<Option<ConversationKey>> {
        match self.signer.self_conversation_key().await {
            Ok(k) => Ok(Some(k)),
            Err(ShukiError::Unsupported(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// NIP-44 decrypt a base64 payload string with the self conversation key,
    /// falling back to the signer's per-entry decrypt.
    async fn decrypt_content(
        &self,
        own_pk: &PublicKey,
        conv_key: Option<&ConversationKey>,
        content: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match conv_key {
            Some(ck) => {
                let bytes = BASE64
                    .decode(content)
                    .map_err(|e| ShukiError::Crypto(format!("nip44 base64: {e}")))?;
                nip44v2::decrypt_to_bytes(ck, &bytes)
                    .map(Zeroizing::new)
                    .map_err(|e| ShukiError::Crypto(format!("nip44 decrypt: {e}")))
            }
            None => self.signer.nip44_decrypt(own_pk, content).await,
        }
    }

    /// Decrypt + decode local ciphertext entries for LWW comparison.
    /// Undecodable local entries are reported and skipped.
    async fn decrypt_local(
        &self,
        own_pk: &PublicKey,
        conv_key: Option<&ConversationKey>,
        ciphers: &BTreeMap<String, CipherEntry>,
        report: &mut SyncReport,
    ) -> BTreeMap<String, SyncPayload> {
        let mut out = BTreeMap::new();
        for (d_tag, c) in ciphers {
            let bytes = match self.decrypt_content(own_pk, conv_key, &c.payload).await {
                Ok(b) => b,
                Err(e) => {
                    report
                        .errors
                        .push((d_tag.clone(), format!("local decrypt: {e}")));
                    continue;
                }
            };
            match SyncPayload::decode(&bytes) {
                Ok(p) => {
                    out.insert(d_tag.clone(), p);
                }
                Err(e) => report
                    .errors
                    .push((d_tag.clone(), format!("local payload: {e}"))),
            }
        }
        out
    }

    /// Fetch our kind-30078 events, decrypt, decode. Undecryptable or
    /// foreign-app contents are skipped silently (other apps share the kind);
    /// structural failures (bad JSON, newer schema) land in `report.errors`.
    /// Returns the entries plus an event_id → ciphertext map for pulls.
    async fn fetch_remote(
        &self,
        client: &Client,
        own_pk: &PublicKey,
        conv_key: Option<&ConversationKey>,
        since: Option<u64>,
        report: &mut SyncReport,
    ) -> Result<(Vec<RemoteEntry>, BTreeMap<String, String>)> {
        let mut filter = Filter::new()
            .author(*own_pk)
            .kind(Kind::ApplicationSpecificData)
            .limit(MAX_FETCH_EVENTS);
        if let Some(ts) = since {
            filter = filter.since(Timestamp::from(ts.saturating_sub(SINCE_OVERLAP_SECS)));
        }
        let events = client
            .fetch_events(filter, relays::FETCH_TIMEOUT)
            .await
            .map_err(|e| ShukiError::Relay(format!("fetch events: {e}")))?;
        if events.len() >= MAX_FETCH_EVENTS {
            report.errors.push((
                "fetch".to_owned(),
                format!(
                    "hit the {MAX_FETCH_EVENTS}-event fetch cap; some remote history may not \
                     have been considered this run (a relay may be replaying stale events)"
                ),
            ));
        }

        let mut entries = Vec::new();
        let mut contents = BTreeMap::new();
        for ev in events.into_iter() {
            let Some(d_tag) = ev.tags.identifier() else {
                continue; // no d tag → not ours
            };
            if d_tag.is_empty() {
                continue;
            }
            let bytes = match self.decrypt_content(own_pk, conv_key, &ev.content).await {
                Ok(b) => b,
                Err(e) => {
                    // Possibly another app's payload under the same kind.
                    debug!(d_tag, "skipping undecryptable kind-30078 event: {e}");
                    continue;
                }
            };
            match SyncPayload::decode(&bytes) {
                Ok(payload) => {
                    let event_id = ev.id.to_hex();
                    contents.insert(event_id.clone(), ev.content.clone());
                    entries.push(RemoteEntry {
                        d_tag: d_tag.to_owned(),
                        payload,
                        event_id,
                        created_at: ev.created_at.as_secs(),
                    });
                }
                Err(ShukiError::Corrupt(msg)) if msg.starts_with("foreign app") => {
                    debug!(d_tag, "skipping foreign app payload");
                }
                Err(e) => report
                    .errors
                    .push((d_tag.to_owned(), format!("remote payload: {e}"))),
            }
        }
        Ok((entries, contents))
    }

    /// Write one remote version into the local store + sync state.
    async fn apply_pull(
        &self,
        state: &mut SyncState,
        remote: &RemoteEntry,
        content: &str,
        conflict: bool,
        report: &mut SyncReport,
    ) {
        let entry = CipherEntry {
            d_tag: remote.d_tag.clone(),
            payload: content.to_owned(),
        };
        match blocking(&self.store, move |s| s.put(&entry)).await {
            Ok(()) => {
                state.entries.insert(
                    remote.d_tag.clone(),
                    EntrySyncState {
                        event_id: Some(remote.event_id.clone()),
                        event_created_at: Some(remote.created_at),
                        dirty: false,
                    },
                );
                report.pulled += 1;
                if remote.payload.deleted {
                    report.tombstones_applied += 1;
                }
                if conflict {
                    report.conflicts_lww += 1;
                }
            }
            Err(e) => report
                .errors
                .push((remote.d_tag.clone(), format!("store put: {e}"))),
        }
    }

    /// Publish one local ciphertext entry, replacing the remote event.
    async fn apply_push(
        &self,
        ctx: &PushCtx<'_>,
        state: &mut SyncState,
        cipher: &CipherEntry,
        remote_created_at: Option<u64>,
        conflict: bool,
        report: &mut SyncReport,
    ) {
        let PushCtx {
            client,
            own_pk,
            now,
        } = *ctx;
        // Strictly newer than both the remote event (when seen) and whatever
        // we last recorded, so the relay actually replaces the stored event.
        let recorded = state
            .entries
            .get(&cipher.d_tag)
            .and_then(|s| s.event_created_at);
        let floor = remote_created_at
            .max(recorded)
            .map(|t| t.saturating_add(1))
            .unwrap_or(0);
        let created_at = floor.max(now);

        let unsigned = EventBuilder::new(Kind::ApplicationSpecificData, cipher.payload.clone())
            .tag(Tag::identifier(cipher.d_tag.clone()))
            .custom_created_at(Timestamp::from(created_at))
            .build(own_pk);
        let event = match self.signer.sign_event(unsigned).await {
            Ok(ev) => ev,
            Err(e) => {
                report
                    .errors
                    .push((cipher.d_tag.clone(), format!("sign: {e}")));
                return;
            }
        };
        match relays::send_signed(client, &event).await {
            Ok(()) => {
                state.entries.insert(
                    cipher.d_tag.clone(),
                    EntrySyncState {
                        event_id: Some(event.id.to_hex()),
                        event_created_at: Some(created_at),
                        dirty: false,
                    },
                );
                report.pushed += 1;
                if conflict {
                    report.conflicts_lww += 1;
                }
            }
            Err(e) => report
                .errors
                .push((cipher.d_tag.clone(), format!("publish: {e}"))),
        }
    }

    async fn sync_inner(&self, client: &Client, report: &mut SyncReport) -> Result<()> {
        let own_pk = self.signer.public_key().await?;
        let conv_key = self.conversation_key().await?;

        let ciphers: BTreeMap<String, CipherEntry> = blocking(&self.store, |s| s.list())
            .await?
            .into_iter()
            .map(|c| (c.d_tag.clone(), c))
            .collect();
        let mut state = blocking(&self.store, |s| s.load_sync_state()).await?;
        let local_payloads = self
            .decrypt_local(&own_pk, conv_key.as_ref(), &ciphers, report)
            .await;

        let (remote, contents) = self
            .fetch_remote(
                client,
                &own_pk,
                conv_key.as_ref(),
                state.last_sync_at,
                report,
            )
            .await?;

        let now = Timestamp::now().as_secs();
        for action in reconcile(&state, &local_payloads, &remote) {
            match action {
                ReconcileAction::PullRemote { remote, conflict } => {
                    let Some(content) = contents.get(&remote.event_id) else {
                        continue; // unreachable: contents covers every entry
                    };
                    self.apply_pull(&mut state, &remote, content, conflict, report)
                        .await;
                }
                ReconcileAction::PushLocal {
                    d_tag,
                    remote_created_at,
                    conflict,
                } => {
                    let Some(cipher) = ciphers.get(&d_tag) else {
                        continue; // unreachable: payload implies ciphertext
                    };
                    let ctx = PushCtx {
                        client,
                        own_pk,
                        now,
                    };
                    self.apply_push(
                        &ctx,
                        &mut state,
                        cipher,
                        remote_created_at,
                        conflict,
                        report,
                    )
                    .await;
                }
                ReconcileAction::Noop { .. } => {}
            }
        }

        state.last_sync_at = Some(now);
        blocking(&self.store, move |s| s.save_sync_state(&state)).await?;
        Ok(())
    }

    async fn restore_inner(&self, client: &Client, report: &mut SyncReport) -> Result<()> {
        let own_pk = self.signer.public_key().await?;
        let conv_key = self.conversation_key().await?;

        let (remote, contents) = self
            .fetch_remote(client, &own_pk, conv_key.as_ref(), None, report)
            .await?;
        let mut state = blocking(&self.store, |s| s.load_sync_state())
            .await
            .unwrap_or_default();

        let best: Vec<RemoteEntry> = dedupe_remote(&remote).into_values().cloned().collect();
        for entry in &best {
            let Some(content) = contents.get(&entry.event_id) else {
                continue;
            };
            self.apply_pull(&mut state, entry, content, false, report)
                .await;
        }

        state.last_sync_at = Some(Timestamp::now().as_secs());
        blocking(&self.store, move |s| s.save_sync_state(&state)).await?;
        Ok(())
    }
}

#[async_trait]
impl SyncApi for SyncEngine {
    async fn sync(&self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let client = relays::build_client(&self.config_snapshot().await).await?;
        let outcome = self.sync_inner(&client, &mut report).await;
        client.disconnect().await;
        outcome?;
        if !report.errors.is_empty() {
            warn!(
                "sync completed with {} per-item errors",
                report.errors.len()
            );
        }
        Ok(report)
    }

    async fn restore_all(&self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let client = relays::build_client(&self.config_snapshot().await).await?;
        let outcome = self.restore_inner(&client, &mut report).await;
        client.disconnect().await;
        outcome?;
        Ok(report)
    }

    async fn publish_relay_list(&self) -> Result<()> {
        let config = self.config_snapshot().await;
        let client = relays::build_client(&config).await?;
        let outcome =
            relays::publish_relay_list(&client, self.signer.as_ref(), &config.relays).await;
        client.disconnect().await;
        outcome
    }

    async fn fetch_relay_list(&self) -> Result<Vec<String>> {
        let own_pk = self.signer.public_key().await?;
        let client = relays::build_client(&self.config_snapshot().await).await?;
        let outcome = relays::fetch_relay_list(&client, own_pk).await;
        client.disconnect().await;
        outcome
    }

    async fn set_net_mode(&self, net: crate::config::NetMode) -> Result<()> {
        self.config.write().await.net = net;
        Ok(())
    }

    async fn net_check(&self) -> Result<Vec<(String, Option<String>)>> {
        let config = self.config_snapshot().await;
        // `build_client` errors with a ShukiError::Config hint on an empty
        // relay list, connects, and waits ~10s for the pool.
        let client = relays::build_client(&config).await?;
        let statuses = relays::relay_statuses(&client, &config.relays).await;
        client.disconnect().await;
        Ok(statuses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Entry, EntryFields, SecretField, VaultPath};
    use crate::testutil::MockSigner;

    fn payload(path: &str, updated_at: u64) -> SyncPayload {
        SyncPayload::from_entry(&Entry {
            path: VaultPath::parse(path).unwrap(),
            fields: EntryFields {
                password: Some(SecretField::from("pw")),
                ..Default::default()
            },
            updated_at,
        })
    }

    fn tombstone(path: &str, updated_at: u64) -> SyncPayload {
        SyncPayload::tombstone(VaultPath::parse(path).unwrap(), updated_at)
    }

    fn remote(d_tag: &str, p: SyncPayload, event_id: &str, created_at: u64) -> RemoteEntry {
        RemoteEntry {
            d_tag: d_tag.to_owned(),
            payload: p,
            event_id: event_id.to_owned(),
            created_at,
        }
    }

    fn state_with(
        d_tag: &str,
        event_id: Option<&str>,
        created_at: Option<u64>,
        dirty: bool,
    ) -> SyncState {
        let mut s = SyncState::default();
        s.entries.insert(
            d_tag.to_owned(),
            EntrySyncState {
                event_id: event_id.map(str::to_owned),
                event_created_at: created_at,
                dirty,
            },
        );
        s
    }

    fn locals(d_tag: &str, p: SyncPayload) -> BTreeMap<String, SyncPayload> {
        BTreeMap::from([(d_tag.to_owned(), p)])
    }

    #[test]
    fn remote_newer_wins() {
        let state = state_with("d1", Some("aa"), Some(100), false);
        let local = locals("d1", payload("a", 100));
        let rem = [remote("d1", payload("a", 200), "bb", 150)];
        let actions = reconcile(&state, &local, &rem);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ReconcileAction::PullRemote { remote, conflict } => {
                assert_eq!(remote.event_id, "bb");
                assert!(
                    !conflict,
                    "clean local overwritten by newer remote is not a conflict"
                );
            }
            other => panic!("expected PullRemote, got {other:?}"),
        }
    }

    #[test]
    fn remote_newer_over_dirty_local_is_conflict() {
        let state = state_with("d1", Some("aa"), Some(100), true);
        let local = locals("d1", payload("a", 150));
        let rem = [remote("d1", payload("a", 200), "bb", 160)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PullRemote { conflict, .. } => assert!(conflict),
            other => panic!("expected PullRemote, got {other:?}"),
        }
    }

    #[test]
    fn local_newer_wins() {
        let state = state_with("d1", Some("aa"), Some(100), true);
        let local = locals("d1", payload("a", 300));
        let rem = [remote("d1", payload("a", 200), "bb", 150)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PushLocal {
                d_tag,
                remote_created_at,
                conflict,
            } => {
                assert_eq!(d_tag, "d1");
                assert_eq!(*remote_created_at, Some(150));
                assert!(
                    conflict,
                    "remote event differs from recorded → competing write"
                );
            }
            other => panic!("expected PushLocal, got {other:?}"),
        }
    }

    #[test]
    fn local_newer_over_own_old_event_is_not_conflict() {
        let state = state_with("d1", Some("aa"), Some(100), true);
        let local = locals("d1", payload("a", 300));
        let rem = [remote("d1", payload("a", 200), "aa", 100)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PushLocal { conflict, .. } => assert!(!conflict),
            other => panic!("expected PushLocal, got {other:?}"),
        }
    }

    #[test]
    fn equal_ts_higher_remote_event_id_pulls() {
        let state = state_with("d1", Some("aa"), Some(100), false);
        let local = locals("d1", payload("a", 200));
        let rem = [remote("d1", payload("a", 200), "bb", 150)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PullRemote { remote, conflict } => {
                assert_eq!(remote.event_id, "bb");
                assert!(conflict);
            }
            other => panic!("expected PullRemote, got {other:?}"),
        }
    }

    #[test]
    fn equal_ts_higher_local_event_id_pushes() {
        let state = state_with("d1", Some("cc"), Some(100), false);
        let local = locals("d1", payload("a", 200));
        let rem = [remote("d1", payload("a", 200), "bb", 150)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PushLocal {
                remote_created_at,
                conflict,
                ..
            } => {
                assert_eq!(*remote_created_at, Some(150));
                assert!(conflict);
            }
            other => panic!("expected PushLocal, got {other:?}"),
        }
    }

    #[test]
    fn equal_ts_no_local_event_id_loses() {
        let state = state_with("d1", None, None, true);
        let local = locals("d1", payload("a", 200));
        let rem = [remote("d1", payload("a", 200), "bb", 150)];
        assert!(matches!(
            &reconcile(&state, &local, &rem)[0],
            ReconcileAction::PullRemote { .. }
        ));
    }

    #[test]
    fn newer_tombstone_beats_live() {
        let state = state_with("d1", Some("aa"), Some(100), false);
        let local = locals("d1", payload("a", 100));
        let rem = [remote("d1", tombstone("a", 200), "bb", 150)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PullRemote { remote, .. } => assert!(remote.payload.deleted),
            other => panic!("expected PullRemote, got {other:?}"),
        }
    }

    #[test]
    fn newer_live_beats_tombstone() {
        let state = state_with("d1", Some("aa"), Some(100), true);
        let local = locals("d1", payload("a", 300));
        let rem = [remote("d1", tombstone("a", 200), "bb", 150)];
        assert!(matches!(
            &reconcile(&state, &local, &rem)[0],
            ReconcileAction::PushLocal { .. }
        ));
    }

    #[test]
    fn unknown_remote_d_tag_pulls() {
        let state = SyncState::default();
        let local = BTreeMap::new();
        let rem = [remote("d9", payload("x", 10), "aa", 5)];
        match &reconcile(&state, &local, &rem)[0] {
            ReconcileAction::PullRemote { remote, conflict } => {
                assert_eq!(remote.d_tag, "d9");
                assert!(!conflict);
            }
            other => panic!("expected PullRemote, got {other:?}"),
        }
    }

    #[test]
    fn local_dirty_only_pushes() {
        let state = state_with("d1", None, None, true);
        let local = locals("d1", payload("a", 100));
        match &reconcile(&state, &local, &[])[0] {
            ReconcileAction::PushLocal {
                d_tag,
                remote_created_at,
                conflict,
            } => {
                assert_eq!(d_tag, "d1");
                assert_eq!(*remote_created_at, None);
                assert!(!conflict);
            }
            other => panic!("expected PushLocal, got {other:?}"),
        }
    }

    #[test]
    fn local_clean_absent_remote_is_noop() {
        // Windowed fetch may simply not include our old event.
        let state = state_with("d1", Some("aa"), Some(100), false);
        let local = locals("d1", payload("a", 100));
        assert!(matches!(
            &reconcile(&state, &local, &[])[0],
            ReconcileAction::Noop { d_tag } if d_tag == "d1"
        ));
    }

    #[test]
    fn clean_and_equal_same_event_is_noop() {
        let state = state_with("d1", Some("aa"), Some(150), false);
        let local = locals("d1", payload("a", 200));
        let rem = [remote("d1", payload("a", 200), "aa", 150)];
        assert!(matches!(
            &reconcile(&state, &local, &rem)[0],
            ReconcileAction::Noop { d_tag } if d_tag == "d1"
        ));
    }

    #[test]
    fn dirty_and_equal_same_event_pushes() {
        let state = state_with("d1", Some("aa"), Some(150), true);
        let local = locals("d1", payload("a", 200));
        let rem = [remote("d1", payload("a", 200), "aa", 150)];
        assert!(matches!(
            &reconcile(&state, &local, &rem)[0],
            ReconcileAction::PushLocal {
                conflict: false,
                ..
            }
        ));
    }

    #[test]
    fn remote_duplicates_deduped_by_lww_then_event_id() {
        let state = SyncState::default();
        let local = BTreeMap::new();
        let rem = [
            remote("d1", payload("a", 100), "zz", 90),
            remote("d1", payload("a", 200), "aa", 95),
            remote("d1", payload("a", 200), "bb", 94),
        ];
        let actions = reconcile(&state, &local, &rem);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ReconcileAction::PullRemote { remote, .. } => {
                // updated_at 200 beats 100; among the two 200s, "bb" > "aa".
                assert_eq!(remote.event_id, "bb");
            }
            other => panic!("expected PullRemote, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_content_roundtrips_with_conversation_key() {
        let signer = MockSigner::new();
        let pk = signer.public_key().await.unwrap();
        let p = payload("web/example.com", 1_700_000_000);
        let ct = signer
            .nip44_encrypt(&pk, &p.encode().unwrap())
            .await
            .unwrap();

        let engine = SyncEngine::new(
            Arc::new(MockSigner::from_keys(signer.keys().clone())),
            Arc::new(NopStore),
            Config::default(),
        );
        let ck = engine.conversation_key().await.unwrap();
        assert!(ck.is_some(), "MockSigner exports a conversation key");
        let pt = engine.decrypt_content(&pk, ck.as_ref(), &ct).await.unwrap();
        let back = SyncPayload::decode(&pt).unwrap();
        assert_eq!(back.path.as_str(), "web/example.com");
        assert_eq!(back.updated_at, 1_700_000_000);

        // Fallback path (no conversation key) must agree.
        let pt2 = engine.decrypt_content(&pk, None, &ct).await.unwrap();
        assert_eq!(&*pt, &*pt2);

        // Garbage is an error, not a panic.
        assert!(engine
            .decrypt_content(&pk, ck.as_ref(), "!!")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn set_net_mode_updates_engine_config() {
        use crate::config::NetMode;

        let engine = SyncEngine::new(
            Arc::new(MockSigner::new()),
            Arc::new(NopStore),
            Config::default(),
        );
        assert_eq!(engine.config.read().await.net, NetMode::Clearnet);
        engine
            .set_net_mode(NetMode::Socks5 {
                addr: "127.0.0.1:9050".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            engine.config.read().await.net,
            NetMode::Socks5 {
                addr: "127.0.0.1:9050".into()
            }
        );
        // Relays are untouched by a mode switch.
        assert!(engine.config.read().await.relays.is_empty());
    }

    #[tokio::test]
    async fn net_check_without_relays_is_config_error() {
        let engine = SyncEngine::new(
            Arc::new(MockSigner::new()),
            Arc::new(NopStore),
            Config::default(),
        );
        match engine.net_check().await {
            Err(ShukiError::Config(msg)) => assert!(msg.contains("no relays")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    /// Store stub for tests that never touch the store.
    struct NopStore;
    impl VaultStore for NopStore {
        fn list(&self) -> Result<Vec<CipherEntry>> {
            Ok(Vec::new())
        }
        fn get(&self, _d_tag: &str) -> Result<Option<CipherEntry>> {
            Ok(None)
        }
        fn put(&self, _entry: &CipherEntry) -> Result<()> {
            Ok(())
        }
        fn remove(&self, _d_tag: &str) -> Result<()> {
            Ok(())
        }
        fn load_sync_state(&self) -> Result<SyncState> {
            Ok(SyncState::default())
        }
        fn save_sync_state(&self, _s: &SyncState) -> Result<()> {
            Ok(())
        }
    }
}
