//! Software signer backed by the OS keychain (owned by `leaf/signer-software-keyring`).
//!
//! Contract: keychain service = `"shuki"`, account = the npub (allows multiple
//! identities later). The nsec is loaded from the keychain per operation into
//! zeroizing memory and dropped immediately; only the (constant) self
//! conversation key is cached for the process lifetime.
//!
//! Keychain layout:
//! - account [`POINTER_ACCOUNT`] (`"default"`) → bech32 npub of the current
//!   identity. Non-secret pointer; enables multiple identities later.
//! - account `<npub bech32>` → bech32 nsec of that identity (the secret).

use async_trait::async_trait;
use nostr::nips::nip44::{self, v2::ConversationKey};
use nostr::{Event, FromBech32, Keys, PublicKey, SecretKey, UnsignedEvent};
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use crate::error::{Result, ShukiError};
use crate::signer::{Signer, SignerKind};

pub const KEYCHAIN_SERVICE: &str = "shuki";

/// Keychain account whose value is the bech32 npub of the current identity.
pub(crate) const POINTER_ACCOUNT: &str = "default";

/// Minimal blocking keychain abstraction used by this module and
/// [`super::keysetup`].
///
/// Production uses [`OsKeychain`] (the `keyring` crate). Tests swap in an
/// in-memory store instead, because `keyring::mock` credentials have no
/// shared persistence across separate `Entry::new` calls, which makes them
/// unusable for multi-call flows (setup then load).
pub(crate) trait KeychainStore: Send + Sync {
    /// Read the value stored for `account`. `Ok(None)` when no entry exists.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>>;

    /// Create or overwrite the value stored for `account`.
    fn set(&self, account: &str, value: &str) -> Result<()>;
}

/// The real OS keychain (macOS Keychain / Windows Credential Manager /
/// Secret Service).
struct OsKeychain;

impl OsKeychain {
    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|e| ShukiError::Keychain(e.to_string()))
    }
}

impl KeychainStore for OsKeychain {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        match Self::entry(account)?.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(ShukiError::Keychain(e.to_string())),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        Self::entry(account)?
            .set_password(value)
            .map_err(|e| ShukiError::Keychain(e.to_string()))
    }
}

/// The active keychain store: the OS keychain, unless a test installed an
/// in-memory override via [`test_support::fresh_store`].
pub(crate) fn active_store() -> std::sync::Arc<dyn KeychainStore> {
    #[cfg(test)]
    if let Some(store) = test_support::override_store() {
        return store;
    }
    std::sync::Arc::new(OsKeychain)
}

/// Map a `spawn_blocking` join failure. Keyring calls are blocking, so every
/// public entry point runs them on the blocking pool.
pub(crate) fn join_err(e: tokio::task::JoinError) -> ShukiError {
    ShukiError::Other(format!("keychain task failed: {e}"))
}

/// Load and parse the nsec stored under `npub_account`. Blocking.
///
/// The bech32 buffer is zeroized on drop; the returned [`Keys`] must live
/// only for the duration of one operation.
pub(crate) fn load_keys_blocking(npub_account: &str) -> Result<Keys> {
    let store = active_store();
    let nsec: Zeroizing<String> = store.get(npub_account)?.ok_or_else(|| {
        ShukiError::NotFound(format!(
            "no key material in keychain for identity {npub_account}"
        ))
    })?;
    let secret_key = SecretKey::from_bech32(nsec.as_str())
        .map_err(|e| ShukiError::Keychain(format!("stored nsec unparsable: {e}")))?;
    Ok(Keys::new(secret_key))
}

/// OS-keychain [`Signer`]. Construct with [`SoftwareSigner::load`].
///
/// `Debug` is implemented manually and prints only the (non-secret) public
/// key — never the cached conversation key.
pub struct SoftwareSigner {
    public_key: PublicKey,
    /// Keychain account holding our nsec (= our bech32 npub). Non-secret.
    npub_account: String,
    /// Cached NIP-44 self conversation key (see [`Signer::self_conversation_key`]).
    /// It stays in process memory for the signer's lifetime by design: it is
    /// the working key for bulk vault encrypt/decrypt, and the contract
    /// requires asking the backend only once.
    self_ck: OnceCell<ConversationKey>,
}

impl SoftwareSigner {
    /// Load the signer for the identity stored in the keychain.
    ///
    /// Reads the `"default"` pointer, verifies that the referenced nsec entry
    /// exists and parses, and caches only the public key. Returns
    /// [`ShukiError::NotFound`] when no identity has been initialized.
    pub async fn load() -> Result<Self> {
        let (public_key, npub_account) =
            tokio::task::spawn_blocking(|| -> Result<(PublicKey, String)> {
                let store = active_store();
                let npub = store.get(POINTER_ACCOUNT)?.ok_or_else(|| {
                    ShukiError::NotFound(
                        "no identity in keychain (generate or import a key first)".into(),
                    )
                })?;
                // The pointer value is a public npub, not secret material.
                let npub: String = npub.to_string();
                let public_key = PublicKey::from_bech32(&npub).map_err(|e| {
                    ShukiError::Keychain(format!("stored identity pointer unparsable: {e}"))
                })?;
                // Verify the nsec entry exists and parses; drop it immediately.
                load_keys_blocking(&npub)?;
                Ok((public_key, npub))
            })
            .await
            .map_err(join_err)??;
        Ok(Self {
            public_key,
            npub_account,
            self_ck: OnceCell::new(),
        })
    }
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("public_key", &self.public_key)
            .field("self_ck", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl Signer for SoftwareSigner {
    fn kind(&self) -> SignerKind {
        SignerKind::Software
    }

    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.public_key)
    }

    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event> {
        let account = self.npub_account.clone();
        tokio::task::spawn_blocking(move || {
            let keys = load_keys_blocking(&account)?;
            unsigned
                .sign_with_keys(&keys)
                .map_err(|e| ShukiError::Crypto(e.to_string()))
        })
        .await
        .map_err(join_err)?
    }

    async fn self_conversation_key(&self) -> Result<ConversationKey> {
        let ck = self
            .self_ck
            .get_or_try_init(|| async {
                let account = self.npub_account.clone();
                let own_pk = self.public_key;
                tokio::task::spawn_blocking(move || {
                    let keys = load_keys_blocking(&account)?;
                    ConversationKey::derive(keys.secret_key(), &own_pk)
                        .map_err(|e| ShukiError::Crypto(e.to_string()))
                })
                .await
                .map_err(join_err)?
            })
            .await?;
        Ok(*ck)
    }

    async fn nip44_encrypt(&self, peer: &PublicKey, plaintext: &[u8]) -> Result<String> {
        let account = self.npub_account.clone();
        let peer = *peer;
        let plaintext = Zeroizing::new(plaintext.to_vec());
        tokio::task::spawn_blocking(move || {
            let keys = load_keys_blocking(&account)?;
            nip44::encrypt(
                keys.secret_key(),
                &peer,
                plaintext.as_slice(),
                nip44::Version::V2,
            )
            .map_err(|e| ShukiError::Crypto(e.to_string()))
        })
        .await
        .map_err(join_err)?
    }

    async fn nip44_decrypt(&self, peer: &PublicKey, payload: &str) -> Result<Zeroizing<Vec<u8>>> {
        let account = self.npub_account.clone();
        let peer = *peer;
        let payload = payload.to_owned();
        tokio::task::spawn_blocking(move || {
            let keys = load_keys_blocking(&account)?;
            nip44::decrypt_to_bytes(keys.secret_key(), &peer, &payload)
                .map(Zeroizing::new)
                .map_err(|e| ShukiError::Crypto(e.to_string()))
        })
        .await
        .map_err(join_err)?
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! In-memory [`KeychainStore`] for tests.
    //!
    //! The store selection is process-global, so every test touching it must
    //! hold the guard returned by [`fresh_store`] for its whole duration.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    use zeroize::Zeroizing;

    use super::KeychainStore;
    use crate::error::Result;

    #[derive(Default)]
    pub(crate) struct MemStore {
        map: Mutex<HashMap<String, String>>,
    }

    impl KeychainStore for MemStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
            Ok(self
                .map
                .lock()
                .expect("mem store lock")
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }

        fn set(&self, account: &str, value: &str) -> Result<()> {
            self.map
                .lock()
                .expect("mem store lock")
                .insert(account.to_owned(), value.to_owned());
            Ok(())
        }
    }

    static OVERRIDE: OnceLock<Mutex<Option<Arc<MemStore>>>> = OnceLock::new();
    // Async mutex: test bodies hold the guard across `.await` points.
    static TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

    fn override_slot() -> &'static Mutex<Option<Arc<MemStore>>> {
        OVERRIDE.get_or_init(|| Mutex::new(None))
    }

    pub(crate) fn override_store() -> Option<Arc<dyn KeychainStore>> {
        override_slot()
            .lock()
            .expect("override lock")
            .clone()
            .map(|s| s as Arc<dyn KeychainStore>)
    }

    /// Serialize access to the process-global store override and install a
    /// fresh, empty in-memory store. Keep the guard alive for the whole test.
    pub(crate) async fn fresh_store() -> (tokio::sync::MutexGuard<'static, ()>, Arc<MemStore>) {
        let guard = TEST_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        let store = Arc::new(MemStore::default());
        *override_slot().lock().expect("override lock") = Some(store.clone());
        (guard, store)
    }
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, ToBech32};

    use super::test_support::fresh_store;
    use super::*;
    use crate::domain::SecretField;
    use crate::signer::keysetup;

    #[tokio::test]
    async fn load_fails_when_uninitialized() {
        let (_guard, _store) = fresh_store().await;
        let err = SoftwareSigner::load().await.unwrap_err();
        assert!(matches!(err, ShukiError::NotFound(_)), "got: {err}");
    }

    #[tokio::test]
    async fn sign_event_and_verify() {
        let (_guard, _store) = fresh_store().await;
        let pk = keysetup::generate_and_store().await.unwrap();
        let signer = SoftwareSigner::load().await.unwrap();
        assert_eq!(signer.kind(), SignerKind::Software);
        assert_eq!(signer.public_key().await.unwrap(), pk);

        let unsigned = EventBuilder::text_note("shuki test note").build(pk);
        let event = signer.sign_event(unsigned).await.unwrap();
        assert_eq!(event.pubkey, pk);
        event.verify().expect("signature must verify");
    }

    #[tokio::test]
    async fn nip44_self_roundtrip() {
        let (_guard, _store) = fresh_store().await;
        let pk = keysetup::generate_and_store().await.unwrap();
        let signer = SoftwareSigner::load().await.unwrap();

        let plaintext = b"correct horse battery staple";
        let ciphertext = signer.nip44_encrypt(&pk, plaintext).await.unwrap();
        assert_ne!(ciphertext.as_bytes(), plaintext.as_slice());
        let decrypted = signer.nip44_decrypt(&pk, &ciphertext).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[tokio::test]
    async fn self_conversation_key_matches_derive_and_is_cached() {
        let (_guard, _store) = fresh_store().await;
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("bech32 infallible");
        keysetup::import_nsec(SecretField::new(nsec)).await.unwrap();

        let signer = SoftwareSigner::load().await.unwrap();
        let ck = signer.self_conversation_key().await.unwrap();
        let expected =
            ConversationKey::derive(keys.secret_key(), &keys.public_key()).expect("derive");
        assert_eq!(ck.as_bytes(), expected.as_bytes());

        // Second call hits the cache and returns the same key.
        let again = signer.self_conversation_key().await.unwrap();
        assert_eq!(again.as_bytes(), ck.as_bytes());
    }
}
