//! Key lifecycle: generate / import / export (owned by `leaf/signer-software-keyring`).
//!
//! All functions operate on the OS keychain (service
//! [`super::software::KEYCHAIN_SERVICE`]). NIP-49 (`ncryptsec…`) is the cold
//! backup format.
//!
//! Layout (see [`super::software`]): account `"default"` holds the bech32
//! npub of the current identity (non-secret pointer); account `<npub>` holds
//! the bech32 nsec. Keyring calls are blocking, so every function runs them
//! on the blocking pool.

use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr::{FromBech32, Keys, PublicKey, SecretKey, ToBech32};
use tokio::task::spawn_blocking;
use zeroize::Zeroizing;

use super::software::{active_store, join_err, load_keys_blocking, POINTER_ACCOUNT};
use crate::domain::SecretField;
use crate::error::{Result, ShukiError};

/// Persist `keys` under the keychain layout (nsec first, then the pointer,
/// so the pointer never dangles). Blocking.
///
/// Refuses to replace a *different* stored identity with
/// [`ShukiError::AlreadyExists`]; re-importing the same key is idempotent.
fn persist_identity(keys: &Keys) -> Result<PublicKey> {
    let store = active_store();
    let public_key = keys.public_key();
    let npub = public_key.to_bech32().expect("npub bech32 is infallible");
    if let Some(existing) = store.get(POINTER_ACCOUNT)? {
        if existing.as_str() != npub {
            return Err(ShukiError::AlreadyExists(
                "a different identity is already stored in the keychain".into(),
            ));
        }
    }
    let nsec = Zeroizing::new(
        keys.secret_key()
            .to_bech32()
            .expect("nsec bech32 is infallible"),
    );
    store.set(&npub, &nsec)?;
    store.set(POINTER_ACCOUNT, &npub)?;
    Ok(public_key)
}

/// Generate a fresh identity, store it in the keychain, return its pubkey.
pub async fn generate_and_store() -> Result<PublicKey> {
    spawn_blocking(|| {
        if active_store().get(POINTER_ACCOUNT)?.is_some() {
            return Err(ShukiError::AlreadyExists(
                "an identity is already stored in the keychain".into(),
            ));
        }
        let keys = Keys::generate();
        persist_identity(&keys)
    })
    .await
    .map_err(join_err)?
}

/// Import a bech32 `nsec…` into the keychain.
///
/// Accepts bech32 (`nsec1…`) or 64-char hex.
pub async fn import_nsec(nsec: SecretField) -> Result<PublicKey> {
    spawn_blocking(move || {
        // Static error message: never echo (parts of) the input back.
        let secret_key = SecretKey::parse(nsec.expose().trim()).map_err(|_| {
            ShukiError::Crypto("invalid secret key: expected bech32 nsec1… or 64-char hex".into())
        })?;
        persist_identity(&Keys::new(secret_key))
    })
    .await
    .map_err(join_err)?
}

/// Import a NIP-49 `ncryptsec…` (decrypt with passphrase, store).
pub async fn import_ncryptsec(ncryptsec: &str, password: SecretField) -> Result<PublicKey> {
    let ncryptsec = ncryptsec.trim().to_owned();
    spawn_blocking(move || {
        let encrypted = EncryptedSecretKey::from_bech32(&ncryptsec)
            .map_err(|e| ShukiError::Crypto(format!("invalid ncryptsec: {e}")))?;
        let secret_key = encrypted.decrypt(password.expose()).map_err(|e| {
            ShukiError::Crypto(format!(
                "ncryptsec decryption failed (wrong passphrase?): {e}"
            ))
        })?;
        persist_identity(&Keys::new(secret_key))
    })
    .await
    .map_err(join_err)?
}

/// Export the stored key as NIP-49 `ncryptsec…` (log_n: KDF hardness, default 16).
pub async fn export_ncryptsec(password: SecretField, log_n: u8) -> Result<String> {
    spawn_blocking(move || {
        let npub = active_store()
            .get(POINTER_ACCOUNT)?
            .ok_or_else(|| ShukiError::NotFound("no identity in keychain".into()))?;
        let keys = load_keys_blocking(npub.as_str())?;
        let encrypted = EncryptedSecretKey::new(
            keys.secret_key(),
            password.expose(),
            log_n,
            KeySecurity::Medium,
        )
        .map_err(|e| ShukiError::Crypto(format!("nip49 encryption: {e}")))?;
        encrypted
            .to_bech32()
            .map_err(|e| ShukiError::Crypto(format!("nip49 bech32 encoding: {e}")))
    })
    .await
    .map_err(join_err)?
}

/// Pubkey of the stored identity, if any.
pub async fn stored_public_key() -> Result<Option<PublicKey>> {
    spawn_blocking(|| match active_store().get(POINTER_ACCOUNT)? {
        None => Ok(None),
        Some(npub) => PublicKey::from_bech32(npub.as_str())
            .map(Some)
            .map_err(|e| ShukiError::Keychain(format!("stored identity pointer unparsable: {e}"))),
    })
    .await
    .map_err(join_err)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::software::test_support::fresh_store;

    /// Low KDF hardness for fast tests; production default is 16.
    const TEST_LOG_N: u8 = 4;

    #[tokio::test]
    async fn generate_then_stored_public_key_roundtrip() {
        let (_guard, _store) = fresh_store().await;
        assert_eq!(stored_public_key().await.unwrap(), None);

        let pk = generate_and_store().await.unwrap();
        assert_eq!(stored_public_key().await.unwrap(), Some(pk));

        let err = generate_and_store().await.unwrap_err();
        assert!(matches!(err, ShukiError::AlreadyExists(_)), "got: {err}");
    }

    #[tokio::test]
    async fn import_nsec_bech32_and_hex() {
        let keys = Keys::generate();

        // bech32
        {
            let (_guard, _store) = fresh_store().await;
            let nsec = keys.secret_key().to_bech32().expect("bech32 infallible");
            let pk = import_nsec(SecretField::new(nsec)).await.unwrap();
            assert_eq!(pk, keys.public_key());
            assert_eq!(stored_public_key().await.unwrap(), Some(pk));
        }

        // 64-char hex
        {
            let (_guard, _store) = fresh_store().await;
            let hex = keys.secret_key().to_secret_hex();
            let pk = import_nsec(SecretField::new(hex)).await.unwrap();
            assert_eq!(pk, keys.public_key());
        }
    }

    #[tokio::test]
    async fn import_nsec_rejects_garbage() {
        let (_guard, _store) = fresh_store().await;
        for garbage in ["", "not-a-key", "nsec1qqqqqqqq", "abcd1234"] {
            let err = import_nsec(SecretField::from(garbage)).await.unwrap_err();
            assert!(matches!(err, ShukiError::Crypto(_)), "got: {err}");
        }
        // Nothing was stored.
        assert_eq!(stored_public_key().await.unwrap(), None);
    }

    #[tokio::test]
    async fn import_refuses_different_identity_but_is_idempotent() {
        let (_guard, _store) = fresh_store().await;
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("bech32 infallible");
        let pk = import_nsec(SecretField::new(nsec.clone())).await.unwrap();

        // Same key again: idempotent.
        let again = import_nsec(SecretField::new(nsec)).await.unwrap();
        assert_eq!(again, pk);

        // A different key: refused.
        let other = Keys::generate();
        let other_nsec = other.secret_key().to_bech32().expect("bech32 infallible");
        let err = import_nsec(SecretField::new(other_nsec)).await.unwrap_err();
        assert!(matches!(err, ShukiError::AlreadyExists(_)), "got: {err}");
        assert_eq!(stored_public_key().await.unwrap(), Some(pk));
    }

    #[tokio::test]
    async fn export_import_ncryptsec_roundtrip() {
        let exported;
        let pk;
        {
            let (_guard, _store) = fresh_store().await;
            pk = generate_and_store().await.unwrap();
            exported = export_ncryptsec(SecretField::from("hunter2"), TEST_LOG_N)
                .await
                .unwrap();
            assert!(exported.starts_with("ncryptsec1"), "got: {exported}");
        }

        // Correct passphrase restores the same identity into a fresh store.
        {
            let (_guard, _store) = fresh_store().await;
            let restored = import_ncryptsec(&exported, SecretField::from("hunter2"))
                .await
                .unwrap();
            assert_eq!(restored, pk);
            assert_eq!(stored_public_key().await.unwrap(), Some(pk));
        }

        // Wrong passphrase fails and stores nothing.
        {
            let (_guard, _store) = fresh_store().await;
            let err = import_ncryptsec(&exported, SecretField::from("wrong"))
                .await
                .unwrap_err();
            assert!(matches!(err, ShukiError::Crypto(_)), "got: {err}");
            assert_eq!(stored_public_key().await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn export_without_identity_is_not_found() {
        let (_guard, _store) = fresh_store().await;
        let err = export_ncryptsec(SecretField::from("pw"), TEST_LOG_N)
            .await
            .unwrap_err();
        assert!(matches!(err, ShukiError::NotFound(_)), "got: {err}");
    }
}
