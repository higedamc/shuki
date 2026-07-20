//! Key lifecycle: generate / import / export (owned by `leaf/signer-software-keyring`).
//!
//! All functions operate on the OS keychain (service
//! [`super::software::KEYCHAIN_SERVICE`]). NIP-49 (`ncryptsec…`) is the cold
//! backup format.

use nostr::PublicKey;

use crate::domain::SecretField;
use crate::error::Result;

/// Generate a fresh identity, store it in the keychain, return its pubkey.
pub async fn generate_and_store() -> Result<PublicKey> {
    todo!("leaf/signer-software-keyring")
}

/// Import a bech32 `nsec…` into the keychain.
pub async fn import_nsec(_nsec: SecretField) -> Result<PublicKey> {
    todo!("leaf/signer-software-keyring")
}

/// Import a NIP-49 `ncryptsec…` (decrypt with passphrase, store).
pub async fn import_ncryptsec(_ncryptsec: &str, _password: SecretField) -> Result<PublicKey> {
    todo!("leaf/signer-software-keyring")
}

/// Export the stored key as NIP-49 `ncryptsec…` (log_n: KDF hardness, default 16).
pub async fn export_ncryptsec(_password: SecretField, _log_n: u8) -> Result<String> {
    todo!("leaf/signer-software-keyring")
}

/// Pubkey of the stored identity, if any.
pub async fn stored_public_key() -> Result<Option<PublicKey>> {
    todo!("leaf/signer-software-keyring")
}
