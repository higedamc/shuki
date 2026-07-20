//! Test utilities — a fully functional in-memory [`Signer`] for unit and
//! integration tests. Not for production use: keys live in process memory.

use async_trait::async_trait;
use nostr::nips::nip44::{self, v2::ConversationKey};
use nostr::{Event, Keys, PublicKey, UnsignedEvent};
use zeroize::Zeroizing;

use crate::error::{Result, ShukiError};
use crate::signer::{Signer, SignerKind};

/// In-memory signer wrapping freshly generated (or supplied) [`Keys`].
pub struct MockSigner {
    keys: Keys,
}

impl MockSigner {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            keys: Keys::generate(),
        }
    }

    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }
}

#[async_trait]
impl Signer for MockSigner {
    fn kind(&self) -> SignerKind {
        SignerKind::Software
    }

    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.keys.public_key())
    }

    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event> {
        unsigned
            .sign_with_keys(&self.keys)
            .map_err(|e| ShukiError::Crypto(e.to_string()))
    }

    async fn self_conversation_key(&self) -> Result<ConversationKey> {
        ConversationKey::derive(self.keys.secret_key(), &self.keys.public_key())
            .map_err(|e| ShukiError::Crypto(e.to_string()))
    }

    async fn nip44_encrypt(&self, peer: &PublicKey, plaintext: &[u8]) -> Result<String> {
        nip44::encrypt(self.keys.secret_key(), peer, plaintext, nip44::Version::V2)
            .map_err(|e| ShukiError::Crypto(e.to_string()))
    }

    async fn nip44_decrypt(&self, peer: &PublicKey, payload: &str) -> Result<Zeroizing<Vec<u8>>> {
        nip44::decrypt_to_bytes(self.keys.secret_key(), peer, payload)
            .map(Zeroizing::new)
            .map_err(|e| ShukiError::Crypto(e.to_string()))
    }
}
