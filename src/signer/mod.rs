//! The [`Signer`] contract — every key backend (software keychain, NSD,
//! future hardware) implements this. Consumers (`vault`, `sync`) depend on
//! nothing else.

pub mod keysetup;
pub mod nsd;
pub mod session;
pub mod software;

use async_trait::async_trait;
use nostr::nips::nip44::v2::ConversationKey;
use nostr::{Event, PublicKey, UnsignedEvent};
use zeroize::Zeroizing;

use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerKind {
    /// nsec in the OS keychain; loaded into zeroizing memory per operation.
    Software,
    /// Nostr Signing Device over USB serial; nsec never touches the host.
    Nsd,
}

/// A Nostr key backend.
///
/// Hot path: callers fetch [`Self::self_conversation_key`] once (constant for
/// a fixed identity) and run NIP-44 host-side for N entries. Backends that
/// cannot reveal a conversation key return [`crate::ShukiError::Unsupported`];
/// callers must then fall back to per-entry [`Self::nip44_encrypt`] /
/// [`Self::nip44_decrypt`].
#[async_trait]
pub trait Signer: Send + Sync {
    fn kind(&self) -> SignerKind;

    async fn public_key(&self) -> Result<PublicKey>;

    /// Sign a Nostr event. Hardware backends may block on physical
    /// confirmation and return `DeviceRejected` / `DeviceTimeout`.
    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event>;

    /// NIP-44 v2 conversation key with our own pubkey (self-encryption key).
    /// Implementations MUST cache it (zeroizing) — devices are asked once.
    async fn self_conversation_key(&self) -> Result<ConversationKey>;

    /// NIP-44 encrypt to an arbitrary peer (base64 payload string).
    async fn nip44_encrypt(&self, peer: &PublicKey, plaintext: &[u8]) -> Result<String>;

    /// NIP-44 decrypt from an arbitrary peer.
    async fn nip44_decrypt(&self, peer: &PublicKey, payload: &str) -> Result<Zeroizing<Vec<u8>>>;
}
