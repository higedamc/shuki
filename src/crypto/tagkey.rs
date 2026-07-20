//! d-tag derivation (owned by `leaf/crypto-core-primitives`).

use nostr::nips::nip44::v2::ConversationKey;

use crate::crypto::TagKey;
use crate::domain::VaultPath;

/// HMAC-SHA256(conversation_key_bytes, b"shuki-tag-key-v1") → tag key.
pub fn derive_tag_key(_conversation_key: &ConversationKey) -> TagKey {
    todo!("leaf/crypto-core-primitives")
}

/// Lowercase-hex HMAC-SHA256(tag_key, path) — the public d-tag for an entry.
pub fn d_tag(_tag_key: &TagKey, _path: &VaultPath) -> String {
    todo!("leaf/crypto-core-primitives")
}
