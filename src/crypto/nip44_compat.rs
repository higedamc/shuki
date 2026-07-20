//! Raw-ECDH → NIP-44 v2 conversation key bridge (owned by `leaf/crypto-core-primitives`).
//!
//! The NSD firmware computes ECDH with `use_hash=false` (uBitcoin), i.e. it
//! returns the raw x-coordinate of the shared point — exactly the input
//! NIP-44 v2 feeds into HKDF-extract with salt `"nip44-v2"`. Deriving the
//! conversation key host-side from that x-coordinate is therefore fully
//! interoperable with standard NIP-44.

use nostr::nips::nip44::v2::ConversationKey;

/// HKDF-extract(salt = b"nip44-v2", ikm = shared_x) → conversation key.
///
/// Must be verified equal to `ConversationKey::derive(sk, pk)` for the same
/// key pair (see the equivalence test in this leaf).
pub fn conversation_key_from_shared_x(_shared_x: &[u8; 32]) -> ConversationKey {
    todo!("leaf/crypto-core-primitives")
}
