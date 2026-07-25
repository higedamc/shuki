//! d-tag derivation: paths are published to relays only as HMAC digests,
//! so relays learn nothing about the tree structure or entry names.

use hmac::{Hmac, Mac};
use nostr::nips::nip44::v2::ConversationKey;
use sha2::Sha256;

use crate::crypto::memlock::LockedBox;
use crate::crypto::TagKey;
use crate::domain::VaultPath;

const TAG_KEY_INFO: &[u8] = b"shuki-tag-key-v1";

/// HMAC-SHA256(conversation_key, "shuki-tag-key-v1") → tag key.
///
/// Domain-separated from the encryption key: knowing every d-tag never helps
/// an attacker toward the conversation key.
pub fn derive_tag_key(conversation_key: &ConversationKey) -> TagKey {
    let mut mac = Hmac::<Sha256>::new_from_slice(conversation_key.as_bytes())
        .expect("hmac accepts any key len");
    mac.update(TAG_KEY_INFO);
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    TagKey(LockedBox::new(bytes))
}

/// Lowercase-hex HMAC-SHA256(tag_key, path) — the public d-tag for an entry.
pub fn d_tag(tag_key: &TagKey, path: &VaultPath) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&tag_key.0[..]).expect("hmac accepts any key len");
    mac.update(path.as_str().as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        write!(out, "{b:02x}").expect("write to string");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn test_ck() -> ConversationKey {
        let k = Keys::generate();
        ConversationKey::derive(k.secret_key(), &k.public_key()).unwrap()
    }

    #[test]
    fn deterministic_and_well_formed() {
        let ck = test_ck();
        let tk = derive_tag_key(&ck);
        let p = VaultPath::parse("web/example.com").unwrap();
        let t1 = d_tag(&tk, &p);
        let t2 = d_tag(&tk, &p);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
        assert!(t1
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn distinct_paths_distinct_tags() {
        let ck = test_ck();
        let tk = derive_tag_key(&ck);
        let a = d_tag(&tk, &VaultPath::parse("a/b").unwrap());
        let b = d_tag(&tk, &VaultPath::parse("a/c").unwrap());
        let c = d_tag(&tk, &VaultPath::parse("a").unwrap());
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn distinct_identities_distinct_tags() {
        let p = VaultPath::parse("same/path").unwrap();
        let t1 = d_tag(&derive_tag_key(&test_ck()), &p);
        let t2 = d_tag(&derive_tag_key(&test_ck()), &p);
        assert_ne!(t1, t2);
    }

    #[test]
    fn tag_key_differs_from_conversation_key() {
        let ck = test_ck();
        let tk = derive_tag_key(&ck);
        assert_ne!(&tk.0[..], ck.as_bytes());
    }
}
