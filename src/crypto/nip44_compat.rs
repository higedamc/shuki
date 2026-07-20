//! Raw-ECDH → NIP-44 v2 conversation key bridge.
//!
//! The NSD firmware computes ECDH with `use_hash=false` (uBitcoin), i.e. it
//! returns the raw x-coordinate of the shared point — exactly the input
//! NIP-44 v2 feeds into HKDF-extract with salt `"nip44-v2"`. Deriving the
//! conversation key host-side from that x-coordinate is therefore fully
//! interoperable with standard NIP-44 (proven by the equivalence test below).

use hmac::{Hmac, Mac};
use nostr::nips::nip44::v2::ConversationKey;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF-extract(salt = b"nip44-v2", ikm = shared_x) → conversation key.
///
/// HKDF-extract(salt, ikm) is HMAC-SHA256 keyed by the salt over the ikm
/// (RFC 5869 §2.2).
pub fn conversation_key_from_shared_x(shared_x: &[u8; 32]) -> ConversationKey {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"nip44-v2").expect("hmac accepts any key len");
    mac.update(shared_x);
    let mut prk: [u8; 32] = mac.finalize().into_bytes().into();
    let key = ConversationKey::new(prk);
    prk.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::secp256k1::ecdh::shared_secret_point;
    use nostr::secp256k1::{Parity, PublicKey as FullPublicKey};
    use nostr::Keys;

    /// The core security property: our HKDF bridge over a raw ECDH
    /// x-coordinate must equal the library's `ConversationKey::derive`
    /// for the same key pair. This proves the NSD path is NIP-44 compliant
    /// without any hardware.
    #[test]
    fn equivalent_to_library_derive() {
        for _ in 0..16 {
            let a = Keys::generate();
            let b = Keys::generate();

            let expected =
                ConversationKey::derive(a.secret_key(), &b.public_key()).expect("derive");

            // Raw ECDH x-coordinate, reconstructing B's full point with even
            // parity (BIP-340 x-only convention, same as the device does).
            let b_full = FullPublicKey::from_x_only_public_key(
                b.public_key().xonly().expect("xonly"),
                Parity::Even,
            );
            let point = shared_secret_point(&b_full, a.secret_key());
            let mut x = [0u8; 32];
            x.copy_from_slice(&point[..32]);

            let bridged = conversation_key_from_shared_x(&x);
            assert_eq!(bridged.as_bytes(), expected.as_bytes());
        }
    }

    /// Deterministic and direction-symmetric (ECDH property), as NIP-44 requires.
    #[test]
    fn symmetric_between_parties() {
        let a = Keys::generate();
        let b = Keys::generate();
        let ab = ConversationKey::derive(a.secret_key(), &b.public_key()).unwrap();
        let ba = ConversationKey::derive(b.secret_key(), &a.public_key()).unwrap();
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }
}
