//! Crypto primitives shared across leaves.
//!
//! - [`nip44_compat`]: build a NIP-44 v2 conversation key from a raw ECDH
//!   x-coordinate (what the NSD returns over serial).
//! - [`tagkey`]: derive the d-tag HMAC key and per-path d-tags.
//! - [`passgen`]: CSPRNG password generation.

pub mod nip44_compat;
pub mod passgen;
pub mod tagkey;

use zeroize::Zeroizing;

/// Key used to HMAC entry paths into public (but meaningless) d-tags.
/// Derived from the self conversation key; never stored.
pub struct TagKey(pub Zeroizing<[u8; 32]>);
