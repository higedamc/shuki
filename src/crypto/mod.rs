//! Crypto primitives shared across leaves.
//!
//! - [`nip44_compat`]: build a NIP-44 v2 conversation key from a raw ECDH
//!   x-coordinate (what the NSD returns over serial).
//! - [`tagkey`]: derive the d-tag HMAC key and per-path d-tags.
//! - [`passgen`]: CSPRNG password generation.
//! - [`memlock`]: best-effort page locking so secrets stay out of swap.

pub mod memlock;
pub mod nip44_compat;
pub mod passgen;
pub mod tagkey;

use memlock::LockedBox;

/// Key used to HMAC entry paths into public (but meaningless) d-tags.
/// Derived from the self conversation key; never stored. Lives on locked
/// pages (best effort) and zeroizes on drop.
pub struct TagKey(pub LockedBox<[u8; 32]>);
