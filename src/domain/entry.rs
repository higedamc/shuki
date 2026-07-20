//! [`Entry`] and secret-bearing field types.
//!
//! [`SecretField`] zeroizes on drop, redacts `Debug`, and compares in
//! constant time. It serializes as a plain JSON string — acceptable ONLY
//! because entry serialization happens exclusively inside NIP-44 encrypted
//! payloads ([`crate::sync::payload::SyncPayload`]); never serialize
//! entries to disk or logs in plaintext.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use super::path::VaultPath;

/// A secret string (password, notes, custom field values).
#[derive(Clone, Default, ZeroizeOnDrop)]
pub struct SecretField(String);

impl SecretField {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Access the plaintext. Keep the borrow short-lived; never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretField(<redacted>)")
    }
}

impl PartialEq for SecretField {
    /// Constant-time comparison (length may still leak; contents do not).
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.0.as_bytes(), other.0.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}
impl Eq for SecretField {}

impl From<&str> for SecretField {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl Serialize for SecretField {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(Self(String::deserialize(d)?))
    }
}

/// The fields of one vault entry. All optional; unknown future fields ride in `custom`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretField>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, SecretField>,
}

/// One decrypted vault entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: VaultPath,
    pub fields: EntryFields,
    /// Unix seconds; authoritative timestamp for last-write-wins sync.
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_field_redacts_debug() {
        let s = SecretField::new("hunter2".into());
        assert_eq!(format!("{s:?}"), "SecretField(<redacted>)");
    }

    #[test]
    fn secret_field_eq() {
        assert_eq!(SecretField::from("abc"), SecretField::from("abc"));
        assert_ne!(SecretField::from("abc"), SecretField::from("abd"));
        assert_ne!(SecretField::from("abc"), SecretField::from("abcd"));
    }

    #[test]
    fn fields_serde_roundtrip() {
        let mut f = EntryFields {
            password: Some(SecretField::from("p@ss")),
            username: Some("alice".into()),
            ..Default::default()
        };
        f.custom.insert("totp".into(), SecretField::from("SECRET"));
        let json = serde_json::to_string(&f).unwrap();
        let back: EntryFields = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
        // Absent options are omitted from the wire format.
        assert!(!json.contains("url"));
        assert!(!json.contains("notes"));
    }
}
